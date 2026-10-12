"""Durable local rehearsal adapter, not a consensus backend or anti-rollback store."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import account_lifecycle as lifecycle
from state_codec import MAX_STATE_BYTES, decode_state, encode_state

SCHEMA_VERSION = 1


def _read(connection: sqlite3.Connection) -> tuple[lifecycle.State, bool]:
    if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise ValueError("unsupported registry schema version")
    # Bound state before fetching its bytes. The surrounding transaction keeps
    # the metadata check and the read on the same snapshot.
    rows = connection.execute(
        "SELECT id, typeof(state), length(state), enrollment_open FROM registry LIMIT 2"
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("registry must contain exactly one account")
    identity, storage_type, size, gate = rows[0]
    if identity != 1 or storage_type != "blob" or not 1 <= size <= MAX_STATE_BYTES:
        raise ValueError("invalid stored account encoding")
    if type(gate) is not int or gate not in (0, 1):
        raise ValueError("invalid stored enrollment gate")
    state = connection.execute("SELECT state FROM registry WHERE id = 1").fetchone()[0]
    return decode_state(state), bool(gate)


def _write_state(connection: sqlite3.Connection, state: lifecycle.HybridState) -> None:
    connection.execute("UPDATE registry SET state = ? WHERE id = 1", (encode_state(state),))


class SQLiteRegistry:
    """Reopen an existing trusted registry; creation is a separate exclusive operation."""

    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        # mode=rw prevents missing files from being silently reinitialized.
        with self._transaction(write=False) as connection:
            _read(connection)

    @classmethod
    def create(
        cls, path: str | Path, state: lifecycle.State, *, enrollment_open: bool = False
    ) -> SQLiteRegistry:
        if type(enrollment_open) is not bool:
            raise ValueError("enrollment policy must be boolean")
        encoded = encode_state(state)
        decode_state(encoded)
        path = Path(path).absolute()
        # Never overwrite/reset even an empty or corrupt existing file.
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE registry ("
                "id INTEGER PRIMARY KEY CHECK(id = 1),"
                "state BLOB NOT NULL CHECK(typeof(state) = 'blob' AND length(state) BETWEEN 1 AND 4265),"
                "enrollment_open INTEGER NOT NULL CHECK(enrollment_open IN (0, 1)))"
            )
            connection.execute(
                "INSERT INTO registry VALUES (1, ?, ?)", (encoded, int(enrollment_open))
            )
            connection.execute("PRAGMA user_version=1")
            connection.commit()
        except BaseException:
            connection.rollback()
            # Leave failed initialization in place: it must not reopen as a fresh
            # legacy account. Opening incomplete state fails closed.
            raise
        finally:
            connection.close()
        return cls(path)

    @contextmanager
    def _transaction(self, *, write: bool):
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=5
        )
        try:
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("unsupported registry journal mode")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @property
    def state(self) -> lifecycle.State:
        with self._transaction(write=False) as connection:
            return _read(connection)[0]

    @property
    def enrollment_open(self) -> bool:
        with self._transaction(write=False) as connection:
            return _read(connection)[1]

    def close_enrollment(self) -> None:
        with self._transaction(write=True) as connection:
            _read(connection)
            connection.execute("UPDATE registry SET enrollment_open = 0 WHERE id = 1")

    def apply(self, request: lifecycle.Transition) -> lifecycle.HybridState:
        with self._transaction(write=True) as connection:
            current, gate = _read(connection)
            replacement = lifecycle.apply_transition(current, request, enrollment_open=gate)
            _write_state(connection, replacement)
        return replacement
