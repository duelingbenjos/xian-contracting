"""Durability, independent-process contention, corruption, and failure atomicity."""

import multiprocessing
import os
import sqlite3
from dataclasses import replace

import pytest
import sqlite_registry as storage
from state_codec import MAX_STATE_BYTES, decode_state, encode_state


def _crash_before_commit(path, request):
    original = storage._write_state

    def crash(connection, state):
        original(connection, state)
        os._exit(23)

    storage._write_state = crash
    storage.SQLiteRegistry(path).apply(request)


def _contend(path, request, ready, start, results):
    registry = storage.SQLiteRegistry(path)
    ready.put(True)
    if not start.wait(10):
        raise RuntimeError("test start timed out")
    try:
        registry.apply(request)
        results.put("committed")
    except ValueError:
        results.put("stale")


def _join(process):
    process.join(15)
    if process.is_alive():
        process.kill()
        process.join()
        pytest.fail("registry subprocess did not finish")


def test_restart_preserves_enrollment_rotation_and_replay_rejection(tmp_path, scenario):
    path = tmp_path / "account.sqlite"
    storage.SQLiteRegistry.create(path, scenario["legacy"], enrollment_open=True).apply(
        scenario["enrollment"]
    )
    reopened = storage.SQLiteRegistry(path)
    assert reopened.state == scenario["first"]
    reopened.apply(scenario["rotation"])
    with pytest.raises(ValueError):
        storage.SQLiteRegistry(path).apply(scenario["rotation"])
    assert storage.SQLiteRegistry(path).state == scenario["second"]


def test_restart_keeps_enrollment_closed_and_creation_cannot_reset(tmp_path, scenario):
    path = tmp_path / "account.sqlite"
    storage.SQLiteRegistry.create(path, scenario["legacy"], enrollment_open=True).close_enrollment()
    reopened = storage.SQLiteRegistry(path)
    assert reopened.enrollment_open is False
    with pytest.raises(ValueError, match="closed"):
        reopened.apply(scenario["enrollment"])
    with pytest.raises(FileExistsError):
        storage.SQLiteRegistry.create(path, scenario["legacy"], enrollment_open=True)
    assert storage.SQLiteRegistry(path).enrollment_open is False


def test_invalid_proof_leaves_persisted_state_unchanged(tmp_path, scenario):
    path = tmp_path / "account.sqlite"
    registry = storage.SQLiteRegistry.create(path, scenario["first"])
    with pytest.raises(ValueError):
        registry.apply(replace(scenario["rotation"], recovery_proof=bytes(3400)))
    assert storage.SQLiteRegistry(path).state == scenario["first"]


def test_storage_failure_after_update_rolls_back(tmp_path, scenario, monkeypatch):
    path = tmp_path / "account.sqlite"
    registry = storage.SQLiteRegistry.create(path, scenario["first"])
    original = storage._write_state

    def fail(connection, state):
        original(connection, state)
        raise sqlite3.OperationalError("injected write failure")

    monkeypatch.setattr(storage, "_write_state", fail)
    with pytest.raises(sqlite3.OperationalError):
        registry.apply(scenario["rotation"])
    assert storage.SQLiteRegistry(path).state == scenario["first"]


def test_process_death_before_commit_preserves_previous_state(tmp_path, scenario):
    path = tmp_path / "account.sqlite"
    storage.SQLiteRegistry.create(path, scenario["first"])
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_before_commit, args=(path, scenario["rotation"])
    )
    process.start()
    _join(process)
    assert process.exitcode == 23
    registry = storage.SQLiteRegistry(path)
    assert registry.state == scenario["first"]
    assert registry.apply(scenario["rotation"]) == scenario["second"]


def test_two_independent_processes_cannot_commit_same_epoch(tmp_path, scenario):
    path = tmp_path / "account.sqlite"
    storage.SQLiteRegistry.create(path, scenario["first"])
    context = multiprocessing.get_context("spawn")
    ready, results, start = context.Queue(), context.Queue(), context.Event()
    processes = [
        context.Process(target=_contend, args=(path, scenario[name], ready, start, results))
        for name in ("rotation", "recovery")
    ]
    try:
        for process in processes:
            process.start()
        assert ready.get(timeout=10) and ready.get(timeout=10)
        start.set()
        for process in processes:
            _join(process)
            assert process.exitcode == 0
        assert sorted([results.get(timeout=5), results.get(timeout=5)]) == ["committed", "stale"]
        assert storage.SQLiteRegistry(path).state == scenario["second"]
    finally:
        start.set()
        for process in processes:
            if process.is_alive():
                process.kill()
                process.join()
        ready.close()
        results.close()


@pytest.mark.parametrize(
    "sql",
    [
        "PRAGMA user_version=2",
        "DELETE FROM registry",
        "UPDATE registry SET state=x'02'",
        "UPDATE registry SET state=zeroblob(4266)",
        "UPDATE registry SET state='text'",
        "UPDATE registry SET enrollment_open=2",
        "UPDATE registry SET enrollment_open='true'",
    ],
)
def test_corrupt_or_unknown_storage_fails_closed(tmp_path, scenario, sql):
    path = tmp_path / "account.sqlite"
    storage.SQLiteRegistry.create(path, scenario["first"])
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(sql)
    with pytest.raises(ValueError):
        storage.SQLiteRegistry(path)


def test_missing_and_empty_database_never_auto_initialize(tmp_path, scenario):
    path = tmp_path / "missing.sqlite"
    with pytest.raises(sqlite3.OperationalError):
        storage.SQLiteRegistry(path)
    assert not path.exists()
    path.touch()
    with pytest.raises(ValueError):
        storage.SQLiteRegistry(path)
    with pytest.raises(FileExistsError):
        storage.SQLiteRegistry.create(path, scenario["legacy"], enrollment_open=True)


@pytest.mark.parametrize("name", ["legacy", "first", "second", "third"])
def test_canonical_state_roundtrip_and_truncation(scenario, name):
    state = scenario[name]
    encoded = encode_state(state)
    assert decode_state(encoded) == state
    for invalid in (
        encoded[:-1],
        encoded + b"x",
        b"\xff" + encoded[1:],
        b"",
        bytes(MAX_STATE_BYTES + 1),
    ):
        with pytest.raises(ValueError):
            decode_state(invalid)


def test_uint64_epoch_survives_storage_without_sql_integer_coercion(tmp_path, scenario):
    original = scenario["first"]
    state = replace(
        original,
        active=replace(original.active, key_epoch=2**64 - 1),
        recovery=replace(original.recovery, key_epoch=2**64 - 1),
    )
    path = tmp_path / "account.sqlite"
    storage.SQLiteRegistry.create(path, state)
    assert storage.SQLiteRegistry(path).state == state
