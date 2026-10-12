"""Bounded canonical public-state codec for local storage and conformance fixtures."""

import account_lifecycle as lifecycle
import hybrid_auth as hybrid

# 1 tag + 2 * (LP16(chain <=64) + LP16(account =72) + u64 + 32 + 1952).
MAX_STATE_BYTES = 4265


class Reader:
    def __init__(self, data: bytes):
        if type(data) is not bytes or not 1 <= len(data) <= MAX_STATE_BYTES:
            raise ValueError("invalid state byte size/type")
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise ValueError("truncated state")
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def text(self, limit: int) -> str:
        size = int.from_bytes(self.take(2), "big")
        if not 1 <= size <= limit:
            raise ValueError("invalid state string length")
        return self.take(size).decode("ascii")

    def context(self) -> tuple[str, str, int]:
        return self.text(64), self.text(72), int.from_bytes(self.take(8), "big")

    def record(self) -> hybrid.AccountRecord:
        return hybrid.AccountRecord(*self.context(), self.take(32), self.take(1952))


def encode_state(state: lifecycle.State) -> bytes:
    return lifecycle._state_bytes(state)


def decode_state(data: bytes) -> lifecycle.State:
    reader = Reader(data)
    tag = reader.take(1)
    if tag == b"\x00":
        state = lifecycle.LegacyState(*reader.context(), reader.take(32))
    elif tag == b"\x01":
        state = lifecycle.HybridState(reader.record(), reader.record())
    else:
        raise ValueError("unsupported state tag")
    if reader.offset != len(data):
        raise ValueError("trailing state bytes")
    return state
