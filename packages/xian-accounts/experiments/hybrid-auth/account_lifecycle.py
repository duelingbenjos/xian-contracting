"""In-memory lifecycle reference model. No network admission or persistent storage.

See xian-meta/docs/HYBRID_ACCOUNT_AUTH_EXPERIMENT.md for the byte contract.
Only initialize from trusted account state. Never treat caller-provided keys as
proof of existing ownership. Use generated test keys, not real account secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from threading import Lock

import hybrid_auth as hybrid
from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

LIFECYCLE_DOMAIN = b"XIAN-HYBRID-LIFECYCLE\0"


class Operation(IntEnum):
    ENROLL = 1
    ROTATE = 2
    RECOVER = 3


class Role(IntEnum):
    AUTHORITY = 1
    NEW_ACTIVE = 2
    NEW_RECOVERY = 3


@dataclass(frozen=True)
class LegacyState:
    chain_id: str
    account_id: str
    enrollment_nonce: int
    ed_public_key: bytes

    def __post_init__(self) -> None:
        hybrid._validate_context(self.chain_id, self.account_id, self.enrollment_nonce)
        hybrid._bytes(self.ed_public_key, 32, "ed_public_key")
        if not crypto_core_ed25519_is_valid_point(self.ed_public_key):
            raise ValueError("invalid legacy Ed25519 public key")


@dataclass(frozen=True)
class HybridState:
    active: hybrid.AccountRecord
    recovery: hybrid.AccountRecord

    def __post_init__(self) -> None:
        if (
            type(self.active) is not hybrid.AccountRecord
            or type(self.recovery) is not hybrid.AccountRecord
        ):
            raise ValueError("both roles require hybrid account records")
        if _context(self.active) != _context(self.recovery):
            raise ValueError("active and recovery identities/epochs must match")
        if (
            self.active.ed_public_key == self.recovery.ed_public_key
            or self.active.pq_public_key == self.recovery.pq_public_key
        ):
            raise ValueError("active and recovery keys must be separate for each primitive")


State = LegacyState | HybridState


def _context(record: hybrid.AccountRecord) -> tuple[str, str, int]:
    return record.chain_id, record.account_id, record.key_epoch


def _record_bytes(record: hybrid.AccountRecord) -> bytes:
    return (
        hybrid._lp16(record.chain_id)
        + hybrid._lp16(record.account_id)
        + record.key_epoch.to_bytes(8, "big")
        + record.ed_public_key
        + record.pq_public_key
    )


def _state_bytes(state: State) -> bytes:
    if type(state) is LegacyState:
        return (
            b"\x00"
            + hybrid._lp16(state.chain_id)
            + hybrid._lp16(state.account_id)
            + state.enrollment_nonce.to_bytes(8, "big")
            + state.ed_public_key
        )
    if type(state) is HybridState:
        return b"\x01" + _record_bytes(state.active) + _record_bytes(state.recovery)
    raise ValueError("unsupported trusted state")


def transition_transcript(
    current: State, operation: Operation, candidate: HybridState, role: Role
) -> bytes:
    if (
        type(operation) is not Operation
        or type(role) is not Role
        or type(candidate) is not HybridState
    ):
        raise ValueError("invalid operation, role, or candidate")
    before, after = _state_bytes(current), _state_bytes(candidate)
    return (
        LIFECYCLE_DOMAIN
        + bytes((hybrid.VERSION, hybrid.SUITE, operation, role))
        + len(before).to_bytes(4, "big")
        + before
        + len(after).to_bytes(4, "big")
        + after
    )


@dataclass(frozen=True)
class Transition:
    operation: Operation
    candidate: HybridState
    authority_proof: bytes
    active_proof: bytes
    recovery_proof: bytes

    def __post_init__(self) -> None:
        if type(self.operation) is not Operation or type(self.candidate) is not HybridState:
            raise ValueError("invalid operation or candidate")
        authority_size = 64 if self.operation is Operation.ENROLL else hybrid.AUTH_BYTES
        hybrid._bytes(self.authority_proof, authority_size, "authority_proof")
        hybrid._bytes(self.active_proof, hybrid.AUTH_BYTES, "active_proof")
        hybrid._bytes(self.recovery_proof, hybrid.AUTH_BYTES, "recovery_proof")


def _check_transition(current: State, operation: Operation, candidate: HybridState) -> None:
    """Check state constraints before any signature work."""
    if type(operation) is not Operation or type(candidate) is not HybridState:
        raise ValueError("invalid operation or candidate")
    if type(current) is LegacyState:
        if operation is not Operation.ENROLL:
            raise ValueError("legacy account must enroll first")
        expected = current.chain_id, current.account_id, 0
        old_ed, old_pq = {current.ed_public_key}, set()
    elif type(current) is HybridState:
        if operation is Operation.ENROLL:
            raise ValueError("hybrid accounts cannot re-enroll or downgrade")
        if current.active.key_epoch == 2**64 - 1:
            raise ValueError("key epoch exhausted")
        expected = current.active.chain_id, current.active.account_id, current.active.key_epoch + 1
        old_ed = {current.active.ed_public_key, current.recovery.ed_public_key}
        old_pq = {current.active.pq_public_key, current.recovery.pq_public_key}
    else:
        raise ValueError("unsupported trusted state")
    if _context(candidate.active) != expected:
        raise ValueError("candidate must preserve identity and advance to the expected epoch")
    for record in (candidate.active, candidate.recovery):
        if record.ed_public_key in old_ed or record.pq_public_key in old_pq:
            raise ValueError("new keys must not reuse any current key")


def _authority(current: HybridState, operation: Operation) -> hybrid.AccountRecord:
    return current.active if operation is Operation.ROTATE else current.recovery


def prepare_transition(
    current: State,
    operation: Operation,
    candidate: HybridState,
    *,
    authority_keys: SigningKey | hybrid.PrivateKeys,
    active_keys: hybrid.PrivateKeys,
    recovery_keys: hybrid.PrivateKeys,
) -> Transition:
    """Local rehearsal signer; real wallets must keep recovery signing offline."""
    _check_transition(current, operation, candidate)
    message = transition_transcript(current, operation, candidate, Role.AUTHORITY)
    if type(current) is LegacyState:
        if (
            type(authority_keys) is not SigningKey
            or bytes(authority_keys.verify_key) != current.ed_public_key
        ):
            raise ValueError("legacy authority key mismatch")
        authority_proof = authority_keys.sign(message).signature
    else:
        if type(authority_keys) is not hybrid.PrivateKeys:
            raise ValueError("hybrid authority keys required")
        authority_proof = hybrid._sign_transcript(
            _authority(current, operation), authority_keys, message
        )
    return Transition(
        operation,
        candidate,
        authority_proof,
        hybrid._sign_transcript(
            candidate.active,
            active_keys,
            transition_transcript(current, operation, candidate, Role.NEW_ACTIVE),
        ),
        hybrid._sign_transcript(
            candidate.recovery,
            recovery_keys,
            transition_transcript(current, operation, candidate, Role.NEW_RECOVERY),
        ),
    )


def apply_transition(current: State, request: Transition, *, enrollment_open: bool) -> HybridState:
    """Pure check: callers must atomically persist the returned state to consume it."""
    if type(enrollment_open) is not bool or type(request) is not Transition:
        raise ValueError("invalid enrollment policy or request")
    _check_transition(current, request.operation, request.candidate)
    if type(current) is LegacyState and not enrollment_open:
        raise ValueError("legacy enrollment is closed")
    message = transition_transcript(current, request.operation, request.candidate, Role.AUTHORITY)
    if type(current) is LegacyState:
        try:
            VerifyKey(current.ed_public_key).verify(message, request.authority_proof)
        except (BadSignatureError, ValueError) as exc:
            raise ValueError("invalid current authority proof") from exc
    elif not hybrid._verify_transcript(
        _authority(current, request.operation), message, request.authority_proof
    ):
        raise ValueError("invalid current authority proof")
    for role, record, proof in (
        (Role.NEW_ACTIVE, request.candidate.active, request.active_proof),
        (Role.NEW_RECOVERY, request.candidate.recovery, request.recovery_proof),
    ):
        message = transition_transcript(current, request.operation, request.candidate, role)
        if not hybrid._verify_transcript(record, message, proof):
            raise ValueError("invalid new key possession proof")
    return request.candidate


class LocalRegistry:
    """One account, initialized from trusted state; intentionally not persistent."""

    def __init__(self, state: State, *, enrollment_open: bool = False):
        _state_bytes(state)
        if type(enrollment_open) is not bool:
            raise ValueError("enrollment policy must be boolean")
        self._state = state
        self._enrollment_open = enrollment_open
        self._lock = Lock()

    @property
    def state(self) -> State:
        with self._lock:
            return self._state

    def close_enrollment(self) -> None:
        with self._lock:
            self._enrollment_open = False

    def apply(self, request: Transition) -> HybridState:
        with self._lock:
            replacement = apply_transition(
                self._state, request, enrollment_open=self._enrollment_open
            )
            self._state = replacement
            return replacement
