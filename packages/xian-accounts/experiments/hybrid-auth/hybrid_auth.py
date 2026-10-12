"""Local experiment only. See xian-meta/docs/HYBRID_ACCOUNT_AUTH_EXPERIMENT.md.

Records must come from trusted state. This module authenticates bounded bytes;
it neither validates transactions nor enrolls/rotates keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pqcrypto.sign import ml_dsa_65

VERSION = 1
SUITE = 1  # Both Ed25519 and ML-DSA-65 are mandatory.
TX_DOMAIN = b"XIAN-HYBRID-TX\0"
AUTH_DOMAIN = b"XIAN-HYBRID-AUTH\0"
MAX_PAYLOAD_BYTES = 131_072
ED_PUBLIC_BYTES = 32
ED_SIGNATURE_BYTES = 64
PQ_PUBLIC_BYTES = 1952
PQ_PRIVATE_BYTES = 4032
PQ_SIGNATURE_BYTES = 3309
HEADER_BYTES = len(AUTH_DOMAIN) + 2 + 8
AUTH_BYTES = HEADER_BYTES + ED_SIGNATURE_BYTES + PQ_SIGNATURE_BYTES

# Fail on backend API/parameter drift rather than changing the wire contract.
if (ml_dsa_65.PUBLIC_KEY_SIZE, ml_dsa_65.SECRET_KEY_SIZE, ml_dsa_65.SIGNATURE_SIZE) != (
    PQ_PUBLIC_BYTES,
    PQ_PRIVATE_BYTES,
    PQ_SIGNATURE_BYTES,
):
    raise RuntimeError("ML-DSA-65 backend does not match experimental suite 1")


def _bytes(value: bytes, length: int, name: str) -> None:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")


def _validate_context(chain_id: str, account_id: str, counter: int) -> None:
    if type(chain_id) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", chain_id):
        raise ValueError("invalid experimental chain id")
    if type(account_id) is not str or not re.fullmatch(r"account:[0-9a-f]{64}", account_id):
        raise ValueError("invalid experimental account id")
    if type(counter) is not int or not 0 <= counter < 2**64:
        raise ValueError("counter must be an unsigned 64-bit integer")


@dataclass(frozen=True)
class AccountRecord:
    """Already-authenticated registry snapshot, never transaction-supplied keys."""

    chain_id: str
    account_id: str
    key_epoch: int
    ed_public_key: bytes
    pq_public_key: bytes

    def __post_init__(self) -> None:
        _validate_context(self.chain_id, self.account_id, self.key_epoch)
        _bytes(self.ed_public_key, ED_PUBLIC_BYTES, "ed_public_key")
        _bytes(self.pq_public_key, PQ_PUBLIC_BYTES, "pq_public_key")
        if not crypto_core_ed25519_is_valid_point(self.ed_public_key):
            raise ValueError("Ed25519 public key must be a canonical prime-order point")


@dataclass(frozen=True)
class PrivateKeys:
    # Avoid accidental repr/log disclosure; Python bytes do not provide zeroization.
    ed_seed: bytes = field(repr=False)
    pq_secret_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _bytes(self.ed_seed, 32, "ed_seed")
        _bytes(self.pq_secret_key, PQ_PRIVATE_BYTES, "pq_secret_key")


def generate_keys(
    *, chain_id: str, account_id: str, key_epoch: int = 0
) -> tuple[AccountRecord, PrivateKeys]:
    """Generate independent random keys for a local record; does not enroll it."""
    ed_key = SigningKey.generate()
    pq_public, pq_secret = ml_dsa_65.generate_keypair()
    return (
        AccountRecord(chain_id, account_id, key_epoch, bytes(ed_key.verify_key), pq_public),
        PrivateKeys(bytes(ed_key), pq_secret),
    )


def _lp16(value: str) -> bytes:
    data = value.encode("ascii")
    return len(data).to_bytes(2, "big") + data


def signing_transcript(record: AccountRecord, payload: bytes) -> bytes:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
        raise ValueError("payload must be nonempty bounded bytes")
    return b"".join(
        (
            TX_DOMAIN,
            bytes((VERSION, SUITE)),
            _lp16(record.chain_id),
            _lp16(record.account_id),
            record.key_epoch.to_bytes(8, "big"),
            record.ed_public_key,
            record.pq_public_key,
            len(payload).to_bytes(4, "big"),
            payload,
        )
    )


def _header(record: AccountRecord) -> bytes:
    return AUTH_DOMAIN + bytes((VERSION, SUITE)) + record.key_epoch.to_bytes(8, "big")


def sign(record: AccountRecord, keys: PrivateKeys, payload: bytes) -> bytes:
    """Sign and self-check to catch mismatched keys before returning an envelope."""
    return _sign_transcript(record, keys, signing_transcript(record, payload))


def _sign_transcript(record: AccountRecord, keys: PrivateKeys, message: bytes) -> bytes:
    """Internal primitive: callers must supply a fully bound, domain-separated message."""
    ed_key = SigningKey(keys.ed_seed)
    if bytes(ed_key.verify_key) != record.ed_public_key:
        raise ValueError("Ed25519 private key does not match account record")
    ed_signature = ed_key.sign(message).signature
    pq_signature = ml_dsa_65.sign(keys.pq_secret_key, message)
    envelope = _header(record) + ed_signature + pq_signature
    if not _verify_transcript(record, message, envelope):
        raise ValueError("private keys/signatures do not match account record")
    return envelope


def verify(record: AccountRecord, payload: bytes, envelope: bytes) -> bool:
    """Authenticate bytes under a trusted record; never fall back to one signature."""
    if type(envelope) is not bytes or len(envelope) != AUTH_BYTES:
        return False
    if envelope[:HEADER_BYTES] != _header(record):
        return False
    try:
        message = signing_transcript(record, payload)
    except ValueError:
        return False
    return _verify_transcript(record, message, envelope)


def _verify_transcript(record: AccountRecord, message: bytes, envelope: bytes) -> bool:
    """Internal primitive shared by transaction and lifecycle domains."""
    if type(envelope) is not bytes or len(envelope) != AUTH_BYTES:
        return False
    if envelope[:HEADER_BYTES] != _header(record):
        return False
    ed_end = HEADER_BYTES + ED_SIGNATURE_BYTES
    try:
        VerifyKey(record.ed_public_key).verify(message, envelope[HEADER_BYTES:ed_end])
    except (BadSignatureError, ValueError):
        return False
    return ml_dsa_65.verify(record.pq_public_key, message, envelope[ed_end:])
