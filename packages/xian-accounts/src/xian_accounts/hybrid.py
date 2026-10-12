"""Hybrid account wire primitives; policy and trusted state belong to the node.

See xian-meta/docs/ACCOUNT_REGISTRY_PROTOCOL.md. These domains deliberately do
not accept experimental signatures. Importing this module needs no PQ backend;
using hybrid cryptography requires the pinned ``hybrid`` extra.
"""

import re
from dataclasses import dataclass

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

TX_FORMAT = "xian_account_v1"
SCHEME = "ed25519_ml_dsa_65_v1"
ENROLL_SCHEME = "ed25519_enroll_v1"
MAX_PAYLOAD_BYTES = 131_072
MAX_WIRE_BYTES = 524_288
PQ_PUBLIC_BYTES = 1952
PQ_SIGNATURE_BYTES = 3309
AUTH_DOMAIN = b"XIAN-ACCOUNT-AUTH\0"
HEADER_BYTES = len(AUTH_DOMAIN) + 2 + 8
AUTH_BYTES = HEADER_BYTES + 64 + PQ_SIGNATURE_BYTES
ROLES = frozenset({"transaction", "authority", "new_active", "new_recovery"})


def backend():
    from pqcrypto.sign import ml_dsa_65

    if (ml_dsa_65.PUBLIC_KEY_SIZE, ml_dsa_65.SECRET_KEY_SIZE, ml_dsa_65.SIGNATURE_SIZE) != (
        1952,
        4032,
        3309,
    ):
        raise RuntimeError("unsupported ML-DSA-65 backend parameters")
    return ml_dsa_65


def hex_bytes(value: object, size: int) -> bytes:
    if (
        type(value) is not str
        or len(value) != size * 2
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise ValueError("invalid canonical hex or length")
    return bytes.fromhex(value)


def uint64(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("expected unsigned 64-bit integer")
    return value


def exact_dict(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("unexpected or missing fields")
    return value


@dataclass(frozen=True)
class PublicKeys:
    ed25519: bytes
    ml_dsa_65: bytes

    def __post_init__(self):
        if type(self.ed25519) is not bytes or len(self.ed25519) != 32:
            raise ValueError("invalid Ed25519 key size")
        if not crypto_core_ed25519_is_valid_point(self.ed25519):
            raise ValueError("Ed25519 key must be canonical and prime order")
        if type(self.ml_dsa_65) is not bytes or len(self.ml_dsa_65) != PQ_PUBLIC_BYTES:
            raise ValueError("invalid ML-DSA-65 key size")

    def to_dict(self) -> dict:
        return {"ed25519": self.ed25519.hex(), "ml_dsa_65": self.ml_dsa_65.hex()}

    @classmethod
    def from_dict(cls, value):
        exact_dict(value, {"ed25519", "ml_dsa_65"})
        return cls(hex_bytes(value["ed25519"], 32), hex_bytes(value["ml_dsa_65"], PQ_PUBLIC_BYTES))


@dataclass(frozen=True)
class AccountRecord:
    epoch: int
    active: PublicKeys
    recovery: PublicKeys

    def __post_init__(self):
        uint64(self.epoch)
        if type(self.active) is not PublicKeys or type(self.recovery) is not PublicKeys:
            raise ValueError("two hybrid key pairs required")
        if (
            self.active.ed25519 == self.recovery.ed25519
            or self.active.ml_dsa_65 == self.recovery.ml_dsa_65
        ):
            raise ValueError("active and recovery keys must be distinct")

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "epoch": self.epoch,
            "active": self.active.to_dict(),
            "recovery": self.recovery.to_dict(),
        }

    @classmethod
    def from_dict(cls, value):
        exact_dict(value, {"version", "epoch", "active", "recovery"})
        if type(value["version"]) is not int or value["version"] != 1:
            raise ValueError("unsupported account record version")
        return cls(
            value["epoch"],
            PublicKeys.from_dict(value["active"]),
            PublicKeys.from_dict(value["recovery"]),
        )


def _payload(payload: bytes) -> bytes:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
        raise ValueError("invalid hybrid payload size/type")
    return len(payload).to_bytes(4, "big") + payload


def enrollment_transcript(payload: bytes) -> bytes:
    return b"XIAN-ACCOUNT-ENROLL\0\x01\x01" + _payload(payload)


def signing_transcript(keys: PublicKeys, epoch: int, payload: bytes, *, role: str) -> bytes:
    uint64(epoch)
    if role not in ROLES:
        raise ValueError("invalid signing role")
    return (
        b"XIAN-ACCOUNT-TX\0\x01\x01"
        + bytes([len(role)])
        + role.encode("ascii")
        + epoch.to_bytes(8, "big")
        + keys.ed25519
        + keys.ml_dsa_65
        + _payload(payload)
    )


def _header(epoch: int) -> bytes:
    return AUTH_DOMAIN + b"\x01\x01" + uint64(epoch).to_bytes(8, "big")


def verify(
    keys: PublicKeys, epoch: int, payload: bytes, signature: bytes, *, role="transaction"
) -> bool:
    if type(signature) is not bytes or len(signature) != AUTH_BYTES:
        return False
    if signature[:HEADER_BYTES] != _header(epoch):
        return False
    message = signing_transcript(keys, epoch, payload, role=role)
    ed_end = HEADER_BYTES + 64
    try:
        VerifyKey(keys.ed25519).verify(message, signature[HEADER_BYTES:ed_end])
    except (ValueError, BadSignatureError):
        return False
    return backend().verify(keys.ml_dsa_65, message, signature[ed_end:])


def sign(
    keys: PublicKeys,
    epoch: int,
    payload: bytes,
    *,
    ed_seed: bytes,
    pq_secret: bytes,
    role="transaction",
) -> bytes:
    """Low-level signer; callers must supply canonical bytes and protect backups."""
    message = signing_transcript(keys, epoch, payload, role=role)
    ed = SigningKey(ed_seed)
    if bytes(ed.verify_key) != keys.ed25519:
        raise ValueError("private key mismatch")
    signature = _header(epoch) + ed.sign(message).signature + backend().sign(pq_secret, message)
    if not verify(keys, epoch, payload, signature, role=role):
        raise ValueError("signature self-check failed")
    return signature
