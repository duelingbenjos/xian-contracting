"""Production framing and key validation; no real account secrets are used."""

import pytest
from nacl.signing import SigningKey
from xian_accounts import hybrid

pytest.importorskip("pqcrypto")


@pytest.fixture
def material():
    ed = SigningKey.generate()
    public, secret = hybrid.backend().generate_keypair()
    return hybrid.PublicKeys(bytes(ed.verify_key), public), bytes(ed), secret


@pytest.mark.parametrize("role", sorted(hybrid.ROLES))
def test_framing_and_both_signatures(material, role):
    keys, seed, secret = material
    payload = b'{"chain_id":"local","nonce":7,"sender":"test"}'
    epoch = 2**63 + 9
    # Independently assemble the bytes; signing and verification cannot mask
    # framing mistakes by sharing the same transcript function.
    expected = (
        b"XIAN-ACCOUNT-TX\0"
        + bytes([1, 1, len(role)])
        + role.encode()
        + epoch.to_bytes(8, "big")
        + keys.ed25519
        + keys.ml_dsa_65
        + len(payload).to_bytes(4, "big")
        + payload
    )
    assert hybrid.signing_transcript(keys, epoch, payload, role=role) == expected
    signature = hybrid.sign(keys, epoch, payload, ed_seed=seed, pq_secret=secret, role=role)
    assert hybrid.verify(keys, epoch, payload, signature, role=role)
    assert not hybrid.verify(keys, epoch - 1, payload, signature, role=role)
    assert not hybrid.verify(keys, epoch, payload + b" ", signature, role=role)
    for offset in [0, hybrid.HEADER_BYTES, hybrid.HEADER_BYTES + 64, len(signature) - 1]:
        damaged = bytearray(signature)
        damaged[offset] ^= 1
        assert not hybrid.verify(keys, epoch, payload, bytes(damaged), role=role)
    for other in hybrid.ROLES - {role}:
        assert not hybrid.verify(keys, epoch, payload, signature, role=other)
    assert not hybrid.verify(keys, epoch, payload, signature[:-1], role=role)
    assert not hybrid.verify(keys, epoch, payload, signature + b"\0", role=role)


@pytest.mark.parametrize(
    "ed", [bytes(32), b"\x01" + bytes(31), bytes.fromhex("ed" + "ff" * 30 + "7f")]
)
def test_rejects_noncanonical_or_small_order_ed_keys(material, ed):
    with pytest.raises(ValueError):
        hybrid.PublicKeys(ed, material[0].ml_dsa_65)


@pytest.mark.parametrize("epoch", [True, -1, 2**64, "0"])
def test_rejects_invalid_epoch(material, epoch):
    keys = material[0]
    with pytest.raises(ValueError):
        hybrid.AccountRecord(epoch, keys, keys)


def test_record_roundtrip_and_role_separation(material):
    keys, _, _ = material
    ed = SigningKey.generate()
    public, _ = hybrid.backend().generate_keypair()
    recovery = hybrid.PublicKeys(bytes(ed.verify_key), public)
    record = hybrid.AccountRecord(2**64 - 1, keys, recovery)
    assert hybrid.AccountRecord.from_dict(record.to_dict()) == record
    for same in [
        keys,
        hybrid.PublicKeys(keys.ed25519, public),
        hybrid.PublicKeys(bytes(ed.verify_key), keys.ml_dsa_65),
    ]:
        with pytest.raises(ValueError):
            hybrid.AccountRecord(0, keys, same)


def test_payload_limits_and_enrollment_domain(material):
    keys = material[0]
    for value in [b"", b"x" * (hybrid.MAX_PAYLOAD_BYTES + 1), "not bytes"]:
        with pytest.raises(ValueError):
            hybrid.signing_transcript(keys, 0, value, role="transaction")
    payload = b"x" * hybrid.MAX_PAYLOAD_BYTES
    assert (
        hybrid.enrollment_transcript(payload)
        == b"XIAN-ACCOUNT-ENROLL\0\x01\x01" + len(payload).to_bytes(4, "big") + payload
    )


@pytest.mark.parametrize("value", ["AA", " 00", "00 ", "0x00", "gg", "", None])
def test_strict_hex(value):
    with pytest.raises(ValueError):
        hybrid.hex_bytes(value, 1)
