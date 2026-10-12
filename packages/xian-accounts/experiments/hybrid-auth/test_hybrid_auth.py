"""Attack-oriented tests of the experimental authorization boundary."""

from dataclasses import replace

import hybrid_auth as hybrid
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nacl.signing import SigningKey

PAYLOAD = (
    b'{"chain_id":"local-hybrid","chi_supplied":1000,"contract":"currency",'
    b'"function":"transfer","kwargs":{"amount":1,"to":"test-recipient"},'
    b'"nonce":1,"sender":"account:' + b"ab" * 32 + b'"}'
)


@pytest.fixture(scope="module")
def owner():
    return hybrid.generate_keys(chain_id="local-hybrid", account_id="account:" + "ab" * 32)


@pytest.fixture(scope="module")
def attacker():
    return hybrid.generate_keys(chain_id="local-hybrid", account_id="account:" + "cd" * 32)


@pytest.fixture(scope="module")
def valid(owner):
    return hybrid.sign(*owner, PAYLOAD)


def test_roundtrip_and_fixed_sizes(owner, valid):
    record, keys = owner
    assert hybrid.verify(record, PAYLOAD, valid)
    assert len(valid) == 3400
    assert len(record.ed_public_key) + len(record.pq_public_key) == 1984
    assert keys.ed_seed.hex() not in repr(keys)
    assert keys.pq_secret_key.hex() not in repr(keys)


@pytest.mark.parametrize("offset", [0, 16, 17, 18, 19, 26, 27, 58, 90, 91, 1000, 3399])
def test_tampering_each_header_and_signature_region(owner, valid, offset):
    corrupt = bytearray(valid)
    corrupt[offset] ^= 1
    assert not hybrid.verify(owner[0], PAYLOAD, bytes(corrupt))


@pytest.mark.parametrize("size", [0, 1, 26, 27, 64, 91, 3309, 3399, 3401, 6800])
def test_missing_truncated_or_extra_signatures_rejected(owner, valid, size):
    envelope = (valid * 2)[:size]
    assert not hybrid.verify(owner[0], PAYLOAD, envelope)


@pytest.mark.parametrize("payload", [b"", b"x" * 131073, "text", None, bytearray(b"x")])
def test_payload_limits(owner, valid, payload):
    assert not hybrid.verify(owner[0], payload, valid)
    with pytest.raises(ValueError):
        hybrid.sign(*owner, payload)


def test_maximum_payload(owner):
    payload = b"x" * hybrid.MAX_PAYLOAD_BYTES
    envelope = hybrid.sign(*owner, payload)
    assert hybrid.verify(owner[0], payload, envelope)


@pytest.mark.parametrize("envelope", [None, "a" * 3400, bytearray(3400), memoryview(bytes(3400))])
def test_envelope_must_be_bytes(owner, envelope):
    assert not hybrid.verify(owner[0], PAYLOAD, envelope)


@pytest.mark.parametrize(
    "change",
    [
        {"chain_id": "different-chain"},
        {"account_id": "account:" + "00" * 32},
        {"key_epoch": 1},
    ],
)
def test_context_substitution(owner, valid, change):
    assert not hybrid.verify(replace(owner[0], **change), PAYLOAD, valid)


def test_payload_and_nonce_substitution(owner, valid):
    assert not hybrid.verify(owner[0], PAYLOAD + b" ", valid)
    assert not hybrid.verify(owner[0], PAYLOAD.replace(b'"nonce":1', b'"nonce":2'), valid)


@pytest.mark.parametrize("key_name", ["ed_public_key", "pq_public_key"])
def test_either_public_key_substitution(owner, attacker, valid, key_name):
    forged_record = replace(owner[0], **{key_name: getattr(attacker[0], key_name)})
    assert not hybrid.verify(forged_record, PAYLOAD, valid)


def test_valid_attacker_pair_cannot_authorize_trusted_account(owner, attacker):
    forged_record = replace(
        attacker[0], account_id=owner[0].account_id, key_epoch=owner[0].key_epoch
    )
    forged = hybrid.sign(forged_record, attacker[1], PAYLOAD)
    assert hybrid.verify(forged_record, PAYLOAD, forged)
    assert not hybrid.verify(owner[0], PAYLOAD, forged)


@pytest.mark.parametrize("key_name", ["ed_seed", "pq_secret_key"])
def test_signer_rejects_mismatched_private_key(owner, attacker, key_name):
    wrong_keys = replace(owner[1], **{key_name: getattr(attacker[1], key_name)})
    with pytest.raises(ValueError, match="match account record"):
        hybrid.sign(owner[0], wrong_keys, PAYLOAD)


def test_epoch_rotation_rejects_old_authorization_even_if_header_rewritten(owner, valid):
    rotated = replace(owner[0], key_epoch=1)
    assert not hybrid.verify(rotated, PAYLOAD, valid)
    rewritten = valid[:19] + (1).to_bytes(8, "big") + valid[27:]
    assert not hybrid.verify(rotated, PAYLOAD, rewritten)
    new_auth = hybrid.sign(rotated, owner[1], PAYLOAD)
    assert hybrid.verify(rotated, PAYLOAD, new_auth)
    assert not hybrid.verify(owner[0], PAYLOAD, new_auth)


def test_each_component_binds_the_other_public_key(owner, attacker, valid):
    # Even if one primitive were bypassed, the other signature binds both keys.
    record = owner[0]
    ed_sig = valid[27:91]
    pq_sig = valid[91:]
    changed_ed = replace(record, ed_public_key=attacker[0].ed_public_key)
    assert not hybrid.ml_dsa_65.verify(
        record.pq_public_key, hybrid.signing_transcript(changed_ed, PAYLOAD), pq_sig
    )
    changed_pq = replace(record, pq_public_key=attacker[0].pq_public_key)
    with pytest.raises(hybrid.BadSignatureError):
        hybrid.VerifyKey(record.ed_public_key).verify(
            hybrid.signing_transcript(changed_pq, PAYLOAD), ed_sig
        )


def test_pq_failure_cannot_fall_back_to_valid_ed_signature(owner, valid):
    assert not hybrid.verify(owner[0], PAYLOAD, valid[:91] + bytes(3309))


def test_structural_and_ed_failure_do_not_invoke_pq_backend(owner, valid, monkeypatch):
    def forbidden(*args):
        pytest.fail("PQ verification reached for malformed/Ed25519-invalid authorization")

    monkeypatch.setattr(hybrid.ml_dsa_65, "verify", forbidden)
    assert not hybrid.verify(owner[0], PAYLOAD, valid + b"x")
    assert not hybrid.verify(owner[0], PAYLOAD, valid[:17] + b"\x02\x01" + valid[19:])
    assert not hybrid.verify(owner[0], PAYLOAD, valid[:18] + b"\x00" + valid[19:])
    assert not hybrid.verify(owner[0], PAYLOAD, valid[:27] + bytes(64) + valid[91:])


@pytest.mark.parametrize(
    "change",
    [
        {"chain_id": "Local"},
        {"chain_id": ""},
        {"chain_id": "a" * 65},
        {"chain_id": "local\n"},
        {"chain_id": "lοcal"},
        {"chain_id": " local"},
        {"account_id": "ab" * 32},
        {"account_id": "account:" + "AB" * 32},
        {"account_id": "account:" + "ab" * 32 + "\n"},
        {"key_epoch": -1},
        {"key_epoch": 2**64},
        {"key_epoch": True},
        {"ed_public_key": bytes(31)},
        {"ed_public_key": b"\x01" + bytes(31)},
        {"ed_public_key": bytes(32)},
        {"pq_public_key": bytes(1951)},
        {"pq_public_key": bytearray(1952)},
    ],
)
def test_noncanonical_or_unbounded_records(owner, change):
    with pytest.raises(ValueError):
        replace(owner[0], **change)


def test_noncanonical_ed_scalar(owner, valid):
    order = 2**252 + 27742317777372353535851937790883648493
    scalar = int.from_bytes(valid[59:91], "little") + order
    malformed = valid[:59] + scalar.to_bytes(32, "little") + valid[91:]
    assert not hybrid.verify(owner[0], PAYLOAD, malformed)


def test_transcript_encoding_golden():
    # Fixed public inputs, including a structural dummy PQ key (not for signing).
    record = hybrid.AccountRecord(
        "local",
        "account:" + "00" * 32,
        0x0102030405060708,
        bytes(SigningKey(bytes(32)).verify_key),
        bytes(1952),
    )
    prefix = bytes.fromhex("5849414e2d4859425249442d545800010100056c6f63616c0048")
    expected = (
        prefix
        + b"account:"
        + b"00" * 32
        + bytes.fromhex("0102030405060708")
        + bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
        + bytes(1952)
        + bytes.fromhex("00000003")
        + b"abc"
    )
    assert hybrid.signing_transcript(record, b"abc") == expected


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=3399), st.integers(min_value=1, max_value=255))
def test_random_single_byte_corruption(owner, valid, offset, mask):
    corrupt = bytearray(valid)
    corrupt[offset] ^= mask
    assert not hybrid.verify(owner[0], PAYLOAD, bytes(corrupt))


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=0, max_size=3500))
def test_arbitrary_envelopes_fail_closed(owner, envelope):
    assert not hybrid.verify(owner[0], PAYLOAD, envelope)
