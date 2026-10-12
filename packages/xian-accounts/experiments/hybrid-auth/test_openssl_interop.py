"""Independent ML-DSA implementation check. Set XIAN_HYBRID_OPENSSL to run live tests."""

import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

import hybrid_auth as hybrid
import pytest
from nacl.signing import SigningKey

# SubjectPublicKeyInfo: OID 2.16.840.1.101.3.4.3.18, absent parameters,
# BIT STRING with zero unused bits and a 1,952-byte ML-DSA-65 public key.
ML_DSA_65_SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
FIXTURE = Path(__file__).with_name("openssl_vector.json")


def run_openssl(executable, *args):
    return subprocess.run(
        [executable, *map(str, args)], check=True, capture_output=True, timeout=30
    ).stdout


@pytest.fixture
def openssl():
    executable = os.environ.get("XIAN_HYBRID_OPENSSL")
    if not executable:
        pytest.skip("set XIAN_HYBRID_OPENSSL to an OpenSSL 3.5+ executable")
    # An explicitly selected backend must work; do not silently skip failures.
    assert b"ML-DSA-65" in run_openssl(executable, "list", "-signature-algorithms")
    return executable


def independent_transcript(record, payload):
    chain = record.chain_id.encode("ascii")
    account = record.account_id.encode("ascii")
    return (
        bytes.fromhex("5849414e2d4859425249442d5458000101")
        + struct.pack(">H", len(chain))
        + chain
        + struct.pack(">H", len(account))
        + account
        + struct.pack(">Q", record.key_epoch)
        + record.ed_public_key
        + record.pq_public_key
        + struct.pack(">I", len(payload))
        + payload
    )


def openssl_vector(executable, directory):
    """Create public test material; the random private key stays in a temporary directory."""
    secret = directory / "ml-dsa.pem"
    run_openssl(executable, "genpkey", "-algorithm", "ML-DSA-65", "-out", secret)
    spki = run_openssl(executable, "pkey", "-in", secret, "-pubout", "-outform", "DER")
    assert spki[:22] == ML_DSA_65_SPKI_PREFIX and len(spki) == 1974
    ed = SigningKey.generate()
    record = hybrid.AccountRecord(
        "local-hybrid", "account:" + "ab" * 32, 7, bytes(ed.verify_key), spki[22:]
    )
    payload = (
        b'{"chain_id":"local-hybrid","chi_supplied":1000,"contract":"currency",'
        b'"function":"transfer","kwargs":{"amount":1,"to":"test-recipient"},'
        b'"nonce":1,"sender":"account:' + b"ab" * 32 + b'"}'
    )
    transcript = independent_transcript(record, payload)
    message = directory / "message.bin"
    message.write_bytes(transcript)
    pq_signature = run_openssl(
        executable, "pkeyutl", "-sign", "-rawin", "-inkey", secret, "-in", message
    )
    assert len(pq_signature) == 3309
    header = bytes.fromhex("5849414e2d4859425249442d41555448000101") + struct.pack(">Q", 7)
    envelope = header + ed.sign(transcript).signature + pq_signature
    return {
        "schema": "xian-hybrid-auth-experiment-vector-v1",
        "producer": run_openssl(executable, "version").decode().strip(),
        "ml_dsa_mode": "pure, empty context",
        "chain_id": record.chain_id,
        "account_id": record.account_id,
        "key_epoch": record.key_epoch,
        "ed_public_key": record.ed_public_key.hex(),
        "pq_public_key": record.pq_public_key.hex(),
        "payload": payload.hex(),
        "transcript_sha512": hashlib.sha512(transcript).hexdigest(),
        "envelope": envelope.hex(),
    }


def check_vector(vector):
    record = hybrid.AccountRecord(
        vector["chain_id"],
        vector["account_id"],
        vector["key_epoch"],
        bytes.fromhex(vector["ed_public_key"]),
        bytes.fromhex(vector["pq_public_key"]),
    )
    payload = bytes.fromhex(vector["payload"])
    envelope = bytes.fromhex(vector["envelope"])
    transcript = hybrid.signing_transcript(record, payload)
    assert hashlib.sha512(transcript).hexdigest() == vector["transcript_sha512"]
    assert hybrid.verify(record, payload, envelope)
    assert not hybrid.verify(record, payload + b"x", envelope)
    assert not hybrid.verify(record, payload, envelope[:-1] + bytes([envelope[-1] ^ 1]))


def test_frozen_openssl_vector():
    check_vector(json.loads(FIXTURE.read_text()))


def test_openssl_signatures_verify_in_pqclean(openssl, tmp_path):
    check_vector(openssl_vector(openssl, tmp_path))


def test_pqclean_signatures_verify_in_openssl(openssl, tmp_path):
    record, keys = hybrid.generate_keys(chain_id="local-hybrid", account_id="account:" + "ab" * 32)
    payload = b"interoperability-test"
    envelope = hybrid.sign(record, keys, payload)
    public = tmp_path / "public.der"
    message = tmp_path / "message.bin"
    signature = tmp_path / "signature.bin"
    public.write_bytes(ML_DSA_65_SPKI_PREFIX + record.pq_public_key)
    message.write_bytes(independent_transcript(record, payload))
    signature.write_bytes(envelope[91:])
    command = (
        "pkeyutl",
        "-verify",
        "-rawin",
        "-pubin",
        "-keyform",
        "DER",
        "-inkey",
        public,
        "-in",
        message,
        "-sigfile",
        signature,
    )
    run_openssl(openssl, *command)
    message.write_bytes(message.read_bytes() + b"x")
    with pytest.raises(subprocess.CalledProcessError):
        run_openssl(openssl, *command)
