"""Deliberately regenerate public conformance vectors from ephemeral test keys."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import account_lifecycle as lifecycle
import hybrid_auth as hybrid
from fixture_support import make_scenario
from state_codec import encode_state


def generate():
    s = make_scenario()
    blobs, cases = {}, []

    def put(name, value):
        blobs[name] = value.hex()
        return name

    for name in ("legacy", "first", "second", "third"):
        put(name, encode_state(s[name]))
    payload = b'{"purpose":"local-parity-test"}'
    put("payload", payload)
    put("tx", hybrid.sign(s["first"].active, s["first_keys"][0], payload))
    transaction = {
        "name": "transaction_valid",
        "kind": "tx",
        "state": "first",
        "payload": "payload",
        "auth": "tx",
        "expected": True,
    }
    cases.append(
        {
            **transaction,
            "transcripts_sha256": [
                hashlib.sha256(hybrid.signing_transcript(s["first"].active, payload)).hexdigest()
            ],
        }
    )
    for name, replacement in (
        ("trailing_state", encode_state(s["first"]) + b"x"),
        ("truncated_state", encode_state(s["first"])[:-1]),
        ("unknown_state", b"\x02"),
        ("empty_state", b""),
        ("oversized_state", bytes(4266)),
    ):
        put(name, replacement)
        cases.append({**transaction, "name": name, "state": name, "expected": False})
    for name, offset in (
        ("bad_domain", 0),
        ("bad_version", 17),
        ("bad_suite", 18),
        ("bad_epoch", 26),
        ("bad_ed", 27),
        ("bad_pq", 91),
    ):
        auth = bytearray.fromhex(blobs["tx"])
        auth[offset] ^= 1
        put(name, bytes(auth))
        cases.append({**transaction, "name": name, "auth": name, "expected": False})
    for name, value in (
        ("missing_pq", bytes.fromhex(blobs["tx"])[:91]),
        ("extra_auth", bytes.fromhex(blobs["tx"]) + b"x"),
    ):
        put(name, value)
        cases.append({**transaction, "name": name, "auth": name, "expected": False})
    put("changed_payload", payload + b" ")
    put("empty_payload", b"")
    for name in ("changed_payload", "empty_payload"):
        cases.append({**transaction, "name": name, "payload": name, "expected": False})
    for name, changes in (
        ("other_chain", {"chain_id": "other-chain"}),
        ("other_account", {"account_id": "account:" + "cd" * 32}),
        ("other_epoch", {"key_epoch": 1}),
    ):
        state = lifecycle.HybridState(
            replace(s["first"].active, **changes), replace(s["first"].recovery, **changes)
        )
        put(name, encode_state(state))
        cases.append({**transaction, "name": name, "state": name, "expected": False})
    for field in ("ed_public_key", "pq_public_key"):
        state = replace(
            s["first"],
            active=replace(s["first"].active, **{field: getattr(s["third"].active, field)}),
        )
        name = "substitute_" + field
        put(name, encode_state(state))
        cases.append({**transaction, "name": name, "state": name, "expected": False})
    # A structurally encoded, invalid identity public key must fail before verification.
    raw = bytearray(encode_state(s["first"]))
    key_offset = 1 + 2 + len(s["first"].active.chain_id) + 2 + len(s["first"].active.account_id) + 8
    raw[key_offset : key_offset + 32] = b"\x01" + bytes(31)
    put("weak_ed_state", bytes(raw))
    cases.append(
        {**transaction, "name": "weak_ed_state", "state": "weak_ed_state", "expected": False}
    )
    scalar_auth = bytearray.fromhex(blobs["tx"])
    scalar = (
        int.from_bytes(scalar_auth[59:91], "little")
        + 2**252
        + 27742317777372353535851937790883648493
    )
    scalar_auth[59:91] = scalar.to_bytes(32, "little")
    put("noncanonical_scalar", bytes(scalar_auth))
    cases.append(
        {
            **transaction,
            "name": "noncanonical_scalar",
            "auth": "noncanonical_scalar",
            "expected": False,
        }
    )
    high_epoch = 2**63 + 9
    high = lifecycle.HybridState(
        replace(s["first"].active, key_epoch=high_epoch),
        replace(s["first"].recovery, key_epoch=high_epoch),
    )
    put("high_epoch_state", encode_state(high))
    put("high_epoch_auth", hybrid.sign(high.active, s["first_keys"][0], payload))
    cases.append(
        {
            **transaction,
            "name": "uint64_epoch_valid",
            "state": "high_epoch_state",
            "auth": "high_epoch_auth",
        }
    )
    frozen = json.loads(Path(__file__).with_name("openssl_vector.json").read_text())
    openssl_record = hybrid.AccountRecord(
        frozen["chain_id"],
        frozen["account_id"],
        frozen["key_epoch"],
        bytes.fromhex(frozen["ed_public_key"]),
        bytes.fromhex(frozen["pq_public_key"]),
    )
    put(
        "openssl_state",
        encode_state(
            lifecycle.HybridState(
                openssl_record, replace(s["first"].recovery, key_epoch=frozen["key_epoch"])
            )
        ),
    )
    blobs["openssl_payload"], blobs["openssl_auth"] = frozen["payload"], frozen["envelope"]
    cases.append(
        {
            **transaction,
            "name": "openssl_signature_valid",
            "state": "openssl_state",
            "payload": "openssl_payload",
            "auth": "openssl_auth",
        }
    )
    for name in ("enrollment", "rotation", "recovery"):
        request = s[name]
        current_name = "legacy" if name == "enrollment" else "first"
        candidate_name = "first" if name == "enrollment" else "second"
        case = {
            "name": name + "_valid",
            "kind": "transition",
            "state": current_name,
            "candidate": candidate_name,
            "operation": int(request.operation),
            "enrollment_open": True,
            "expected": True,
        }
        for field in ("authority_proof", "active_proof", "recovery_proof"):
            case[field] = put(name + "_" + field, getattr(request, field))
        cases.append(
            {
                **case,
                "transcripts_sha256": [
                    hashlib.sha256(
                        lifecycle.transition_transcript(
                            s[current_name], request.operation, request.candidate, role
                        )
                    ).hexdigest()
                    for role in lifecycle.Role
                ],
            }
        )
        for field in ("authority_proof", "active_proof", "recovery_proof"):
            invalid = bytearray(getattr(request, field))
            invalid[-1] ^= 1
            key = put(name + "_bad_" + field, bytes(invalid))
            cases.append({**case, "name": key, field: key, "expected": False})
        cases.append({**case, "name": name + "_stale", "state": candidate_name, "expected": False})
        cases.append(
            {
                **case,
                "name": name + "_swapped_proofs",
                "active_proof": case["recovery_proof"],
                "recovery_proof": case["active_proof"],
                "expected": False,
            }
        )
        if name == "enrollment":
            cases.append(
                {**case, "name": "enrollment_closed", "enrollment_open": False, "expected": False}
            )
        else:
            cases.append(
                {
                    **case,
                    "name": name + "_wrong_operation",
                    "operation": 3 if name == "rotation" else 2,
                    "expected": False,
                }
            )
            cases.append(
                {**case, "name": name + "_unsupported_operation", "operation": 4, "expected": False}
            )
    # Decoder-only cases ensure malformed-state rejection is independently
    # checked, not merely implied by a subsequently invalid signature.
    first_bytes = encode_state(s["first"])
    record_size = (len(first_bytes) - 1) // 2
    for name, replacement, offset in (
        ("shared_ed_roles", s["first"].active.ed_public_key, key_offset + record_size),
        ("shared_pq_roles", s["first"].active.pq_public_key, key_offset + record_size + 32),
        ("uppercase_chain", b"L", 3),
        ("non_ascii_chain", b"\x80", 3),
    ):
        raw = bytearray(first_bytes)
        raw[offset : offset + len(replacement)] = replacement
        put(name, bytes(raw))
    for name in (
        "legacy",
        "first",
        "high_epoch_state",
        "trailing_state",
        "truncated_state",
        "unknown_state",
        "empty_state",
        "oversized_state",
        "weak_ed_state",
        "shared_ed_roles",
        "shared_pq_roles",
        "uppercase_chain",
        "non_ascii_chain",
    ):
        cases.append(
            {
                "name": "decode_" + name,
                "kind": "decode",
                "state": name,
                "expected": name in ("legacy", "first", "high_epoch_state"),
            }
        )
    return {
        "schema": "xian-hybrid-parity-v1",
        "provenance": "Generated test keys; PQClean/PyNaCl signatures plus frozen OpenSSL ML-DSA vector. No private keys.",
        "blobs": blobs,
        "cases": cases,
    }


if __name__ == "__main__":
    destination = Path(__file__).with_name("parity_vectors.json")
    destination.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"Wrote public conformance vectors to {destination.name}")
