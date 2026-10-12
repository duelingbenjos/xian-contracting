"""Local microbenchmark, not a network-capacity or mobile-performance estimate."""

import argparse
import importlib.metadata
import json
import math
import platform
import statistics
import subprocess
from datetime import datetime, timezone
from time import perf_counter_ns

import hybrid_auth as hybrid
from nacl.signing import SigningKey


def measure(operation, samples):
    for _ in range(10):
        operation()
    values = []
    for _ in range(samples):
        start = perf_counter_ns()
        operation()
        values.append((perf_counter_ns() - start) / 1_000_000)
    values.sort()
    return {
        "samples": samples,
        "median_ms": round(statistics.median(values), 6),
        "p95_ms": round(values[math.ceil(samples * 0.95) - 1], 6),
    }


def benchmark(samples):
    record, keys = hybrid.generate_keys(chain_id="local-hybrid", account_id="account:" + "ab" * 32)
    ed = SigningKey(keys.ed_seed)
    cpu = platform.processor()
    if platform.system() == "Darwin":
        cpu = subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
        ).strip()
    result = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"os": platform.platform(), "cpu": cpu, "python": platform.python_version()},
        "libraries": {name: importlib.metadata.version(name) for name in ("pqcrypto", "pynacl")},
        "scope": "single-process local microbenchmark; no network, JSON/hex encoding or state lookup",
        "sizes_bytes": {
            "ed25519_signature": 64,
            "ml_dsa_65_signature": 3309,
            "authorization_envelope": hybrid.AUTH_BYTES,
            "authorization_hex_characters": hybrid.AUTH_BYTES * 2,
            "registry_public_keys": 1984,
            "private_keys": 4064,
        },
        "key_generation": measure(
            lambda: hybrid.generate_keys(chain_id="local-hybrid", account_id=record.account_id), 50
        ),
        "payloads": {},
    }
    for size in (256, 4096, hybrid.MAX_PAYLOAD_BYTES):
        payload = b"x" * size
        auth = hybrid.sign(record, keys, payload)
        invalid_ed = auth[:27] + bytes(64) + auth[91:]
        # Mutate the challenge, preserving encoding/norm checks so verification
        # reaches the expensive ML-DSA equation rather than an early parse reject.
        invalid_pq = auth[:91] + bytes([auth[91] ^ 1]) + auth[92:]
        invalid_ed_equation = auth[:27] + ed.sign(b"wrong transcript").signature + auth[91:]
        classical = ed.sign(payload).signature
        assert hybrid.verify(record, payload, auth)
        assert not hybrid.verify(record, payload, invalid_ed)
        assert not hybrid.verify(record, payload, invalid_ed_equation)
        assert not hybrid.verify(record, payload, invalid_pq)
        result["payloads"][str(size)] = {
            "ed25519_sign_payload": measure(lambda: ed.sign(payload), samples),
            "ed25519_verify_payload": measure(
                lambda: ed.verify_key.verify(payload, classical), samples
            ),
            "hybrid_sign_including_self_check": measure(
                lambda: hybrid.sign(record, keys, payload), samples
            ),
            "hybrid_verify_valid": measure(lambda: hybrid.verify(record, payload, auth), samples),
            "hybrid_verify_invalid_ed": measure(
                lambda: hybrid.verify(record, payload, invalid_ed), samples
            ),
            "hybrid_verify_invalid_ed_equation": measure(
                lambda: hybrid.verify(record, payload, invalid_ed_equation), samples
            ),
            "hybrid_verify_invalid_pq": measure(
                lambda: hybrid.verify(record, payload, invalid_pq), samples
            ),
            "hybrid_reject_wrong_size": measure(
                lambda: hybrid.verify(record, payload, auth[:-1]), samples
            ),
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=500)
    args = parser.parse_args()
    if not 20 <= args.samples <= 100_000:
        parser.error("--samples must be between 20 and 100000")
    print(json.dumps(benchmark(args.samples), indent=2))
