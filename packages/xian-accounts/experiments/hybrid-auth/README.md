# Hybrid account authorization experiment

Local Ed25519 + ML-DSA-65 signing, verification, adversarial tests, and cost
measurements. Both signatures are required. This project is outside the
published `xian_accounts` source tree and has its own pinned dependencies and
environment. It is not a supported transaction format or wallet API.

The shared byte contract and trust boundaries are in
[`xian-meta/docs/HYBRID_ACCOUNT_AUTH_EXPERIMENT.md`](../../../../../xian-meta/docs/HYBRID_ACCOUNT_AUTH_EXPERIMENT.md).
No production caller imports this experiment. The network implementation uses
`xian_accounts.hybrid` and `xian-abci` account-registry transitions, with a
different wire format. Wallet master derivation belongs to the SDKs.

## Run

From this directory, using Python 3.14 and `uv`:

```bash
uv sync --locked
uv run --locked pytest -q
# Run both live cross-implementation tests too (OpenSSL 3.5+ with ML-DSA):
XIAN_HYBRID_OPENSSL="$(command -v openssl)" uv run --locked pytest -q
uv run --locked python benchmark.py --samples 500
# Independent verifiers over the same public fixtures:
npm --prefix parity-js ci --ignore-scripts
npm --prefix parity-js test
cargo test --locked --manifest-path parity-rust/Cargo.toml
cargo clippy --locked --manifest-path parity-rust/Cargo.toml --all-targets -- -D warnings
```

Without `XIAN_HYBRID_OPENSSL`, only the two live OpenSSL checks skip; the frozen
OpenSSL vector always runs. An explicitly selected but incompatible OpenSSL
fails the tests. This suite is separate from the repository's default test path.

- `hybrid_auth.py`: bounded binary transcript, immutable trusted account record,
  independent random key generation, signing with self-check, both-required verification.
- `account_lifecycle.py`: authenticated enrollment, rotation, and recovery under
  a separate signing domain; an atomic in-memory registry for one trusted account.
- `test_account_lifecycle.py`: ownership and possession proofs, recovery policy,
  stale/concurrent requests, role/domain separation, failure atomicity, and
  randomized proof corruption.
- `state_codec.py`: bounded canonical binary decoder/encoder for public state.
- `sqlite_registry.py`: optional local persistence with atomic verification and
  updates, an enrollment cutoff that survives restarts, and exclusive creation.
- `test_sqlite_registry.py`: restart/replay, corrupt state, injected write
  failures, pre-commit process death, and competing independent processes.
- `parity_vectors.json`: 61 shared public conformance cases, including a frozen
  OpenSSL signature, lifecycle roles, malformed state, and a uint64 epoch above
  JavaScript's safe-number range. Signing-message SHA-256 values are fixture
  checks only; neither primitive signs an application prehash.
- `test_parity_vectors.py`, `parity-js/`, `parity-rust/`: independent Python,
  JavaScript, and Rust checks of the same verdicts and reconstructed messages.
  JavaScript uses Noble; Rust uses dalek and RustCrypto ML-DSA. Each language
  checks canonical state and its own crypto backend; passing these examples is
  not proof of universal parity or certification of the libraries.
- `generate_parity_fixtures.py`: deliberately regenerates those fixtures from
  ephemeral test keys. Run only when changing the contract, review the public
  output, then run all three verifiers. Never regenerate as part of normal tests.
- `test_hybrid_auth.py`: substitution, tampering, downgrade, epoch, scalar
  malleability, length/type limits, and 300 randomized examples per run.
- `test_openssl_interop.py`: ML-DSA checks in both directions against OpenSSL,
  including an independently assembled transcript and changed-message rejection.
- `openssl_vector.json`: public inputs/signatures produced with OpenSSL 3.6.5
  for ML-DSA and PyNaCl for Ed25519; no private keys. A regression fixture, not a
  NIST certification vector. Regenerate only deliberately with `openssl_vector`
  in the test module, a temporary directory, and a reviewed OpenSSL executable.
- `benchmark.py`: sizes, key generation, signing, valid verification, malformed
  input rejection, and expensive invalid-signature verification paths.
- `benchmark-local.json`: recorded local measurement, not a performance target.
- `uv.lock`: exact experiment dependencies and distribution hashes. The pinned
  `pqcrypto==0.4.0` wheel uses PQClean ML-DSA-65; `pynacl==1.6.0` uses libsodium.

## Local measurements

Recorded October 11, 2026 on Apple M1 / macOS 27.0.1 / Python 3.14.8, with
500 samples per signature operation, 50 for key generation, and 10 warmups each.
Values are medians in milliseconds; the JSON includes p95. Synthetic payloads
exercise the byte primitive only. These measurements predate the lifecycle
model and do not include lifecycle transitions.

| Payload bytes | Ed25519 verify | Hybrid verify | Hybrid sign with self-check | Valid Ed25519, invalid ML-DSA |
| ---: | ---: | ---: | ---: | ---: |
| 256 | 0.144 | 0.279 | 0.760 | 0.276 |
| 4,096 | 0.196 | 0.333 | 0.929 | 0.333 |
| 131,072 | 1.605 | 2.219 | 6.122 | 2.219 |

The invalid ML-DSA case mutates the challenge while preserving structural
checks. Its cost approaches valid verification; an early malformed-input
benchmark alone would understate the DoS budget. These timings exclude registry
lookup, JSON/hex encoding, network transport, execution, and concurrent load.
They do not estimate production throughput or mobile performance. The classical
baseline verifies the payload alone; hybrid verification includes its framing
and both public keys as required by the experimental contract.

The detached authorization is **3,400 bytes**, including 27 bytes of framing
and 3,373 signature bytes, versus a bare 64-byte Ed25519 signature. Hex encoding
that authorization takes 6,800 ASCII bytes, before any enclosing transaction
encoding. Public keys occupy 1,984 bytes in a trusted record and are not repeated
in the authorization. The private key material is 4,064 bytes before encryption
and storage framing. These sizes describe the experiment, not the network
transaction envelope.

## Lifecycle rehearsal

The lifecycle model starts from an authenticated legacy Ed25519 account mapping.
Enrollment is closed by default; `LocalRegistry(..., enrollment_open=True)`
explicitly opens it for a local rehearsal. Enrollment requires the old owner's
signature and separate possession proofs for the new active and recovery pairs.
The registry can close enrollment permanently for that instance.

`prepare_transition(...)` constructs test requests; `LocalRegistry.apply(...)`
verifies and atomically installs them. `apply_transition(...)` is the pure
version for adapters: returning a replacement does not itself consume
the old state. All three operations are covered by the normal experiment suite.

Rotation requires the current active hybrid pair. Recovery requires the separate
current recovery hybrid pair. Both require possession of both new pairs,
preserve the account identity, advance the epoch, and replace all four keys.
No old key may be carried over from either current role. Legacy signatures and
single-primitive proofs cannot authorize an enrolled account. Distinct signed
operation and role bytes prevent reusing a proof for another purpose.

Recovery is immediate, with no delay or guardian veto. Its purpose is recovery
from loss of active secrets; it does not protect funds from an attacker holding
both active secrets, who can transact and rotate recovery authority. Production
wallets must generate and retain recovery secrets offline. The rehearsal signer
holds all supplied secrets in one process and is not a production wallet flow.
There is no password/admin reset if both usable authorization pairs are lost.

The two active/recovery public-key pairs use 3,968 raw bytes. Enrollment proofs
use 6,864 bytes (legacy authority plus two hybrid proofs); rotation/recovery
proofs use 10,200 bytes (three hybrid proofs), before candidate-state and wire
encoding overhead. These are distinct from ordinary transaction authorization.

## Durable local rehearsal

`SQLiteRegistry.create(path, trusted_state, enrollment_open=False)` creates a
new registry exclusively; it fails if the path exists. `SQLiteRegistry(path)`
opens existing state and cannot reinitialize it. Use the same `apply(request)`,
`state`, and `close_enrollment()` operations as the in-memory registry. The
`enrollment_open` read-only property reports the persisted gate. Store only
generated test accounts; this adapter is not wired to Xian's state database.

Each write obtains a SQLite write transaction, re-reads the current state and
gate, verifies, and commits the replacement atomically. This works across
separate processes and fresh handles without caching an old epoch in memory.
Failed checks/writes roll back; committed state and gate closure survive
reopening. Schema version and bounded canonical bytes are checked on read.
Private keys are never stored. Rollback journaling and `synchronous=FULL` are
used; tests include process termination after SQL UPDATE and before COMMIT.

The database and parent directory are trusted. Copying an older valid database
over the current file can roll back epochs and the gate; the adapter cannot
detect that. Production must use canonical chain state, restore/reorg rules,
and consensus policy. Tests do not simulate filesystem or hardware power-loss
faults. This is a persistence rehearsal, not a production migration.

## Experiment boundaries

`AccountRecord` is trusted input. This experiment does not parse canonical
Xian payloads, enforce chain nonces or connect to chain state. Its optional
SQLite adapter is a local persistence model only. The network implementation
and shared registry contract are documented in the [package README](../../README.md).

This is not an audited protocol or a FIPS-validated module. Python immutable
secret bytes are not securely erased. It supplies no wallet backup or hardware
signer integration and tracks no all-time key history. Use generated test keys.
