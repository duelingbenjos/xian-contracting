# Rust conformance verifier

Independent local implementation of the experimental binary state, transcript,
and signature rules. This unpublished crate is not a node or VM dependency.

`src/lib.rs` uses pinned dalek Ed25519 and RustCrypto ML-DSA libraries. Tests
consume the shared `../parity_vectors.json`, compare verdicts, and check hashes
of independently reconstructed messages. `Cargo.lock` pins transitive inputs.

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

See [the experiment README](../README.md) for the Python/JavaScript checks and
experiment boundaries. This is a fixture verifier, not a consensus module.
