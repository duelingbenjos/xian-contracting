# Safety Invariants

This file records the runtime properties that must hold before a
`xian-contracting` release is considered safe.

## Contract Execution

- Failed execution must not persist writes, events, or partially mutated nested
  state.
- Contract Python globals must not leak across transactions.
- Prefix scans and collection helpers must not hand out live mutable references
  into stored state.
- Submission metadata and validator-derived VM IR must stay deterministic for
  the same source input.

## Signature Verification

- Native admission and VM `crypto.verify` reject small-order public keys and
  signature points using strict Ed25519 verification.
- Python admission and the native fast path agree on adversarial signatures,
  including identity-point forgeries and noncanonical scalars. Run
  `xian-abci/tests/unit/test_native_fastpath_parity.py` with the rebuilt native
  extension; a skipped optional-native test is not evidence of parity.
- Signature-policy changes require a coordinated validator release. SDK
  verification must apply compatible rejection rules.

## Metering

- Metering must never under-charge relative to the native-instruction tracer
  audit baseline.
- Transaction-byte and host-write costs must remain deterministic across
  validators.
- Native helper paths may over-charge conservatively, but they must not
  under-meter.

## VM Conformance

- `xian_vm_v1` execution must match the local harness conformance oracle for
  result, writes, events, and failure mode across the curated matrix.
- Stateful contract sequences must preserve the same committed state across the
  oracle and VM checks, including rollback after deliberate post-write failure.
- Native deployment must reject client-supplied IR artifacts and derive VM IR
  from submitted source before staging contract writes.

## Release Gate

Use `./scripts/validate-release.sh` before release. The gate covers:

- lint and format checks
- default pytest coverage
- Rust package checks for the zk package and VM core
- zk Python tests
- optional-native zk / VM conformance tests
- stateful local-harness-vs-VM fuzz coverage

The existing security tests in `tests/security/` and the VM conformance tests in
`tests/integration/` are the enforcement surface for these invariants.
