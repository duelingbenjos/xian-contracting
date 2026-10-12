# JavaScript conformance verifier

Independent local implementation of the experimental binary state, transcript,
and signature rules. It is private and is not imported by `xian-js` or wallets.

`verifier.mjs` uses pinned Noble libraries, explicit prime-order Ed25519 checks,
and `BigInt` for uint64 counters. `verifier.test.mjs` reads the shared public
`../parity_vectors.json` and checks verdicts and signing-message hashes.

```bash
npm ci --ignore-scripts
npm test
```

See [the experiment README](../README.md) for scope, trust boundaries, and the
Python/Rust checks that must pass alongside this suite. This is a fixture
verifier, not a production transaction parser or supported SDK API.
