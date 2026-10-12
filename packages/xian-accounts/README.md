# xian-tech-accounts

Small shared account and signing primitives for the Xian workspace.

This package is intentionally narrow. It is the neutral home for reusable
Ed25519 and hybrid key, signing, and verification helpers that should not live in the
external SDK and should not be mixed into deterministic runtime types.

## API

- `generate_private_key()`
- `public_key_from_private_key(private_key)`
- `sign_message(private_key, message)`
- `verify_message(public_key, message, signature)`
- `is_valid_ed25519_key(key)`
- `Ed25519Account.generate()`
- `Ed25519Account.sign_message(message)`
- `Ed25519Account.verify_message(message, signature)`

`sign_msg(...)` and `verify_msg(...)` remain small aliases for wallet-style
callers in the wider Xian workspace.

## Hybrid Primitives

`xian_accounts.hybrid` supplies bounded public records, strict hex parsing,
domain-separated signing transcripts, and both-required Ed25519 + ML-DSA-65
signing/verification. Install `xian-tech-accounts[hybrid]` for the pinned ML-DSA
backend. Importing the ordinary account API does not load that backend.

These are low-level primitives, not a wallet or migration workflow. The node
must supply trusted registry state and canonical payload bytes, enforce nonces,
and commit transitions atomically. The production framing is deliberately
separate from the experiment. See
[the shared registry contract](../../../xian-meta/docs/ACCOUNT_REGISTRY_PROTOCOL.md).
Default networks disable enrollment. Wallet-level master derivation and
verified backup/recovery live in the Python and JavaScript SDKs.

## Local Experiments

[Hybrid account authorization](experiments/hybrid-auth/README.md) explores
Ed25519 + ML-DSA-65 with both signatures required. It has a separate environment
and test suite outside the published package and is not accepted by any network.

## Validation

```bash
cd packages/xian-accounts
uv run --extra hybrid --with pytest pytest -q
```
