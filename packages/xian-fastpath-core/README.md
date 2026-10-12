# xian-tech-fastpath-core

Optional Rust fast paths for:

- transaction wire decode and static validation
- payload extraction from decoded transaction JSON

This package is optional. Nodes use the Python static-validation path when it
is absent; the compiler and execution VM have their own native requirements.

Integration note:

- `xian-abci` uses the combined decode + static validation fast path.
- `xian-abci` also uses the native payload extractor from Python decode paths.
- Stateful hybrid verification uses the node account registry; this package
  does not select authority or update account records.

## API

- `decode_and_validate_transaction_static(raw, chain_id)`
- `extract_payload_string(json_str)`
- `NativeFastpathValidationError`

## Validation

```bash
cargo check --manifest-path packages/xian-fastpath-core/Cargo.toml
```
