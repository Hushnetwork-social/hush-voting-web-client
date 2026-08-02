# HushVault Rust Reference Runner

Non-production independent validator for the FEAT-003 `conformance/vault/v1/` corpus.
It is a separate Cargo package and is never linked into the Tauri application, browser
bundle, or platform adapter.

```bash
cargo run --locked --manifest-path tools/vault-reference-runner/Cargo.toml -- \
  --corpus conformance/vault/v1 --check \
  --report conformance/reports/vault-rust-reference.json
```

Optional `--expected-manifest-sha256 <64-lowercase-hex>` enforces an immutable consumer
pin. Exit categories are stable: `0` pass, `1` vector/integrity mismatch, `2` invalid
arguments/corpus, `3` contained internal failure. Reports contain identifiers, typed
codes, and SHA-256 digests only.

Quality gates (run serially):

```bash
cargo fmt --manifest-path tools/vault-reference-runner/Cargo.toml --check
cargo clippy --locked --manifest-path tools/vault-reference-runner/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path tools/vault-reference-runner/Cargo.toml
```

Generate the independent TypeScript report with `npm run vault:conformance:report`, then
compare both reports using `npm run vault:reports:compare`. Production separation is
checked with `npm run vault:production-exclusion`.
