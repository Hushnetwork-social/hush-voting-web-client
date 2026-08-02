# Vault v1 Deterministic Vectors

All values are public synthetic test inputs declared by `../metadata.json` and confined
to this allowlisted corpus path.

| File | Families |
|---|---|
| `canonical-byte-vectors.json` | RFC 8785 object/string/UTF-16-key/number vectors |
| `aad-vectors.json` | Full public logical AAD inputs and expected canonical digests |
| `suite-vectors.json` | Argon2id, HKDF-SHA-256, and AES-256-GCM known answers |
| `password-vectors.json` | NFC, grapheme/byte bounds, common and identity-derived policy |
| `core-vectors.json` | Extensions, lifecycle, migration, generations, sessions, typed results |

`src/lib/vault-core/conformance/vectors.test.ts` derives every file deterministically.
The separately compiled Rust runner independently replays the same inputs and emits only
identifier/code/digest diagnostics. Production adapters in FEAT-004/005/006 replay these
unchanged logical vectors and add platform-specific evidence; they do not copy or edit the
corpus.
