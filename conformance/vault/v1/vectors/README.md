# Vault v1 Vectors (Phase 5)

Deterministic public-synthetic vectors, replayable by every adapter. Each family is
derived by the primary implementation path (`src/lib/vault-core/conformance/vectors.test.ts`)
and replayed by the isolated TypeScript/Node validator
(`src/lib/vault-core/conformance/isolated-validator.ts`) through an independent
calculation path. Both must agree; divergence fails `npm run vault:conformance`.

## Families

| File | IDs | Replay |
|---|---|---|
| `canonical-byte-vectors.json` | C-001…C-008 | Independent RFC 8785 JCS reproduces pinned canonical bytes + SHA-256 |
| `aad-vectors.json` | A-001…A-006 | Independent AAD assembly (input → metadata → JCS bytes → SHA-256); S-003 AES-GCM binds to A-001 bytes |
| `suite-vectors.json` | S-001…S-006 | HKDF labels (S-001/S-002), vault-specific AES-256-GCM record wrap (S-003), suite-parameter Argon2id (S-004), published RFC 9106 §5.3 Argon2id KAT (S-005), published RFC 5869 §2.2 Test Case 1 HKDF KAT (S-006) |
| `password-vectors.json` | P-001…P-007 | Unicode NFC/grapheme/UTF-8 contract and deterministic policy hard-rejection |
| `core-vectors.json` | E-001…E-003, L-001…L-006, M-001…M-002, G-001…G-004, Q-001…Q-006, T-001…T-018 | Independent extension/lifecycle/migration/generation/session/typed-result replay engines |

## Rules

- All values are declared public test credentials (see `../metadata.json`
  `publicTestCredentials`) and are confined to this allowlisted path.
- Published KAT values (RFC 5869, RFC 9106, NIST GCM AES-256) are pinned verbatim;
  the derivation asserts them before writing.
- Every file is manifest-tracked (`manifest.json`) so adapters replay an exact pinned
  revision; the isolated validator verifies the manifest digest before replay.
- No editable fixture copy exists outside this corpus.
