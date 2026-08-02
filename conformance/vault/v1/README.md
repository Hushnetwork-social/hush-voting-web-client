# HushVault Conformance Corpus — v1

Canonical, platform-neutral corpus for **FEAT-003 Credential Vault and Session Core**.

One editable owner. Consumers (FEAT-004/005/006 production adapters) replay an exact pinned
revision and manifest digest; no editable fixture copy exists in platform repositories.

## Layout

```text
conformance/vault/v1/
├── README.md
├── metadata.json            corpus metadata: pins, limits, public-test-credential declaration
├── manifest.json            generated: sorted SHA-256 manifest (check mode supported)
├── schemas/                 JSON Schema draft 2020-12 (closed, bounded)
│   ├── envelope.schema.json logical inner envelope (4 version axes, records, extensions)
│   ├── record.schema.json   encrypted record slot (ordinary / mnemonic)
│   ├── preview.schema.json  cleartext locked preview (identity-only)
│   ├── extension.schema.json bounded namespaced extension container
│   ├── suite.schema.json    closed parameter suite v1 (Argon2id / HKDF-SHA-256 / AES-256-GCM)
│   ├── sidecar.schema.json  non-secret operational sidecar
│   ├── metadata.schema.json corpus metadata schema
│   ├── manifest.schema.json corpus manifest schema
│   └── report.schema.json   secret-safe conformance report schema (TS + Rust)
├── scripts/                 deterministic tooling (manifest generation, validation)
└── tests/                   node:test integrity / exclusion / boundary tests
```

## v1 Contract Highlights

- **Four independent version axes**: `envelopeFormatVersion`, `parameterSuiteVersion`,
  `recordSchemaVersion`, `platformWrapperVersion` (0 = no wrapper in the logical envelope).
- **No network identity in v1** (Deep-Dive override): no canonical network field, no
  `NetworkMismatch` behavior, no network-bound AAD. Endpoint/server context is external
  application display configuration; a future versioned contract introduces binding.
- **Locked preview is identity-only**: normalized alias (1–64), first 8 and last 6
  signing-address characters, lifecycle status, format versions.
- **Byte strings are unpadded base64url**; integers for versions and numeric parameters;
  strict duplicate-key rejection and unknown-root-property rejection at parse time.
- **Closed suite**: suite v1 fixes Argon2id (19 MiB / 2 iterations / p=1, ≥16-byte salt,
  ≥32-byte output, 500–1,000 ms calibration, 1,500 ms hard limit, 64 MiB browser/Android
  cap, 256 MiB Ubuntu cap), HKDF-SHA-256 labels `hush/vault/v1/credential-kek` and
  `hush/vault/v1/mnemonic-kek`, AES-256-GCM (32-byte keys, fresh 96-bit nonces).
- **Limits**: envelope ≤1 MiB, authenticated metadata ≤64 KiB, record ≤512 KiB,
  extension depth ≤4, collections ≤64, nesting ≤16.
- **Extension mechanism**: closed root/record schemas; bounded namespaced `extensions`
  plus `criticalExtensions`. Unknown critical → fail closed and preserve bytes;
  unknown non-critical → preserve canonically.

## Public Test Credentials

All synthetic mnemonic/private-key values are **declared public test credentials** and are
confined to allowlisted corpus paths (`schemas`, `vectors`, `tests`, `scripts`). They must
never appear in production artifacts; `scripts/vault/` scans enforce this.

## Commands

```bash
npm run vault:manifest        # regenerate manifest.json (deterministic)
npm run vault:integrity       # manifest check + schema validation (CI gate)
npm run vault:integrity:tests # node:test manifest + production-exclusion tests
npm run vault:conformance     # primary + isolated TypeScript conformance (Phase 5)
npm run vault:conformance:isolated # isolated validator only
npm run vault:production-exclusion  # import-graph + selector + artifact scans
npm run vault:test:adversarial# property/fuzz/fault/concurrency (introduced Phase 7)
```

## Phase 5 — Isolated TypeScript/Node Validation

- `src/lib/vault-core/conformance/isolated/` holds independently written replay modules
  (RFC 8785 JCS, AAD assembly, Unicode contract, policy hard-rejection, core
  lifecycle/session/generation/migration/extension/typed-result engines). They never
  import the primary implementation helpers being checked.
- `src/lib/vault-core/conformance/isolated-validator.ts` verifies the manifest digest
  before replaying every vector family and emits a deterministic secret-safe report
  (`generator: hush-vault-ts-isolated`) per `schemas/report.schema.json`.
- The manifest covers `schemas/`, `metadata.json`, and every `vectors/` file so
  downstream adapters (FEAT-004/005/006) replay an exact pinned revision.
- No Rust, Cargo, compiled sidecar binary, or standalone validator project belongs to
  this feature (Deep-Dive decision); the report generator enum is
  `hush-vault-ts-reference` | `hush-vault-ts-isolated`.

## Pinned Upstream (FEAT-001)

- Revision: `4d31de2c15a37ccf23c5c94df076a7b687eb5ebd`
- Identity manifest SHA-256: `f1bec7741de20efc3e488d0736ab61e745f3739032daaf50d955a83878d4f124`
- Contract version: `1.0.0`

## Residual Limitations (documented, not hidden)

- Complete browser-storage rollback cannot be detected without an external trusted monotonic
  counter; HushServerNode does not track local vault generations.
- Sidecar values are untrusted: malformed/implausible cooldown data resets safely rather than
  creating denial of service.
- Physical zeroization/secure erasure guarantees remain platform-limited.
