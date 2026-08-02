# Vault v1 Downstream Handoff — FEAT-003

**Status**: immutable for corpus v1 | **Owner**: hush-voting-web-client (canonical corpus + reference validator)
**Corpus pin**:
- HushVoting revision: `4d31de2c15a37ccf23c5c94df076a7b687eb5ebd` (FEAT-001 identity corpus revision)
- Vault corpus manifest SHA-256: see `conformance/vault/versions.json` (registry pin) and `manifest.json`
- FEAT-001 identity manifest SHA-256: `f1bec7741de20efc3e488d0736ab61e745f3739032daaf50d955a83878d4f124`
- Contract version: `1.0.0` | Unicode version: `16.0.0`

This handoff is immutable evidence for downstream consumers. It is **not** a mutable
design document: any change to the vault contract requires a new corpus version and
new evidence (see Version & Migration Rules). No branch URL, live digest, or
unresolved placeholder appears here; every artifact path and command is concrete.

---

## 1. Consumer Matrix

Every downstream feature consumes FEAT-003 artifacts. Platform evidence is ADDITIVE:
a production adapter replays the unchanged corpus with its production implementation
and reports platform-specific results; it never edits the corpus or copies fixtures.

| Consumer | Consumes | Required vector families (replay) | Report generator | Ownership boundary |
|---|---|---|---|---|
| FEAT-004 (browser adapter) | corpus v1, schemas, typed results, session contracts | canonical (C/A), suite (S), password (P), core extension/lifecycle/migration/generation/session/typed-result (E/L/M/G/Q/T) | `hush-vault-ts-*` + platform report | Production IndexedDB/worker/WASM crypto; platform replay evidence |
| FEAT-005 (Ubuntu adapter) | same corpus v1 + native wrapper contract | all families; logical native-wrapper vectors | platform report | Secret Service/libsecret + reviewed password-only fallback; platform replay evidence |
| FEAT-006 (Android adapter) | same corpus v1 + wrapper + backup policy | all families | platform report | Android Keystore/secure-screen; platform replay evidence |
| FEAT-007 (identity creation flow) | `ValidatedCredentialBundle` admission (`integration/admission.ts`), atomic provisioning/replacement contracts | core lifecycle (L), generation (G), typed-result (T) | core report | Validated bundle creation inside secret-owning boundary |
| FEAT-008 (recovery flow) | same admission + replacement contracts | lifecycle (L), generation (G), typed-result (T) | core report | Validated recovery bundle creation inside secret-owning boundary |
| FEAT-009 (mnemonic recovery flow) | same admission + mnemonic-consistency evidence | lifecycle (L), generation (G), typed-result (T) | core report | Mnemonic revalidation inside secret-owning boundary |
| FEAT-010 (returning-user lifecycle) | lifecycle/session models, password change, removal, typed results | lifecycle (L), session (Q), typed-result (T) | core report | Production returning-user orchestration |
| FEAT-002 (existing auth app) | safe projections (`auth-adapter/projections.ts`), fail-closed composition (`integration/composition.ts`) | typed-result (T) mapping | n/a (unit regression) | UI/orchestration authority; thin adapters only |

### Vector family reference

| Family | File | IDs | Replay path |
|---|---|---|---|
| canonical bytes | `vectors/canonical-byte-vectors.json` | C-001…C-008 | RFC 8785 JCS |
| AAD | `vectors/aad-vectors.json` | A-001…A-006 | AAD assembly + JCS |
| suite | `vectors/suite-vectors.json` | S-001…S-006 | HKDF/AES-GCM/Argon2id + published KATs |
| password | `vectors/password-vectors.json` | P-001…P-007 | Unicode contract + policy hard-rejection |
| core | `vectors/core-vectors.json` | E-001…E-003, L-001…L-006, M-001…M-002, G-001…G-004, Q-001…Q-006, T-001…T-018 | lifecycle/session/generation/migration/extension/typed-result engines |

## 2. Corpus Usage (exact commands)

From a clean checkout of `hush-voting-web-client`:

```bash
npm ci
npm run lint && npm run typecheck && npm run test:unit
npm run vault:integrity            # manifest + schema validation
npm run vault:integrity:tests      # node:test corpus suites
npm run vault:conformance          # primary + isolated TypeScript/Node replay
npm run identity:conformance       # FEAT-001 regression (pinned)
npm run vault:ci:replay            # retained prior versions replay against digest pins
npm run build:web && npm run build:static
npm run auth:audit && npm run vault:production-exclusion
```

Expected reports (deterministic, digest-only, schema `schemas/report.schema.json`):

| Artifact | Path | Generator |
|---|---|---|
| Isolated report | `conformance/reports/vault-ts-isolated.json` | `hush-vault-ts-isolated` |
| Primary report | `conformance/reports/vault-ts-reference.json` | `hush-vault-ts-reference` |
| CI summary | `conformance/reports/vault-ci-summary.json` | FEAT-003 vault CI contract v1 |

## 3. Version & Migration Rules

- Four independent version axes: `envelopeFormatVersion`, `parameterSuiteVersion`,
  `recordSchemaVersion`, `platformWrapperVersion` (v1: 1/1/1/0).
- A new KDF, cipher, label scheme, field, operation kind, wrapper, or **network
  binding** requires a NEW corpus version (v2+), a reviewed migration path, and new
  corpus evidence. Network binding is NEVER a v1 configuration toggle.
- Unknown critical versions fail closed and preserve bytes; no best-effort downgrade.
- Retained prior versions replay permanently against their immutable manifest digest
  pins (`conformance/vault/versions.json`); a new version must not change a prior
  version's expected outcomes.

## 4. Pin Update Procedure

1. Record the new immutable FEAT-001 revision + identity manifest digest (40-hex / 64-hex).
2. Update `FEAT_001_PIN` in `src/lib/vault-core/integration/admission.ts` and
   `conformance/vault/v1/metadata.json` together, in one reviewed commit.
3. Extend `conformance/vault/versions.json` with the new corpus version and its
   manifest digest pin (never mutate a retained entry).
4. Re-run every gate in Section 2; publish new deterministic reports.

## 5. Core-Owned vs Downstream Evidence

- Core-owned: schemas, vectors, manifest pins, typed results, session/lifecycle
  reference models, isolated + primary reports, production-exclusion proof.
- Downstream-owned: production randomness/crypto execution, encrypted storage and
  transactions, OS key stores, secret-memory containers, worker/process isolation,
  platform resource reporting, and the platform replay report.
- FEAT-003 completion does NOT claim browser/Ubuntu/Android adapters pass; each
  adapter proves itself by replaying the unchanged corpus.

## 6. Stable Artifact Paths

| Path | Purpose |
|---|---|
| `conformance/vault/v1/` | canonical corpus (schemas, vectors, manifest, metadata) |
| `conformance/vault/versions.json` | retained version registry with digest pins |
| `src/lib/vault-core/contracts/` | closed contracts, typed results, ports |
| `src/lib/vault-core/canonical/` | primary JCS/AAD + reference suite ops |
| `src/lib/vault-core/password/` | Unicode/policy/throttle reference |
| `src/lib/vault-core/lifecycle/` + `session/` | deterministic lifecycle/session kernels |
| `src/lib/vault-core/auth-adapter/` | FEAT-002 safe projections |
| `src/lib/vault-core/integration/` | FEAT-001 pin admission + fail-closed composition |
| `src/lib/vault-core/conformance/` | primary derivation + isolated validator |
| `scripts/vault/` | CI orchestration, replay, self-test, production-exclusion |
