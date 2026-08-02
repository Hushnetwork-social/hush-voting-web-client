# Browser Vault v1 Downstream Handoff — FEAT-004

**Status**: immutable for browser-vault contract v1 | **Owner**: hush-voting-web-client (production browser adapter)
**Corpus pin**: FEAT-003 vault corpus v1.0.0 manifest SHA-256 `e8dfdfa49b9e33cfc8a47b1266c5a14cb978c4be28f21d87cc2f034d435582e5` (unchanged, never edited by FEAT-004)
**Protocol version**: 1 (closed page/worker protocol; see `src/lib/browser-vault/contracts/protocol.ts`)
**Contract version**: `1.0.0`

This handoff is immutable evidence for downstream consumers. It is **not** a mutable design document: any change to the browser protocol, capability surface, operation registry, or storage layout requires a new contract version and new evidence.

---

## 1. Consumer Matrix

Every downstream feature consumes FEAT-004 through one closed operation seam (see `src/lib/browser-vault/contracts/operations.ts`). Platform evidence is ADDITIVE; the FEAT-003 corpus is never edited.

| Consumer | Consumes | Operation seam | Result surface |
|---|---|---|---|
| FEAT-007 (identity creation flow) | Closed key-generation/validation/provisioning inside the authority | `createProvision` | typed-outcome (safe review fields + opaque operation id) |
| FEAT-008 (recovery words restore) | Closed mnemonic validation/provisioning | `recoverWordsProvision` | typed-outcome |
| FEAT-009 (`.dat` restore) | Closed encrypted-file decryption/validation/provisioning | `recoverFileProvision` | typed-outcome |
| FEAT-010 (returning-user lifecycle) | Unlock/verification, password change, Lock, removal | `unlock`, `changePassword`, `lock`, `removeLocalUser`, `verifyOnline` | typed-outcome |
| FEAT-011 (portable export) | Separately approved encrypted `.dat` v1 output only | `exportEncryptedFile` | digest-only-report |

**Generic secret access is structurally impossible**: no operation returns private keys, arbitrary signing/decryption, serialized bundles, or plaintext exports.

## 2. Authority Order and Capability Preflight

- Registration is Web-only after fail-closed capability preflight (`src/lib/browser-vault/integration/composition.ts`).
- Authority order: SharedWorker → exclusive Web Lock → generation-CAS 15 s IndexedDB lease → blocked.
- Fresh-password capabilities are channel/purpose/epoch-bound, one-use, ≤ 60 s.
- Online identity verification is worker-owned with an endpoint allowlist; a page Boolean can never promote authentication.

## 3. Storage Model (fixed, immutable for v1)

- Database `hushvoting-vault`, schema version 1.
- Stores: `vaultSlots` (fixed keys `slot-a`, `slot-b`), `vaultJournal` (fixed key `current`), `operationalSidecars` (allowlisted keys only).
- No identity-bearing database/store/key/index.

## 4. Evidence Reports

Browser-adapter reports are digest-only (`src/lib/browser-vault/contracts/reports.ts`): versions, corpus pins, browser family/major, coarse timing buckets, adapter digest. No identity, device, session, URL, exact timestamp, or credential value.

## 5. Verification Commands

From a clean checkout of `hush-voting-web-client`:

```bash
npm ci
npm run browser-vault:ci            # unified adapter gate (lint/typecheck/unit/vault-ci/exclusion/audit/dependency/browser/deployment/handoff)
npm run browser-vault:ci:selftest   # failure-mode self-tests (corpus pin tamper, reference import)
npm run lint && npm run typecheck && npm run test:unit
```

Expected summary: `conformance/reports/browser-vault-ci-summary.json` (revision + corpus digest + per-stage pass; no secret values).
