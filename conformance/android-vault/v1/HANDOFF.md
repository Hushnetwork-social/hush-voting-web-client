# Android Vault Conformance Handoff (v1) — FEAT-006

**Adapter**: `android-keystore` | **Feature**: FEAT-006
**Status**: Phase 2 — closed contracts, wrapper v1 canonical vectors, storage
model, and evidence schemas published. Final contract published at Phase 8
after native qualification evidence lands.
**Consumers**: FEAT-007 (create), FEAT-008 (recovery words), FEAT-009 (`.dat`
import), FEAT-010 (unlock/lifecycle), FEAT-011 (`.dat` export), future
operation-specific voting/messaging features.

## Closed seams (final at Phase 8)

Downstream features consume only the closed operation registry of the native
boundary. No generic signer, decryptor, private-key return, vault decrypt,
filesystem, path, URI, or intent command exists. The native dispatcher
validates epoch, operation version, capability phase, input bounds, public
identity binding, and user-confirmation context before any secret work.

| Seam | Operation (draft) | Capability phase | Notes |
|---|---|---|---|
| FEAT-007 create | `createProvision` (`createFullIdentitySign`) | provisioning / verificationOnly | TypeScript canonical bytes signed natively only after parse/context validation |
| FEAT-008 restore | `recoverWordsProvision` | provisioning | One-shot bounded word submission; native validate/derive/provision atomically |
| FEAT-009 import | `recoverFileProvision` (`importDatV1`) | provisioning | Native Storage Access Framework import; no broad storage permission; no URI/path to TypeScript |
| FEAT-010 unlock | `unlock` | locked | Android Keystore unwrap → device-password KDF → exact online both-key verification before `Authenticated` |
| FEAT-010 lock / password change / removal / reveal | `lock`, `changeDevicePassword`, `removeLocalUser`, `revealMnemonic` | any / authenticated | Tombstone-backed resumable removal; bounded reveal ≤60 s |
| FEAT-011 export | `exportEncryptedFile` (`exportDatV1`) | authenticated | Ciphertext-only SAF export; fresh-purpose gate |
| Future voting/messaging | TBD | TBD | New operation-specific contract; never a generic signer |

## Phase 2 published artifacts

- **Closed contract vocabulary** (Rust `src-tauri/src/android_vault/contracts/`,
  TS `src/lib/android-vault/contracts.ts`): capability status, security level,
  key state, 14 bridge operations, 15 result codes + recovery actions,
  lifecycle evidence, sensitive states, document operations, sanitized
  diagnostics.
- **Wrapper v1** (Rust `src-tauri/src/android_vault/wrapper.rs`, TS
  `src/lib/android-vault/wrapper.ts`): RFC 8785 canonical AAD, 1 MiB inner /
  1.5 MiB wrapper bounds, identity-free metadata, bounded fields.
- **Fixed storage model** (Rust `src-tauri/src/android_vault/storage/`):
  `<noBackupFilesDir>/vault/v1/` layout, journal CAS + key cardinality,
  throttle sidecar, removal tombstone, non-decrypting startup inspection.
- **Evidence schemas** (Rust `src-tauri/src/android_vault/evidence.rs`, TS
  `src/lib/android-vault/evidence.ts`): sanitized qualification reports +
  required-profile matrix (physical TEE/oldest/current API mandatory;
  StrongBox release-gated; emulator cannot claim hardware).
- **JSON schemas**: `schemas/` (wrapper metadata v1, result, evidence,
  vectors).
- **Public synthetic vectors**: `vectors/android-wrapper-vectors.json`
  (AW-001 pinned canonical bytes + SHA-256, replayed byte-identically by Rust
  and TypeScript).

## Replay obligations (evidence at Phases 3–8)

- FEAT-001 identity corpus v1 replayed unchanged by native derivation/signing.
- FEAT-003 vault corpus v1 replayed unchanged by native crypto (suite S,
  AAD A vectors) under the Android 64 MiB KDF cap.
- AW-001 (and later mutation vectors) replayed by Rust and TypeScript
  independently; physical Keystore tests assert properties/tamper behavior,
  never fixed ciphertext.

## Integrity

- Production keys and real wrapped vault ciphertext never enter reports or
  artifacts. The deterministic fake provider is compiled only in test
  variants and is provably absent from release builds (Phase 6 gate).
- This handoff is finalized at Phase 8; draft seams above are versioned and
  must not be consumed as final by downstream features before then.
