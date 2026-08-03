# Android Vault Conformance Handoff (v1) — FEAT-006

**Adapter**: `android-keystore` | **Feature**: FEAT-006
**Status**: Phase 6 — production composition integrated; contract sealed for
FEAT-007–011 consumption. Final qualification evidence (physical TEE/API,
APK/AAB, security review) is published at Phase 8 and is release-blocking.
**Consumers**: FEAT-007 (create), FEAT-008 (recovery words), FEAT-009 (`.dat`
import), FEAT-010 (unlock/lifecycle), FEAT-011 (`.dat` export).

## Closed seams (sealed)

Downstream features consume only the closed operation registry of the native
boundary. No generic signer, decryptor, private-key return, vault decrypt,
filesystem, path, URI, or intent command exists. The native dispatcher
validates epoch, operation version, capability phase, input bounds, public
identity binding, and user-confirmation context before any secret work.

| Seam | Operation | Capability phase | Consumer |
|---|---|---|---|
| FEAT-007 create | `createProvision` (`createFullIdentitySign`) | provisioning / verificationOnly | FEAT-007 |
| FEAT-008 restore | `recoverWordsProvision` | provisioning | FEAT-008 |
| FEAT-009 import | `recoverFileProvision` (`importDatV1`) | provisioning | FEAT-009 |
| FEAT-010 unlock | `unlock` | locked | FEAT-010 |
| FEAT-010 lock / password change / removal / reveal | `lock`, `changeDevicePassword`, `removeLocalUser`, `revealMnemonic` | any / authenticated | FEAT-010 |
| FEAT-011 export | `exportEncryptedFile` (`exportDatV1`) | authenticated | FEAT-011 |

Future voting/messaging operations require a separately reviewed,
operation-specific contract; no generic signer/decryptor is ever reused.

## Versioned pins (immutable)

| Pin | Value |
|---|---|
| Android wrapper version | `1` (independent `platformWrapperVersion`) |
| Adapter ID | `android-keystore` |
| WebView↔Rust IPC protocol | `1.0` (shared, platform-neutral) |
| Rust↔Kotlin mobile-plugin protocol | `1.0` |
| Production application ID | `com.hushvoting.client` (variants `.debug`/`.test`/`.internal`) |
| minSdk / targetSdk / compileSdk | 28 / 36 / 36 |
| Inner envelope max / wrapper max | 1 MiB / 1.5 MiB |
| Identity corpus manifest | `f1bec774…d4f124` (unchanged, replayed) |
| Vault corpus manifest | `e8dfdfa4…582e5` (unchanged, replayed) |
| AW-001 canonical AAD sha256 | `706f5a9dcf9c8ccc4484e3c5099835bae1894d204886165f65dafe94059edd76` |

## Published artifacts (Phase 2–6)

- **Contracts** (Rust `src-tauri/src/android_vault/contracts/`, TS
  `src/lib/android-vault/contracts.ts`): capability, security level, key
  state, 14 bridge operations, 17 result codes + recovery actions, lifecycle
  evidence, sensitive states, document operations, sanitized diagnostics.
- **Wrapper v1** (Rust/TS `wrapper.ts`): RFC 8785 canonical AAD, bounds,
  identity-free metadata.
- **Storage model** (Rust `storage/`): fixed `<noBackupFilesDir>/vault/v1/`
  layout, journal CAS + key cardinality, throttle sidecar, tombstone,
  non-decrypting startup inspection.
- **Keystore policy** (Rust `keystore/`, Kotlin `src-tauri/mobile-plugin/`):
  exact AES-256-GCM policy, StrongBox/TEE selection, capability qualification.
- **Session/bridge/lifecycle** (Rust `session/`, `bridge/`, `navigation/`,
  `platform_controls/`): opaque epochs, handshake-gated dispatch, timing,
  Back authority, shielding/clipboard/SAF policy.
- **Evidence schemas** (Rust/TS `evidence.*`): sanitized qualification
  reports + mandatory profile matrix (physical TEE/oldest/current API,
  package, accessibility, security; StrongBox release-gated).
- **JSON schemas**: `schemas/` (wrapper metadata v1, result, evidence,
  vectors).
- **Vectors**: `vectors/android-wrapper-vectors.json` (AW-001) replayed
  byte-identically by Rust and TypeScript.

## Consumer obligations

- FEAT-007–011 must consume ONLY the sealed seams above; no generic
  signer/decryptor/file/URI/private-key capability exists.
- Consumers must replay the unchanged FEAT-001/FEAT-003 corpora and AW-001 in
  their own flows (additive platform reports; never edited fixtures).
- StrongBox support claims are release-disabled until a qualified StrongBox
  physical protocol passes (Phase 7/8); consumers must not assume StrongBox.

## Integrity

- Production keys and real wrapped vault ciphertext never enter reports or
  artifacts; the deterministic fake provider is compiled only in test
  variants and is provably absent from release builds (Phase 6 gate).
- This handoff is validated by `android-vault:ci` (handoff-integrity stage)
  and finalized with qualification evidence at Phase 8.
