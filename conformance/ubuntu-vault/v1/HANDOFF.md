# Ubuntu Vault Conformance Handoff (v1)

**Adapter**: `ubuntu-secret-service-v1` | **Feature**: FEAT-005
**Status**: Phase 6 — production composition integrated; final contract
published at Phase 8 after full native qualification evidence lands.
**Consumers**: FEAT-007 (create), FEAT-008 (recovery words), FEAT-009 (`.dat`
import), FEAT-010 (unlock/lifecycle), FEAT-011 (`.dat` export), future
operation-specific voting/messaging features.

## Closed seams (final at Phase 8)

Downstream features consume only the closed operation registry of the native
boundary. No generic signer, decryptor, private-key return, vault decrypt, or
filesystem command exists. The native dispatcher validates epoch, operation
version, capability phase, input bounds, public identity binding, and
user-confirmation context before any secret work.

| Seam | Operation | Capability phase | Notes |
|---|---|---|---|
| FEAT-007 create | `createProvision` (`generateIdentity` / `createFullIdentitySign`) | provisioning / verificationOnly | Native CSPRNG + BIP-39 + compatible derivation; TypeScript canonical bytes signed natively only after parse/context validation (k256 RFC 6979, compact 64-byte r\|\|s) |
| FEAT-008 restore | `recoverWordsProvision` (`restoreIdentity`) | provisioning | One-shot bounded word submission; native validate/derive/provision atomically |
| FEAT-009 import | `recoverFileProvision` (`importDatV1`) | provisioning | Native capability-scoped `.dat` decrypt in memory; no generic filesystem |
| FEAT-010 unlock | `unlock` | locked | Sequential OS unwrap → device-password KDF → exact online both-key verification (`verifyOnline`) before `Authenticated` |
| FEAT-010 lock | `lock` | any | Synchronous epoch revocation; every handle invalidated |
| FEAT-010 password change | `changeDevicePassword` | authenticated | Two-slot atomic commit under the bounded rollback rule |
| FEAT-010 removal | `removeLocalUser` | authenticated | Tombstone-backed, resumable, verified-absence-gated; no device password required |
| FEAT-010 reveal | `revealMnemonic` | authenticated | Bounded transient delivery; ≤60 s or earlier lifecycle concealment |
| FEAT-010 online verify | `verifyOnline` | verificationOnly | Exact both-key equality only; 10 s bound; WebView cannot submit `verified` |
| FEAT-011 export | `exportEncryptedFile` (`exportDatV1`) | authenticated | Ciphertext-only encrypted `.dat` output; no plaintext export |
| Future voting/messaging | TBD | TBD | New operation-specific contract; never a generic signer |

## Replay obligations (evidence at Phases 3–8)

- FEAT-001 identity corpus v1 replayed unchanged by native derivation/signing
  (canonical-byte CB vectors + signature S-vectors cross-verified; S-001..S-009
  green in Phase 4).
- FEAT-003 vault corpus v1 replayed unchanged by native crypto
  (S-001..S-006 + A-001/A-002 green in Phase 3).
- Cross-runtime conformance: TypeScript, Rust, and HushServerNode replay the
  same public compatibility vectors.

## Safety invariants (evidence at Phases 3–8)

- WebView receives no private signing/encryption key, decrypted bundle,
  password root, record key, or generic signing capability.
- Mnemonic crosses only through the bounded creation/confirmation/reveal
  exception (≤60 s, dedicated component, immediate concealment on lifecycle).
- Device password crosses one bounded non-logged command and is zeroized.
- Every file/keyring mutation is crash-safe, generation-checked,
  self-verified, and non-destructive (Phase 3 fault matrix green).
- One HushVoting process per Ubuntu user session owns the vault
  (single-instance plugin + fd-lock defense in depth, Phase 4).
- OS-backed protection requires sequential Secret Service access and the
  HushVoting device password; password-only fallback exists only for confirmed
  provider absence with explicit informed acknowledgement.
- Endpoints are a closed vocabulary: production TLS-only
  (`https://api.hushnetwork.social`); cleartext/test fixtures composition-gated.
- Protocol artifacts are digest-pinned (build-time SHA-256 gate); the gRPC
  client is generated, never edited.

## Evidence location

Deterministic, digest-only reports land in `reports/` under this directory:
- `ubuntu-vault-ci-summary.json` — unified gate results (Phase 6+).
- `release-evidence.json` — package/protocol/corpus/dependency digests (Phase 6+).
- Phase 7 qualification/security/package/a11y/performance reports append here.
- The manifest digest is recorded here at Phase 8.
