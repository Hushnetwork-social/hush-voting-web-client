# Ubuntu Vault Conformance Handoff (v1) — Skeleton

**Adapter**: `ubuntu-secret-service-v1` | **Feature**: FEAT-005
**Status**: Skeleton — Phase 2. Final contract published at Phase 8 after full
native qualification evidence lands.
**Consumers**: FEAT-007 (create), FEAT-008 (recovery words), FEAT-009 (`.dat`
import), FEAT-010 (unlock/lifecycle), FEAT-011 (`.dat` export), future
operation-specific voting/messaging features.

## Closed seams (final at Phase 8)

Downstream features consume only the closed operation registry of the native
boundary. No generic signer, decryptor, private-key return, vault decrypt, or
filesystem command exists.

| Seam | Operation | Capability phase | Notes |
|---|---|---|---|
| FEAT-007 create | `generateIdentity` / `createFullIdentitySign` | provisioning / verificationOnly | Native CSPRNG + BIP-39 + compatible derivation; TS canonical bytes signed natively after parse/context validation |
| FEAT-008 restore | `restoreIdentity` | provisioning | One-shot bounded word submission; native validate/derive/provision atomically |
| FEAT-009 import | `importDatV1` | provisioning | Native capability-scoped `.dat` decrypt in memory; no generic filesystem |
| FEAT-010 lifecycle | `unlock` / `lock` / `changeDevicePassword` / `removeLocalUser` | per registry | Tombstone-backed removal; FEAT-003 throttling |
| FEAT-011 export | `exportDatV1` | authenticated | Ciphertext-only encrypted `.dat` output |
| Future voting/messaging | TBD | TBD | New operation-specific contract; never a generic signer |

## Replay obligations (final evidence at Phases 3–8)

- FEAT-001 identity corpus v1 replayed unchanged by native derivation/signing.
- FEAT-003 vault corpus v1 replayed unchanged by native crypto (Argon2id/
  HKDF-SHA-256/AES-256-GCM/AAD/canonical vectors).
- Cross-runtime conformance: TypeScript, Rust, and HushServerNode replay the
  same public compatibility vectors.

## Safety invariants (final evidence at Phases 3–8)

- WebView receives no private signing/encryption key, decrypted bundle,
  password root, record key, or generic signing capability.
- Mnemonic crosses only through the bounded creation/confirmation/reveal
  exception (≤60 s, dedicated component, immediate concealment on lifecycle).
- Device password crosses one bounded non-logged command and is zeroized.
- Every file/keyring mutation is crash-safe, generation-checked,
  self-verified, and non-destructive.
- One HushVoting process per Ubuntu user session owns the vault.
- OS-backed protection requires sequential Secret Service access and the
  HushVoting device password; password-only fallback exists only for confirmed
  provider absence with explicit informed acknowledgement.

## Evidence location

Final deterministic, digest-only reports land in `reports/` under this
directory during Phases 3–8; the manifest digest is recorded here at Phase 8.
