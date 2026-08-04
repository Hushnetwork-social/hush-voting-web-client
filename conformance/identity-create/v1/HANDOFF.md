# FEAT-007 Identity-Create Downstream Handoff (v1)

**Sealed handoff for**: FEAT-008 (Recovery Words Restore), FEAT-009 (Credential File Restore), FEAT-010 (Returning User Unlock + Lifecycle), FEAT-011 (Portable `.dat` Export)
**Version**: 1
**Digest**: computed at release (Phase 7 immutable pin report)
**Date**: 2026-08-04

## Contract Invariant

FEAT-007 does NOT create a second identity service, a generic signer, a new envelope format, or any new secret surface. It consumes the sealed FEAT-001–006 seams and publishes the following reusable artifacts. Downstream features must consume these contracts; they must NOT re-derive validation, normalization, or lifecycle policy.

## Reusable Artifacts

| Artifact | Location | Consumers |
|---|---|---|
| Creation/lifecycle contracts, safe review projections, secret-boundary guard | `src/lib/identity-creation/contracts.ts` | FEAT-008/009/010 |
| Alias/visibility validation + canonical FullIdentity transaction description | `src/lib/identity-creation/profile.ts` | FEAT-008/009 |
| Wire normalizers (closed GetIdentity/SubmitSignedTransaction outcomes) | `src/lib/identity-creation/wire.ts` | FEAT-008/009/010 |
| Generation/recovery policy (challenge, reveal, conceal) | `src/lib/identity-creation/authority.ts` | FEAT-008 |
| Provisioning capability + promotion + cancellation/quarantine policy | `src/lib/identity-creation/provision.ts` | FEAT-010/011 |
| Lookup-first reconciliation, polling, correction, reset policy | `src/lib/identity-creation/reconciliation.ts` | FEAT-010 |
| View-state mapping + create-user actor registration contract | `src/lib/identity-creation/presentation.ts` | FEAT-008/009 |
| Root-only navigation control (history, Back, vault-inspection, events) | `src/lib/identity-creation/navigation-control.ts` | FEAT-008/010 |
| Browser BFF transport + server transport port | `src/lib/identity-creation/transport.ts`, `src/app/api/*` | FEAT-008/009/010 |
| Create User UI surfaces (design-baseline copy, a11y primitives) | `src/app/auth/create/*` | FEAT-008/009 reuse Protect/review primitives |

## Explicit Missing-Profile Contract (FEAT-008)

- New identities may be created only when `GetIdentity` authoritatively reports absence AND credential verification passed (see `MissingProfileCreationContract` in `contracts.ts`).
- Fields are restricted to: normalizedAlias, visibility, abbreviated signing/encryption addresses, authorizationRef. No secrets, no full addresses.
- FEAT-008 consumes this contract to offer explicit missing-profile creation after a valid recovery-word derivation finds no on-chain profile.

## Device-Protection Reuse (FEAT-008/009)

- The `ProtectScreen` component (uncontrolled refs, direct authority transfer, immediate DOM clearing) is the shared device-protection primitive.
- The backup-file password is a separate purpose; FEAT-009 must destroy backup-password buffers before mounting the shared Protect screen. FEAT-007 never collects a backup-file password.

## Reconciliation Projections (FEAT-010)

- Provisional → saved-waiting → confirmed projections and startup resume behavior are published by `provision.ts` + `reconciliation.ts`.
- Lock handoff: `navigation-control.ts` `unifiedBack` resolves post-boundary Back to the locked/returning-user target.
- Vault-inspection guards (`inspectOnboardingToken`) reject forged/stale creation tokens.

## Retained Mnemonic Policy (FEAT-011)

- Created identities retain the mnemonic record (separately encrypted) per the sealed provision record; FEAT-011 may export only with a fresh authenticated operation and a new backup-file password. No export behavior exists in FEAT-007.

## Evidence and Secret Rules

- No real mnemonic, password, private key, full transaction, or full address may appear in this handoff or in FEAT-007 evidence.
- Cross-adapter conformance proves equivalent normalized results (browser BFF vs native Rust); it never pretends browser custody proves native custody.
- The BFF server transport gRPC binding completes with the pinned HushServerNode hardening artifact; until then all server calls fail closed.
