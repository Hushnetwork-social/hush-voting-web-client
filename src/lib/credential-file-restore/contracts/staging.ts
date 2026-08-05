/**
 * FEAT-009 credential-file restore — staging journal contract.
 *
 * Framework-neutral. Defines the closed vocabulary for the encrypted
 * staged-restore record lifecycle consumed from FEAT-003/008 kernels:
 * stage presence inspection, unlock, lookup-first reconciliation,
 * cancellation/removal, and cleanup/quarantine. Startup never shows
 * first-run while staged data exists; no source path/URI/password/
 * mnemonic is restored.
 *
 * SECRET BOUNDARY: no staging contract carries the Backup-file password,
 * source bytes, plaintext, mnemonic, private keys, or full ordinary
 * addresses.
 *
 * Normative source: FEAT-009 FeatureDescription "Persistent Staging and
 * Activation", "Restart and Resume", "Concurrency and Ownership",
 * "Logout/Removal"; FEAT-003 lifecycle kernels; FEAT-008 staged resume.
 */

/** Startup inspection result — decides first-run vs resume surface. */
export type StartupInspection =
  | { readonly kind: 'verifiedEmpty' } // no active/staged/rollback/removal/quarantined/competing authority
  | { readonly kind: 'stagedExists' } // encrypted file-restore stage present; show Finish restoring your identity
  | { readonly kind: 'activeIdentity' } // configured local identity present; Lock retains; no Create/Restore
  | { readonly kind: 'quarantined' } // cleanup failure; Create/Restore blocked
  | { readonly kind: 'competingAuthority' }; // another tab/window/process owns the epoch

/** Cleanup scope — only HushVoting-managed local data, never the external source. */
export type CleanupScope =
  | 'stage' // encrypted staged record
  | 'transaction' // retained exact transaction (persistent policy only)
  | 'protectionBinding' // password/WebAuthn/OS wrapper binding
  | 'sidecar' // temporary metadata/sidecar files
  | 'session' // session-only in-memory state
  | 'externalSource' // FORBIDDEN — never in any cleanup scope set
  | 'tempCiphertext'; // temporary ciphertext copy (verify deleted)

/** Closed cleanup/quarantine outcome. */
export type CleanupVerification =
  | { readonly kind: 'verifiedAbsent' } // every managed item removed; first-run paths allowed
  | { readonly kind: 'quarantined'; readonly remaining: readonly CleanupScope[] }; // failed removal; blocks Create/Restore

/** Cancellation outcome for a staged restore. */
export type StagedCancellation =
  | { readonly kind: 'removed' } // staged keys securely removed; source re-import required later
  | { readonly kind: 'quarantined' }; // removal failed verification; first-run blocked

/** One-owner concurrency state for the restore epoch. */
export type OwnerState =
  | { readonly kind: 'owner' }
  | { readonly kind: 'nonOwner'; readonly safeStatus: 'recoveryInProgress' } // safe blocked state only
  | { readonly kind: 'released' }; // ownership released; Retry/focus allowed after release
