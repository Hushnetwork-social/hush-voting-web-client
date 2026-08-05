/**
 * FEAT-009 credential-file restore — protection and staging contracts.
 *
 * Framework-neutral. Defines the closed vocabulary for the separate
 * FEAT-008 local-protection step (Device-password default; qualified
 * passwordless/session-only alternatives), encrypted concrete-key staging
 * (two-slot journal, generation CAS, canonical AAD, authenticated
 * read-back, exact address binding), staged resume, session-only
 * non-persistence, and fail-closed activation truth. The Backup-file
 * password component/state is destroyed before any protection contract is
 * produced.
 *
 * SECRET BOUNDARY: no protection/staging contract carries the Backup-file
 * password, source data, plaintext, mnemonic, private keys (only opaque
 * verified-key references), full ordinary addresses, or generic
 * capabilities.
 *
 * Normative source: FEAT-009 FeatureDescription "Initial Local
 * Protection", "Persistent Staging and Activation", "Session-Only Import",
 * "Restart and Resume"; FEAT-008 protection/staging/activation contracts;
 * FEAT-003 two-slot/CAS kernels; FEAT-004/005/006 platform protection.
 */

import type { RestoreFailureCode, RestoreResult } from './lifecycle';

/** Closed protection modes (FEAT-008 vocabulary; no empty/plaintext modes). */
export type ProtectionMode = 'devicePassword' | 'webAuthnPasswordless' | 'nativePasswordless' | 'sessionOnly';

/** Closed protection qualification outcome. */
export type ProtectionQualification =
  | { readonly kind: 'qualified'; readonly mode: ProtectionMode; readonly version: string }
  | { readonly kind: 'unavailable'; readonly mode: ProtectionMode } // capability lost before stage; no downgrade
  | { readonly kind: 'unsupported' }; // unknown mode/version; fail closed

/** Closed staging lifecycle state. */
export type StageState =
  | 'unstarted'
  | 'writing' // journal slot write
  | 'readBack' // authenticated read-back verification
  | 'casSwitch' // generation CAS commit
  | 'committed' // encrypted stage exists; NOT authentication
  | 'quarantined'; // integrity/cleanup failure; blocks Create/Restore

/** Stage integrity verification result. */
export type StageVerification =
  | { readonly kind: 'verified' } // two-slot/CAS/read-back/address binding all pass
  | { readonly kind: 'tampered' } // ciphertext/metadata from another network/purpose/generation/profile/mode
  | { readonly kind: 'corrupt' }
  | { readonly kind: 'versionMismatch' }
  | { readonly kind: 'addressMismatch' }
  | { readonly kind: 'unknown' };

/** What a staged record may contain (safe binding metadata only). */
export interface StagedRestoreRecordMetadata {
  readonly protectionMode: ProtectionMode;
  readonly protectionVersion: string;
  readonly networkLabel: string;
  readonly signingAddressAbbreviated: string;
  readonly encryptionAddressAbbreviated: string;
  readonly profileAlias: string | null; // blockchain-authoritative or explicitly reviewed pending metadata
  readonly profileIsPublic: boolean | null;
  readonly stagedAtMs: number;
  readonly generation: number; // CAS generation
  readonly purpose: 'file-restore'; // never any other purpose
}

/** Closed resume outcome after unlock. */
export type ResumeOutcome =
  | { readonly kind: 'resume'; readonly stage: StagedRestoreRecordMetadata } // lookup-first reconciliation follows
  | { readonly kind: 'corrupt' } // corruption/version/key mismatch; fail closed
  | { readonly kind: 'quarantined' }
  | { readonly kind: 'cancelled' }; // explicit staged cancellation/removal; source re-import required later

/** Session-only lifecycle outcome (nothing persisted). */
export type SessionOnlyOutcome =
  | { readonly kind: 'active' } // verified keys in isolated memory only
  | { readonly kind: 'ended' } // Lock/reload/final-tab close/process loss/session policy; no local user remains
  | { readonly kind: 'requiresReimport' }; // exact online verification or confirmation required after re-import

/** Closed activation truth (never from local state alone). */
export type ActivationOutcome =
  | { readonly kind: 'activatedExisting' } // fresh exact online lookup verified
  | { readonly kind: 'activatedCreated' } // exact FEAT-007 block confirmation
  | { readonly kind: 'notYetActive' } // staged/awaiting; not authenticated
  | { readonly kind: 'connectivityFailure' } // stage preserved; Retry; never shell
  | { readonly kind: 'failedClosed' }; // corruption/version/key mismatch; fail closed

/** Protection/staging contract — closed mode registry. */
export const PROTECTION_MODES: readonly ProtectionMode[] = [
  'devicePassword',
  'webAuthnPasswordless',
  'nativePasswordless',
  'sessionOnly',
];

/** Device-password is the default selection. */
export const DEFAULT_PROTECTION_MODE: ProtectionMode = 'devicePassword';

/** A staged restore is never authentication. */
export const STAGED_RESTORE_IS_AUTHENTICATION = false as const;

export type ProtectionResult = RestoreResult<{
  readonly qualification: ProtectionQualification;
  readonly stage: StageState;
  readonly verification: StageVerification | null;
  readonly metadata: StagedRestoreRecordMetadata | null;
}>;

export type StageFailureCode = RestoreFailureCode; // reuse closed failure vocabulary
