/**
 * FEAT-009 credential-file restore — safe UI projection contracts.
 *
 * Framework-neutral. These are the ONLY data shapes that may cross the
 * authority boundary toward the UI. They carry safe selected status,
 * coarse progress, typed outcomes, permitted actions, focus targets,
 * backoff countdown state, abbreviated addresses, and bounded profile
 * metadata. Full public addresses exist only in explicit transient reveal
 * data, never in ordinary projection state.
 *
 * SECRET BOUNDARY: no projection can represent a source identifier, source
 * byte, Backup-file password, derived AES key, plaintext, mnemonic, private
 * key, full address, credential ID, exact transaction, or generic
 * capability.
 *
 * Normative source: FEAT-009 FeatureDescription "Success and User
 * Feedback", "Error Privacy", "Accessibility and Responsive UX", "Identity
 * Resolution", "Backup-File Password UX"; FEAT-007/008 presentation
 * vocabulary; FEAT-002 safe projections.
 */

import type { RestoreFailure, RestoreStage } from './lifecycle';
import type { ReadProgress } from './custody';

/** Abbreviate a public address to `<first 8>…<last 6>` (design baseline). */
export function abbreviateAddress(address: string): string {
  if (address.length <= 14) {
    return address;
  }
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

/** Permitted UI actions — only actions safe for the current lifecycle stage. */
export type RestoreAction =
  | 'chooseFile'
  | 'chooseDifferentFile'
  | 'cancelRead'
  | 'retryRead'
  | 'submitPassword'
  | 'togglePasswordVisibility'
  | 'enableEmptyPasswordOption'
  | 'back'
  | 'selectProtectionMode'
  | 'acknowledgeSessionOnly'
  | 'revealFullAddress'
  | 'copyFullAddress'
  | 'createIdentity'
  | 'unlockStagedResume'
  | 'cancelStagedRestore'
  | 'retryCleanup';

/** Focus target for deterministic post-transition focus movement. */
export type RestoreFocusTarget =
  | 'entryChoice'
  | 'chooseFileButton'
  | 'passwordField'
  | 'errorSummary'
  | 'countdownStatus'
  | 'retryButton'
  | 'protectionChoice'
  | 'createIdentityButton'
  | 'resumeUnlockButton'
  | 'successAnnouncement'
  | 'remediation';

/** Bounded protection-mode choice (FEAT-008 vocabulary; no empty/plaintext modes). */
export type RestoreProtectionChoice =
  | 'devicePassword'
  | 'webAuthnPasswordless'
  | 'nativePasswordless'
  | 'sessionOnly';

/** Exact required copy keys — centralized safe copy; never raw exception text. */
export type RestoreCopyKey =
  | 'readingCredentialFile'
  | 'backupReadyForPassword'
  | 'decryptingBackup'
  | 'validatingIdentityKeys'
  | 'checkingBlockchainIdentity'
  | 'protectThisDevice'
  | 'savingEncryptedIdentity'
  | 'waitingForBlockchainFinalApproval'
  | 'identityRestored'
  | 'finishRestoringYourIdentity'
  | 'credentialFileSelected'
  | 'backupPasswordIncorrectOrDamaged'
  | 'invalidOrInconsistentIdentityKeys'
  | 'noProfileExistsOnBlockchain'
  | 'serverRejectedIdentityProof'
  | 'thisBackupCreatedWithoutPassword'
  | 'passwordDecryptsSelectedBackupOnly'
  | 'mnemonicSourceNotice'
  | 'recoveryInProgress'
  | 'quarantinedCleanup';

/** One restore view — closed safe projection. */
export interface RestoreViewProjection {
  readonly stage: RestoreStage;
  readonly copyKey: RestoreCopyKey;
  readonly permittedActions: readonly RestoreAction[];
  readonly focusTarget: RestoreFocusTarget;
  readonly progress: ReadProgress | null;
  readonly failure: RestoreFailure | null; // safe typed failure (code/message/supportCode only)
  readonly backoff: {
    readonly active: boolean;
    readonly remainingSeconds: number; // accessible countdown; 0 when inactive
  } | null;
  readonly passwordFieldState: {
    readonly visible: boolean; // show/hide toggle state
    readonly emptyOptionChecked: boolean;
    readonly emptyOptionEnabled: boolean;
    readonly byteLimit: number; // 4096
  } | null;
  readonly protectionChoices: readonly RestoreProtectionChoice[] | null;
  readonly profile: RestoreProfileProjection | null;
  readonly reveal: {
    readonly token: string; // opaque explicit-reveal token; expires from ordinary state
    readonly fullSigningAddress: string; // present ONLY in explicit reveal projection
    readonly fullEncryptionAddress: string;
  } | null;
}

/** Bounded safe profile projection (chain-authoritative or reviewed pending metadata). */
export interface RestoreProfileProjection {
  readonly alias: string; // escaped/isolated/bounded; never rendered unsanitized
  readonly isPublic: boolean;
  readonly signingAddressAbbreviated: string; // abbreviateAddress()
  readonly encryptionAddressAbbreviated: string;
  readonly networkLabel: string; // safe bound-network label
  readonly source: 'blockchain' | 'importedReview'; // chain metadata authoritative
  readonly aliasEditable: boolean; // only in missing-profile review with current rules
  readonly publicAcknowledgementRequired: boolean;
}

/** Compile-time guard: a projection must never contain a secret surface. */
export interface SafeRestoreProjection {
  readonly view: RestoreViewProjection;
  readonly isSafe: true; // marker: only SafeRestoreProjection crosses the authority boundary
}
