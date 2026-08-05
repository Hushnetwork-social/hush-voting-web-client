/**
 * FEAT-009 credential-file restore — view-state and action projections.
 *
 * Framework-neutral. Maps every authority stage to exactly one screen, a
 * deterministic allowed-action set, safe review fields, bounded progress,
 * disabled/busy state, and a focus destination. React stays a thin
 * renderer: it receives a closed `RestoreViewState` and allowed actions
 * only. Stale or duplicate results are rejected by the authority epoch
 * before reaching this mapping. No secret, source identifier, full address
 * (outside transient reveal), or generic capability is representable.
 *
 * Normative source: FEAT-009 FeatureDescription "Success and User
 * Feedback", "Error Privacy", "Identity Resolution", "Initial Local
 * Protection", "Navigation and Back"; FEAT-002 presentation vocabulary;
 * FEAT-007/008 presentation mapping.
 */
import type { RestoreAction, RestoreCopyKey, RestoreFocusTarget, RestoreProtectionChoice, RestoreViewProjection } from '../contracts/projection';
import type { RestoreStage } from '../contracts/lifecycle';
import type { ReadProgress } from '../contracts/custody';

/** Deterministic restore screens (closed union). */
export type RestoreScreen =
  | 'entry' // three-choice first-run entry (Create / Restore File / Restore Words)
  | 'vaultGuard' // verified-empty inspection / remediation
  | 'capabilityPreflight' // safe custody/protection disclosure (session-only-only notice)
  | 'picker' // one-source selection (cancel neutral)
  | 'reading' // "Reading credential file…" with progress and Cancel
  | 'password' // "Backup ready for password" — purpose-specific field
  | 'decrypting' // "Decrypting backup…"
  | 'validating' // "Validating identity keys…"
  | 'lookup' // "Checking blockchain identity…"
  | 'profileReview' // missing-profile explicit review
  | 'protection' // "Protect this device" — FEAT-008 choice
  | 'staging' // "Saving encrypted identity…"
  | 'resumeGate' // "Finish restoring your identity"
  | 'activating' // final online verification / block confirmation wait
  | 'success' // "Identity restored" (announced once; auto dashboard)
  | 'locked' // lifecycle lock
  | 'quarantined' // cleanup failure gate
  | 'terminal'; // fail-closed terminal

/** Deterministic stage → screen mapping (single source for the renderer). */
export function mapRestoreStageToScreen(stage: RestoreStage): RestoreScreen {
  switch (stage) {
    case 'vaultGuard':
      return 'vaultGuard';
    case 'capabilityPreflight':
      return 'capabilityPreflight';
    case 'picker':
      return 'picker';
    case 'reading':
      return 'reading';
    case 'password':
      return 'password';
    case 'decrypting':
      return 'decrypting';
    case 'validating':
      return 'validating';
    case 'lookup':
      return 'lookup';
    case 'profileReview':
      return 'profileReview';
    case 'protection':
      return 'protection';
    case 'staging':
      return 'staging';
    case 'resumeGate':
      return 'resumeGate';
    case 'activating':
      return 'activating';
    case 'success':
      return 'success';
    case 'locked':
      return 'locked';
    case 'quarantined':
      return 'quarantined';
    case 'terminal':
      return 'terminal';
    default:
      return 'terminal'; // unknown/contradictory stage fails closed (runtime defense)
  }
}

/** Stage → copy key mapping (accurate progress/success truth). */
export function copyKeyForStage(stage: RestoreStage): RestoreCopyKey {
  switch (stage) {
    case 'reading':
      return 'readingCredentialFile';
    case 'password':
      return 'backupReadyForPassword';
    case 'decrypting':
      return 'decryptingBackup';
    case 'validating':
      return 'validatingIdentityKeys';
    case 'lookup':
      return 'checkingBlockchainIdentity';
    case 'protection':
      return 'protectThisDevice';
    case 'staging':
      return 'savingEncryptedIdentity';
    case 'activating':
      return 'waitingForBlockchainFinalApproval';
    case 'resumeGate':
      return 'finishRestoringYourIdentity';
    case 'success':
      return 'identityRestored'; // only after exact online activation
    case 'quarantined':
      return 'quarantinedCleanup';
    default:
      return 'credentialFileSelected';
  }
}

/** Stage → permitted actions mapping (actions legal only in enumerated stages). */
export function permittedActionsForStage(stage: RestoreStage): readonly RestoreAction[] {
  switch (stage) {
    case 'picker':
      return ['chooseFile', 'back'];
    case 'reading':
      return ['cancelRead', 'back'];
    case 'password':
      return ['submitPassword', 'togglePasswordVisibility', 'enableEmptyPasswordOption', 'chooseDifferentFile', 'back'];
    case 'decrypting':
    case 'validating':
      return ['back'];
    case 'lookup':
      return ['back'];
    case 'profileReview':
      return ['createIdentity', 'revealFullAddress', 'back'];
    case 'protection':
      return ['selectProtectionMode', 'back'];
    case 'staging':
      return ['back'];
    case 'resumeGate':
      return ['unlockStagedResume', 'cancelStagedRestore', 'retryCleanup'];
    case 'activating':
      return [];
    case 'success':
      return ['copyFullAddress'];
    case 'quarantined':
      return ['retryCleanup'];
    case 'locked':
      return [];
    default:
      return ['back'];
  }
}

/** Failure code → focus target (predictable post-error focus). */
export function focusTargetForFailure(code: string): RestoreFocusTarget {
  switch (code) {
    case 'AUTHENTICATION_FAILED':
    case 'BACKOFF_ACTIVE':
      return 'countdownStatus';
    case 'PICKER_CANCELLED':
    case 'READ_UNAVAILABLE':
    case 'READ_INACTIVITY_TIMEOUT':
    case 'READ_PARTIAL':
    case 'FILE_TOO_LARGE':
      return 'retryButton';
    case 'SIGNING_KEY_MISMATCH':
    case 'ENCRYPTION_KEY_MISMATCH':
    case 'MNEMONIC_KEY_MISMATCH':
    case 'KEY_PROOF_FAILED':
    case 'UNSUPPORTED_KEY_ENCODING':
    case 'PAYLOAD_DUPLICATE_FIELD':
    case 'PAYLOAD_UNKNOWN_FIELD':
    case 'PAYLOAD_MISSING_FIELD':
    case 'PAYLOAD_INVALID_FIELD':
      return 'errorSummary';
    case 'CLEANUP_FAILURE':
    case 'QUARANTINED':
      return 'remediation';
    default:
      return 'errorSummary';
  }
}

/** Input needed by the deterministic projector. */
export interface RestoreViewInput {
  readonly stage: RestoreStage;
  readonly progress: ReadProgress | null;
  readonly failureCode: string | null;
  readonly backoffRemainingSeconds: number; // 0 when inactive
  readonly passwordField: {
    readonly visible: boolean;
    readonly emptyOptionChecked: boolean;
    readonly emptyOptionEnabled: boolean;
  } | null;
  readonly protectionChoices: readonly RestoreProtectionChoice[] | null;
  readonly profile: RestoreViewProjection['profile'];
  readonly reveal: RestoreViewProjection['reveal'];
}

/** Closed view state consumed by the renderer. */
export interface RestoreViewState {
  readonly screen: RestoreScreen;
  readonly copyKey: RestoreCopyKey;
  readonly permittedActions: readonly RestoreAction[];
  readonly focusTarget: RestoreFocusTarget;
  readonly progress: ReadProgress | null;
  readonly failureCode: string | null;
  readonly backoff: { readonly active: boolean; readonly remainingSeconds: number } | null;
  readonly passwordFieldState: RestoreViewProjection['passwordFieldState'];
  readonly protectionChoices: readonly RestoreProtectionChoice[] | null;
  readonly profile: RestoreViewProjection['profile'];
  readonly reveal: RestoreViewProjection['reveal'];
  readonly canSubmitPassword: boolean; // enabled only when a value may be submitted
}

/** Deterministic projection of authority state to a closed view. */
export function toRestoreViewState(input: RestoreViewInput): RestoreViewState {
  const screen = mapRestoreStageToScreen(input.stage);
  const copyKey = copyKeyForStage(input.stage);
  const permittedActions = permittedActionsForStage(input.stage);
  const focusTarget = input.failureCode !== null ? focusTargetForFailure(input.failureCode) : focusTargetForStage(input.stage);
  const backoff =
    input.backoffRemainingSeconds > 0
      ? { active: true, remainingSeconds: input.backoffRemainingSeconds }
      : null;
  return {
    screen,
    copyKey,
    permittedActions,
    focusTarget,
    progress: input.progress,
    failureCode: input.failureCode,
    backoff,
    passwordFieldState: input.passwordField
      ? { ...input.passwordField, byteLimit: 4096 }
      : null,
    protectionChoices: input.protectionChoices,
    profile: input.profile,
    reveal: input.reveal,
    canSubmitPassword: input.stage === 'password' && input.passwordField !== null && !input.passwordField.emptyOptionChecked,
  };
}

function focusTargetForStage(stage: RestoreStage): RestoreFocusTarget {
  switch (stage) {
    case 'picker':
      return 'chooseFileButton';
    case 'password':
      return 'passwordField';
    case 'protection':
      return 'protectionChoice';
    case 'profileReview':
      return 'createIdentityButton';
    case 'resumeGate':
      return 'resumeUnlockButton';
    case 'success':
      return 'successAnnouncement';
    default:
      return 'entryChoice';
  }
}

/** Success truth table: only exact online activation produces Identity restored. */
export function isIdentityRestored(stage: RestoreStage, activation: 'existing' | 'created' | 'none'): boolean {
  if (stage !== 'success') {
    return false;
  }
  // success is only reachable through the authority's exact online
  // activation; the activation kind is evidence, not authority.
  return activation === 'existing' || activation === 'created';
}
