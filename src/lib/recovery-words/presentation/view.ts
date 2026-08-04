/**
 * FEAT-008 recovery-words — recovery view-state and action projections.
 *
 * Framework-neutral. Maps every authority stage to exactly one screen, a
 * deterministic allowed-action set, safe review fields, bounded progress,
 * disabled/busy state, and a focus destination. React stays a thin renderer:
 * it receives a closed `RecoveryViewState` and allowed actions only. Stale or
 * duplicate results are rejected by the authority epoch before reaching this
 * mapping. No secret, full address (outside transient reveal), or capability
 * is representable.
 *
 * Normative source: FEAT-008 FeatureDescription "Primary User Journey",
 * "Candidate Outcome UX", "Restart and Resume", "Accessibility and Responsive
 * UX", "Navigation and History", "Concurrency and Ownership"; FEAT-002
 * presentation vocabulary; FEAT-007 creation presentation mapping.
 */
import type { RecoveryAction } from '../contracts/projection';
import type { RecoveryStage } from '../contracts/lifecycle';

/** Deterministic recovery screens (closed union). */
export type RecoveryScreen =
  | 'entry' // exact three-choice first-run screen (Create / Restore Words / Restore File)
  | 'vaultGuard' // verified-empty inspection / remediation
  | 'networkLabel' // canonical target network confirmation
  | 'wordEntry' // 12/24 selector, grid, paste, concealment, validation
  | 'verifying' // one bounded phrase handoff; page buffers clear
  | 'deriving' // candidate derivation progress (after 150 ms)
  | 'lookup' // safe counted lookup progress ("Checking identity formats 2 of 4")
  | 'resolving' // outcome assembly; no intermediate disclosure
  | 'candidateSelection' // zero-match source-guided selection (no default)
  | 'profileSelection' // multiple existing blockchain profiles (no default)
  | 'proof' // selected-key control proof
  | 'protection' // non-retention acknowledgement + protection choice
  | 'staging' // encrypted stage write + read-back verification
  | 'existingProfileVerify' // fresh exact GetIdentity before activation
  | 'recreateReview' // missing-profile alias/visibility review
  | 'registration' // FEAT-007 status/polling
  | 'activating' // atomic activation
  | 'success' // Identity restored (announced once; automatic dashboard transition)
  | 'finishRestoring' // staged resume gate; never reveals words
  | 'locked' // lifecycle lock
  | 'quarantined' // cleanup failure gate
  | 'terminal'; // fail-closed terminal

/** Deterministic stage → screen mapping (single source for the renderer). */
export function mapRecoveryStageToScreen(stage: RecoveryStage): RecoveryScreen {
  switch (stage) {
    case 'vaultGuard':
      return 'vaultGuard';
    case 'networkLabel':
      return 'networkLabel';
    case 'wordEntry':
      return 'wordEntry';
    case 'verifying':
      return 'verifying';
    case 'deriving':
      return 'deriving';
    case 'lookup':
      return 'lookup';
    case 'resolving':
      return 'resolving';
    case 'candidateSelection':
      return 'candidateSelection';
    case 'profileSelection':
      return 'profileSelection';
    case 'proof':
      return 'proof';
    case 'protection':
      return 'protection';
    case 'staging':
      return 'staging';
    case 'existingProfileVerify':
      return 'existingProfileVerify';
    case 'recreateReview':
      return 'recreateReview';
    case 'registration':
      return 'registration';
    case 'activating':
      return 'activating';
    case 'success':
      return 'success';
    case 'finishRestoring':
      return 'finishRestoring';
    case 'locked':
      return 'locked';
    case 'quarantined':
      return 'quarantined';
    case 'terminal':
      return 'terminal';
  }
}

/** Primary action availability (derived, never guessed by the renderer). */
export type RecoveryActionAvailability = 'enabled' | 'disabled' | 'inProgress' | 'hidden';

/** One deterministic screen/action/error model for the renderer. */
export interface RecoveryViewState {
  readonly screen: RecoveryScreen;
  readonly canGoBack: boolean;
  readonly primaryAction: RecoveryActionAvailability;
  /** Safe error surface: stable code + safe text; never echoes secrets. */
  readonly error: { readonly code: string; readonly message: string } | null;
  /** Progress coarse bucket for long operations (after 150 ms). */
  readonly progressBucket: 'idle' | 'pending' | 'running' | 'done';
  /** Privacy-safe evidence category for telemetry (aggregate only). */
  readonly evidenceCategory: string | null;
  /** 1-based focus target for the first invalid input (word entry only). */
  readonly focusFirstInvalidPosition: number | null;
  /** Owner state (single-owner coordination). */
  readonly ownerState: 'owner' | 'blockedByOtherOwner' | 'awaitingRelease';
  /** Allowed user actions for the current screen (closed allowlist). */
  readonly allowedActions: readonly RecoveryAction[];
}

/** Inputs the authority publishes to the presentation layer (secret-free). */
export interface RecoveryViewInput {
  readonly stage: RecoveryStage;
  readonly operationInFlight: boolean;
  readonly canGoBack: boolean;
  readonly lastError: { readonly code: string; readonly message: string } | null;
  readonly progressStarted: boolean;
  readonly progressComplete: boolean;
  readonly evidenceCategory: string | null;
  readonly focusFirstInvalidPosition: number | null;
  readonly ownerState: 'owner' | 'blockedByOtherOwner' | 'awaitingRelease';
  readonly busyStages?: ReadonlyArray<RecoveryStage>;
}

/** Stages that render as busy/disabled while an operation is in flight. */
export const RECOVERY_BUSY_STAGES: ReadonlyArray<RecoveryStage> = [
  'verifying',
  'deriving',
  'lookup',
  'resolving',
  'proof',
  'staging',
  'existingProfileVerify',
  'registration',
  'activating',
];

/** Deterministic action allowlist per screen (renderer never guesses). */
export function allowedActionsForScreen(screen: RecoveryScreen, inFlight: boolean, ownerState: RecoveryViewState['ownerState']): readonly RecoveryAction[] {
  if (ownerState === 'blockedByOtherOwner') {
    return ['retry']; // safe already-in-progress surface only
  }
  switch (screen) {
    case 'entry':
      return []; // the three-choice entry dispatch belongs to the FEAT-002 auth shell, not the recovery child
    case 'vaultGuard':
      return ['removeLocalUser', 'back'];
    case 'networkLabel':
      return ['verify', 'back'];
    case 'wordEntry':
      if (inFlight) {
        return ['clearAll', 'toggleShowAll'];
      }
      return ['selectWordCount', 'pastePhrase', 'clearAll', 'toggleShowAll', 'verify', 'back'];
    case 'verifying':
    case 'deriving':
    case 'resolving':
      return ['back'];
    case 'lookup':
      if (inFlight) {
        return ['back'];
      }
      return ['retryUnresolvedLookups', 'back'];
    case 'candidateSelection':
    case 'profileSelection':
      return ['selectCandidate', 'revealFullAddress', 'concealFullAddress', 'copyFullAddress', 'back'];
    case 'proof':
      return ['back'];
    case 'protection':
      return ['chooseProtectionMode', 'acknowledgeNoRetention', 'back'];
    case 'staging':
      return ['back'];
    case 'existingProfileVerify':
      return ['confirmExistingProfile', 'back'];
    case 'recreateReview':
      return ['confirmRecreateProfile', 'back'];
    case 'registration':
      return ['submitRegistration', 'back'];
    case 'activating':
      return [];
    case 'success':
      return [];
    case 'finishRestoring':
      return ['finishRestoringUnlock', 'lock'];
    case 'locked':
      return ['lock', 'removeLocalUser', 'back'];
    case 'quarantined':
      return ['retry'];
    case 'terminal':
      return ['retry'];
  }
}

/** Build the deterministic view state from authority inputs. */
export function toRecoveryViewState(input: RecoveryViewInput): RecoveryViewState {
  const screen = mapRecoveryStageToScreen(input.stage);
  const busy = input.busyStages?.includes(input.stage) ?? RECOVERY_BUSY_STAGES.includes(input.stage);
  const primaryAction: RecoveryActionAvailability = input.operationInFlight
    ? 'inProgress'
    : busy
      ? 'disabled'
      : screen === 'success' || screen === 'activating' || screen === 'terminal'
        ? 'hidden'
        : 'enabled';
  const progressBucket = input.progressComplete ? 'done' : input.progressStarted ? 'running' : input.operationInFlight ? 'pending' : 'idle';
  const allowedActions = allowedActionsForScreen(screen, input.operationInFlight, input.ownerState);
  return {
    screen,
    canGoBack: input.canGoBack,
    primaryAction,
    error: input.lastError,
    progressBucket,
    evidenceCategory: input.evidenceCategory,
    focusFirstInvalidPosition: input.focusFirstInvalidPosition,
    ownerState: input.ownerState,
    allowedActions,
  };
}
