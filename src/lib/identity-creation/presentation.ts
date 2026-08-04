/**
 * FEAT-007 identity-creation — presentation view-state mapping and create-user
 * actor registration contract.
 *
 * Maps the platform-neutral creation authority outcomes to ONE deterministic
 * screen/action/error model for the renderer. React stays a thin renderer:
 * it receives a closed `CreationViewState` and allowed actions only. Duplicate
 * or stale results are rejected by the authority epoch before they reach this
 * mapping. No secret, full address, transaction, or capability is representable.
 *
 * The create-user actor registration contract mirrors the FEAT-002 capability
 * registry (`onboardingCreateUser` is mandatory and must be non-synthetic in
 * production). The concrete OnboardingPort implementation that binds platform
 * adapters lands in Phase 6 integration.
 *
 * Normative source: FEAT-007 FeatureDescription "Platform Composition",
 * "Navigation and History", "Accessibility and Responsive UX"; FEAT-002
 * registration validation.
 */
import type { CreationStage } from './contracts.js';

/** Deterministic creation screens (closed union). */
export type CreationScreen =
  | 'entry' // exactly three equal first-run choices
  | 'preflight' // platform security/persistence check + remediation
  | 'profile' // alias + initial visibility
  | 'generate' // explicit generation with progress
  | 'recovery' // 24-word reveal (bounded)
  | 'confirmRecovery' // six-position challenge
  | 'protect' // Device password (direct authority boundary)
  | 'review' // safe final review
  | 'finishCreating' // provisional resume
  | 'waiting' // mempool waiting gate
  | 'delay' // three-minute abnormal delay
  | 'connection' // waiting for connection
  | 'correcting' // editable alias rejection
  | 'cancelling' // destructive-confirmed cancellation
  | 'locked'; // lifecycle lock / returning-user unlock

/** Primary action availability (derived, never guessed by the renderer). */
export type CreationActionAvailability = 'enabled' | 'disabled' | 'inProgress' | 'hidden';

/** One deterministic screen/action/error model for the renderer. */
export interface CreationViewState {
  readonly screen: CreationScreen;
  readonly canGoBack: boolean;
  readonly primaryAction: CreationActionAvailability;
  /** Safe error surface: stable code + safe text; never echoes secrets. */
  readonly error: { readonly code: string; readonly message: string } | null;
  /** Progress coarse bucket for long operations (after 150 ms). */
  readonly progressBucket: 'idle' | 'pending' | 'running' | 'done';
  /** Privacy-safe evidence category for telemetry (aggregate only). */
  readonly evidenceCategory: string | null;
  /** True only when the local boundary has been crossed (history invalidation). */
  readonly localBoundaryCrossed: boolean;
}

/** Deterministic stage → screen mapping (single source for the renderer). */
export function mapStageToScreen(stage: CreationStage): CreationScreen {
  switch (stage) {
    case 'preflight':
      return 'preflight';
    case 'profile':
      return 'profile';
    case 'generating':
      return 'generate';
    case 'recovery':
      return 'recovery';
    case 'protect':
      return 'protect';
    case 'review':
      return 'review';
    case 'provisionalResume':
      return 'finishCreating';
    case 'waiting':
      return 'waiting';
    case 'delay':
      return 'delay';
    case 'connection':
      return 'connection';
    case 'correcting':
      return 'correcting';
    case 'cancelling':
      return 'cancelling';
    case 'locked':
      return 'locked';
    case 'terminal':
      return 'locked'; // fail-closed terminal renders through the locked/error shell
    default:
      return 'entry';
  }
}

export interface ViewInput {
  readonly stage: CreationStage;
  readonly canGoBack: boolean;
  readonly operationInFlight: boolean;
  readonly lastError: { readonly code: string; readonly message: string } | null;
  readonly progressStarted: boolean;
  readonly progressComplete: boolean;
  readonly localBoundaryCrossed: boolean;
  readonly evidenceCategory: string | null;
}

/** Build the deterministic view state from authority inputs. */
export function toViewState(input: ViewInput): CreationViewState {
  const screen = mapStageToScreen(input.stage);
  const busy = screen === 'waiting' || screen === 'connection' || screen === 'preflight';
  const primaryAction: CreationActionAvailability = input.operationInFlight
    ? 'inProgress'
    : busy
      ? 'disabled'
      : input.stage === 'locked' || input.stage === 'terminal'
        ? 'hidden'
        : 'enabled';
  const progressBucket = input.progressComplete ? 'done' : input.progressStarted ? 'running' : input.operationInFlight ? 'pending' : 'idle';
  return {
    screen,
    canGoBack: input.canGoBack,
    primaryAction,
    error: input.lastError,
    progressBucket,
    evidenceCategory: input.evidenceCategory,
    localBoundaryCrossed: input.localBoundaryCrossed,
  };
}

/**
 * Create-user actor registration contract: non-synthetic, mandatory, exactly
 * one registration, production-safe. Mirrors FEAT-002 registry rules.
 */
export interface CreateUserActorRegistration {
  readonly capability: 'onboardingCreateUser';
  readonly availability: 'mandatory';
  readonly synthetic: false;
}

export const CREATE_USER_ACTOR_REGISTRATION: CreateUserActorRegistration = {
  capability: 'onboardingCreateUser',
  availability: 'mandatory',
  synthetic: false,
};

/** Reject a duplicate or synthetic registration (fail closed). */
export function validateCreateUserRegistration(seen: boolean, synthetic: boolean): { readonly ok: true } | { readonly ok: false; readonly code: 'DUPLICATE' | 'SYNTHETIC_IN_PRODUCTION' } {
  if (seen) {
    return { ok: false, code: 'DUPLICATE' };
  }
  if (synthetic) {
    return { ok: false, code: 'SYNTHETIC_IN_PRODUCTION' };
  }
  return { ok: true };
}
