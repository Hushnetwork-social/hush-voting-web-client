/**
 * FEAT-008 recovery-words — recovery child-actor registration and view-state
 * composition.
 *
 * Registers the real `restoreRecoveryWords` child flow through the FEAT-002
 * capability registry (`onboardingRestoreRecoveryWords` is mandatory and must
 * be non-synthetic in production) without creating a second authentication or
 * navigation authority. The concrete OnboardingPort implementation that binds
 * the sealed platform adapters lands in Phase 6 integration; this module owns
 * the registration contract and the deterministic view-state composition.
 *
 * SECRET BOUNDARY: no phrase, seed, private key, password, PRF output, full
 * address (outside transient reveal), or transaction crosses this module.
 *
 * Normative source: FEAT-008 FeatureDescription "Navigation and History",
 * "Concurrency and Ownership", "Restart and Resume"; FEAT-002 registry rules;
 * FEAT-007 creation actor registration pattern.
 */
import type { OnboardingKind } from '../../auth/types';
import type { OnboardingResult } from '../../auth/results';
import type { RecoveryFailureCode, RecoveryStage } from '../contracts/lifecycle';
import { mapRecoveryStageToScreen, toRecoveryViewState, type RecoveryViewInput, type RecoveryViewState } from './view';
import { mapErrorToRemediation } from './remediation';

/** Recovery words child-flow actor registration: non-synthetic, mandatory. */
export interface RecoveryWordsActorRegistration {
  readonly capability: 'onboardingRestoreRecoveryWords';
  readonly availability: 'mandatory';
  readonly synthetic: false;
}

export const RECOVERY_WORDS_ACTOR_REGISTRATION: RecoveryWordsActorRegistration = {
  capability: 'onboardingRestoreRecoveryWords',
  availability: 'mandatory',
  synthetic: false,
};

/** Reject a duplicate or synthetic registration (fail closed). */
export function validateRecoveryWordsRegistration(seen: boolean, synthetic: boolean): { readonly ok: true } | { readonly ok: false; readonly code: 'DUPLICATE' | 'SYNTHETIC_IN_PRODUCTION' } {
  if (seen) {
    return { ok: false, code: 'DUPLICATE' };
  }
  if (synthetic) {
    return { ok: false, code: 'SYNTHETIC_IN_PRODUCTION' };
  }
  return { ok: true };
}

/** Only the recovery words onboarding kind is accepted by this actor. */
export function assertRecoveryWordsKind(kind: OnboardingKind): { readonly ok: true } | { readonly ok: false; readonly code: 'WRONG_ONBOARDING_KIND' } {
  return kind === 'restoreRecoveryWords' ? { ok: true } : { ok: false, code: 'WRONG_ONBOARDING_KIND' };
}

/** Deterministic completion mapping from authority completion state. */
export function completionResult(state: 'restoredExistingProfile' | 'createdMissingProfile' | 'sessionOnlyRestored' | 'cancelled' | 'quarantined'): OnboardingResult {
  if (state === 'cancelled') {
    return { code: 'ONBOARDING_BACK' };
  }
  if (state === 'quarantined') {
    return { code: 'UNKNOWN_FAILURE', supportCode: 'RW-QUARANTINE-1' };
  }
  return { code: 'ONBOARDING_COMPLETED', localUserRef: `recovery:${state}` };
}

/** Safe view-state composition: stage + error → one renderer model. */
export function composeRecoveryView(stage: RecoveryStage, input: Omit<RecoveryViewInput, 'stage'>): RecoveryViewState {
  const remediation = input.lastError ? mapErrorToRemediation(input.lastError.code as RecoveryFailureCode) : null;
  return toRecoveryViewState({
    stage,
    ...input,
    lastError: remediation ? { code: remediation.code, message: remediation.message } : null,
  });
}

/** Staged-resume surface gate (never first-run while staged data exists). */
export function surfaceForStaged(staged: boolean, corrupted: boolean): 'finishRestoring' | 'wordEntry' {
  if (staged && !corrupted) {
    return 'finishRestoring';
  }
  return 'wordEntry';
}

/** Re-export the screen vocabulary for renderers. */
export { mapRecoveryStageToScreen };
