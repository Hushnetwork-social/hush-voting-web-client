/**
 * FEAT-009 credential-file restore — child-actor registration and
 * root-only navigation composition.
 *
 * Registers the real `restoreCredentialFile` child flow through the
 * FEAT-002 capability registry (`onboardingRestoreCredentialFile` is
 * mandatory and must be non-synthetic in production) without creating a
 * second authentication or navigation authority. The concrete
 * OnboardingPort implementation that binds the sealed platform adapters
 * lands in Phase 6 integration; this module owns the registration
 * contract, the root-only Back/history policy, and the deterministic
 * view-state composition.
 *
 * SECRET BOUNDARY: no source identifier, password, plaintext, mnemonic,
 * private key, full address (outside transient reveal), or transaction
 * crosses this module.
 *
 * Normative source: FEAT-009 FeatureDescription "Navigation and Back",
 * "Concurrency and Ownership", "Entry and Capability Preflight";
 * FEAT-002 registry rules; FEAT-008 recovery child registration pattern.
 */
import type { OnboardingKind } from '../../auth/types';
import type { OnboardingResult } from '../../auth/results';
import type { RestoreStage } from '../contracts/lifecycle';
import { mapRestoreStageToScreen, toRestoreViewState, type RestoreViewInput, type RestoreViewState } from './view';
import { mapErrorToRemediation } from './remediation';

/** Credential-file child-flow actor registration: non-synthetic, mandatory. */
export interface CredentialFileActorRegistration {
  readonly capability: 'onboardingRestoreCredentialFile';
  readonly availability: 'mandatory';
  readonly synthetic: false;
}

export const CREDENTIAL_FILE_ACTOR_REGISTRATION: CredentialFileActorRegistration = {
  capability: 'onboardingRestoreCredentialFile',
  availability: 'mandatory',
  synthetic: false,
};

/** Reject a duplicate or synthetic registration (fail closed). */
export function validateCredentialFileRegistration(
  seen: boolean,
  synthetic: boolean,
): { readonly ok: true } | { readonly ok: false; readonly code: 'DUPLICATE' | 'SYNTHETIC_IN_PRODUCTION' } {
  if (seen) {
    return { ok: false, code: 'DUPLICATE' };
  }
  if (synthetic) {
    return { ok: false, code: 'SYNTHETIC_IN_PRODUCTION' };
  }
  return { ok: true };
}

/** Only the credential-file onboarding kind is accepted by this actor. */
export function assertCredentialFileKind(kind: OnboardingKind): { readonly ok: true } | { readonly ok: false; readonly code: 'WRONG_ONBOARDING_KIND' } {
  return kind === 'restoreCredentialFile' ? { ok: true } : { ok: false, code: 'WRONG_ONBOARDING_KIND' };
}

/** Deterministic completion mapping from authority completion state. */
export function completionResult(
  state: 'restoredExistingProfile' | 'createdMissingProfile' | 'sessionOnlyRestored' | 'cancelled' | 'quarantined',
  localUserRef: string,
): OnboardingResult {
  if (state === 'cancelled') {
    return { code: 'ONBOARDING_BACK' };
  }
  if (state === 'quarantined') {
    return { code: 'UNKNOWN_FAILURE', supportCode: 'DAT-QUARANTINE-1' };
  }
  return { code: 'ONBOARDING_COMPLETED', localUserRef }; // exact online activation completed
}

/** Root-only navigation policy: visible URL stays `/`; typed opaque history only. */
export function rootNavigationPolicy(): { readonly visibleUrl: '/' } {
  return { visibleUrl: '/' };
}

/** Stage-specific Back handling through the shared authority (browser/Android/in-app). */
export function backForStage(stage: RestoreStage): 'clearInputs' | 'destroyAuthority' | 'lock' {
  switch (stage) {
    case 'picker':
    case 'reading':
    case 'password':
    case 'decrypting':
      return 'clearInputs';
    case 'validating':
    case 'lookup':
    case 'profileReview':
    case 'protection':
      return 'destroyAuthority';
    case 'staging':
    case 'resumeGate':
    case 'activating':
      return 'lock';
    default:
      return 'clearInputs';
  }
}

/** Deterministic view-state composition for the child actor. */
export function composeRestoreView(input: RestoreViewInput): { readonly view: RestoreViewState; readonly remediation: ReturnType<typeof mapErrorToRemediation> | null } {
  const view = toRestoreViewState(input);
  const remediation = input.failureCode !== null ? mapErrorToRemediation(input.failureCode as Parameters<typeof mapErrorToRemediation>[0]) : null;
  return { view, remediation };
}

export type { RestoreViewState, RestoreStage };
export { mapRestoreStageToScreen };
