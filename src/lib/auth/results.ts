/**
 * FEAT-002 authentication contracts — typed actor results.
 *
 * Every actor outcome is typed data with one stable machine-readable code.
 * Expected actor failures are data; raw exceptions never cross the port.
 * This module owns the deterministic mapping from outcome code to the
 * documented UX state so every typed outcome has exactly one UX mapping.
 *
 * Normative source: FEAT-002 FeatureDescription "Initialization results",
 * "Core transitions", "Errors", and "Test Requirements" sections.
 */

import type { AuthOutcomeCode, AuthStateCode, ConnectivityStateCode } from './types.js';

/** Every documented typed state (including recoverable/blocked categories). */
export type ErrorCategory = 'recoverable' | 'blocked';

/**
 * Deterministic mapping: outcome code → authentication state.
 * Every reachable code has exactly one destination (no blank screens,
 * no ambiguous transitions). `null` means the outcome does not drive a
 * state change (e.g., pure informational results).
 */
export function outcomeToAuthState(code: AuthOutcomeCode): AuthStateCode | null {
  switch (code) {
    case 'INIT_NO_LOCAL_USER':
    case 'INIT_MEMORY_ONLY':
      return 'noLocalUser';
    case 'INIT_LOCKED_USER':
      return 'locked';
    case 'INIT_STORAGE_UNAVAILABLE':
      return 'recoverableError';
    case 'INIT_UNSUPPORTED_VAULT_VERSION':
    case 'INIT_CORRUPT_VAULT':
    case 'INIT_UNSAFE_COORDINATION':
    case 'MISSING_PLATFORM_PROTECTION':
    case 'COORDINATION_UNSAFE':
      return 'blockedError';
    case 'UNLOCK_SUCCESS':
      return 'verifyingIdentityOnline';
    case 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED':
      return 'locked';
    case 'UNLOCK_THROTTLED':
    case 'INVALID_MNEMONIC':
      return 'recoverableError';
    case 'VERIFY_SUCCESS':
      return 'authenticated';
    case 'VERIFY_PROFILE_MISSING':
      return 'missingProfileConfirmation';
    case 'VERIFY_SIGNING_KEY_MISMATCH':
    case 'VERIFY_ENCRYPTION_KEY_MISMATCH':
      return 'blockedError';
    case 'VERIFY_TIMEOUT':
    case 'VERIFY_NETWORK_UNAVAILABLE':
      // stays behind the locked verification gate; connectivity handles retry
      return 'verifyingIdentityOnline';
    case 'ONBOARDING_COMPLETED':
      return 'verifyingIdentityOnline';
    case 'ONBOARDING_BACK':
    case 'ONBOARDING_CLEANUP_COMPLETE':
      return 'noLocalUser';
    case 'REMOVAL_COMPLETE':
      return 'noLocalUser';
    case 'REMOVAL_BLOCKED_REMEDIATION':
      return 'blockedError';
    case 'TRANSACTION_REJECTED':
      return 'recoverableError';
    case 'AUTHORITY_LOST':
    case 'SESSION_INVALIDATED':
      return 'locked';
    case 'UNKNOWN_FAILURE':
      return 'recoverableError';
    case 'COORDINATION_SAFE':
      return null;
  }
}

/** Deterministic mapping: outcome code → connectivity state (independent region). */
export function outcomeToConnectivityState(code: AuthOutcomeCode): ConnectivityStateCode | null {
  switch (code) {
    case 'VERIFY_TIMEOUT':
    case 'VERIFY_NETWORK_UNAVAILABLE':
      return 'offline';
    case 'COORDINATION_SAFE':
    case 'COORDINATION_UNSAFE':
      return null;
    default:
      return null;
  }
}

/** Error category for recoverable vs blocked outcomes (drives available actions). */
export function outcomeErrorCategory(code: AuthOutcomeCode): ErrorCategory | null {
  switch (code) {
    case 'INIT_STORAGE_UNAVAILABLE':
    case 'UNLOCK_THROTTLED':
    case 'INVALID_MNEMONIC':
    case 'VERIFY_TIMEOUT':
    case 'VERIFY_NETWORK_UNAVAILABLE':
    case 'TRANSACTION_REJECTED':
    case 'UNKNOWN_FAILURE':
      return 'recoverable';
    case 'INIT_UNSUPPORTED_VAULT_VERSION':
    case 'INIT_CORRUPT_VAULT':
    case 'INIT_UNSAFE_COORDINATION':
    case 'MISSING_PLATFORM_PROTECTION':
    case 'VERIFY_SIGNING_KEY_MISMATCH':
    case 'VERIFY_ENCRYPTION_KEY_MISMATCH':
    case 'REMOVAL_BLOCKED_REMEDIATION':
    case 'COORDINATION_UNSAFE':
      return 'blocked';
    default:
      return null;
  }
}

/** Safe action set allowed for an outcome (never includes remote reset/sign-out). */
export type SafeRecoveryAction = 'retry' | 'unlock' | 'lock' | 'updateGuidance' | 'recoveryGuidance' | 'removal' | 'createOrRestore';

/** Deterministic valid recovery/action set per outcome. */
export function outcomeSafeActions(code: AuthOutcomeCode): readonly SafeRecoveryAction[] {
  switch (code) {
    case 'INIT_STORAGE_UNAVAILABLE':
    case 'VERIFY_TIMEOUT':
    case 'VERIFY_NETWORK_UNAVAILABLE':
      return ['retry'];
    case 'INVALID_MNEMONIC':
      return ['retry', 'createOrRestore'];
    case 'INIT_UNSUPPORTED_VAULT_VERSION':
      return ['updateGuidance', 'removal'];
    case 'INIT_CORRUPT_VAULT':
      return ['recoveryGuidance', 'removal'];
    case 'INIT_UNSAFE_COORDINATION':
    case 'COORDINATION_UNSAFE':
      return ['retry', 'removal'];
    case 'MISSING_PLATFORM_PROTECTION':
      return ['updateGuidance', 'removal'];
    case 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED':
    case 'UNLOCK_THROTTLED':
      return ['unlock'];
    case 'VERIFY_SIGNING_KEY_MISMATCH':
    case 'VERIFY_ENCRYPTION_KEY_MISMATCH':
      return ['lock', 'removal'];
    case 'VERIFY_PROFILE_MISSING':
      return ['createOrRestore'];
    case 'REMOVAL_BLOCKED_REMEDIATION':
      return ['recoveryGuidance', 'retry'];
    case 'TRANSACTION_REJECTED':
      return ['retry', 'lock'];
    case 'AUTHORITY_LOST':
    case 'SESSION_INVALIDATED':
      return ['unlock'];
    case 'UNKNOWN_FAILURE':
      return ['retry', 'lock'];
    default:
      return [];
  }
}

/** Initialization actor result — one of the seven documented mappings. */
export type InitializationResult =
  | { readonly code: 'INIT_NO_LOCAL_USER' }
  | { readonly code: 'INIT_MEMORY_ONLY' }
  | { readonly code: 'INIT_LOCKED_USER'; readonly safeIdentity: { readonly alias: string; readonly abbreviatedSigningAddress: string } }
  | { readonly code: 'INIT_STORAGE_UNAVAILABLE' }
  | { readonly code: 'INIT_UNSUPPORTED_VAULT_VERSION' }
  | { readonly code: 'INIT_CORRUPT_VAULT' }
  | { readonly code: 'INIT_UNSAFE_COORDINATION' };

/** Local unlock actor result (secret authority owns the secret; machine sees only the code). */
export type UnlockResult =
  | { readonly code: 'UNLOCK_SUCCESS' }
  | { readonly code: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' }
  | { readonly code: 'UNLOCK_THROTTLED'; readonly cooldownDeadlineMs: number }
  | { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string };

/** Online identity verification actor result (exact profile + both-key binding). */
export type VerificationResult =
  | { readonly code: 'VERIFY_SUCCESS' }
  | { readonly code: 'VERIFY_PROFILE_MISSING'; readonly safeCandidate: { readonly alias: string; readonly abbreviatedSigningAddress: string } }
  | { readonly code: 'VERIFY_SIGNING_KEY_MISMATCH' }
  | { readonly code: 'VERIFY_ENCRYPTION_KEY_MISMATCH' }
  | { readonly code: 'VERIFY_TIMEOUT' }
  | { readonly code: 'VERIFY_NETWORK_UNAVAILABLE' }
  | { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string };

/** Onboarding child-flow actor result. */
export type OnboardingResult =
  | { readonly code: 'ONBOARDING_COMPLETED' }
  | { readonly code: 'ONBOARDING_BACK' }
  | { readonly code: 'ONBOARDING_CLEANUP_COMPLETE' }
  | { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string };

/** Local-user removal actor result. */
export type RemovalResult =
  | { readonly code: 'REMOVAL_COMPLETE' }
  | { readonly code: 'REMOVAL_BLOCKED_REMEDIATION'; readonly remediation: 'recoveryGuidance' | 'retry' }
  | { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string };

/** Browser coordination actor result. */
export type CoordinationResult =
  | { readonly code: 'COORDINATION_SAFE' }
  | { readonly code: 'COORDINATION_UNSAFE' };
