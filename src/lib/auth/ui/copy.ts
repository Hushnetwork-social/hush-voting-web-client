/**
 * FEAT-002 authentication UI copy — pure, deterministic, accessibility-safe.
 *
 * Maps every auth state / outcome to the exact user-facing copy and the
 * accessible document title. No secret content ever appears in titles,
 * labels, or live regions. Terminology is local-device language only
 * (Unlock HushVoting!, Device password, Lock, Remove local user) — never
 * "server login", "account password", "password reset", or "remote sign-out".
 *
 * Normative source: FeatureDescription "Terminology", "Errors",
 * "Locked-user screen", "Removal confirmation".
 */

import { AUTH_TERMINOLOGY, COMBINED_CREDENTIAL_ERROR } from '../types';
import type { AuthStateCode } from '../types';

/** Safe document title for each reachable auth state. */
export function documentTitleForState(state: AuthStateCode): string {
  switch (state) {
    case 'initializing':
      return 'HushVoting!';
    case 'noLocalUser':
      return 'Welcome · HushVoting!';
    case 'onboarding':
      return 'Set up · HushVoting!';
    case 'locked':
      return `${AUTH_TERMINOLOGY.unlock} · HushVoting!`;
    case 'unlocking':
      return `${AUTH_TERMINOLOGY.unlock} · HushVoting!`;
    case 'verifyingIdentityOnline':
      return `${AUTH_TERMINOLOGY.unlock} · HushVoting!`;
    case 'missingProfileConfirmation':
      return 'Confirm identity · HushVoting!';
    case 'authenticated':
      return 'HushVoting!';
    case 'recoverableError':
      return 'Something went wrong · HushVoting!';
    case 'blockedError':
      return 'HushVoting! is locked';
    case 'removingLocalUser':
      return `${AUTH_TERMINOLOGY.removeLocalUser} · HushVoting!`;
  }
}

/** Accessible heading for the primary surface in each state. */
export function headingForState(state: AuthStateCode): string {
  switch (state) {
    case 'initializing':
      return 'HushVoting!';
    case 'noLocalUser':
      return 'Welcome to HushVoting!';
    case 'onboarding':
      return 'Set up this device';
    case 'locked':
      return AUTH_TERMINOLOGY.unlock;
    case 'unlocking':
      return 'Unlocking…';
    case 'verifyingIdentityOnline':
      return 'Verifying your identity…';
    case 'missingProfileConfirmation':
      return 'Confirm your identity';
    case 'authenticated':
      return 'HushVoting!';
    case 'recoverableError':
      return 'Something went wrong';
    case 'blockedError':
      return 'HushVoting! is locked';
    case 'removingLocalUser':
      return AUTH_TERMINOLOGY.removeLocalUser;
  }
}

/** Polite progress label shown after the 250 ms threshold (no secrets). */
export function progressLabelForState(state: AuthStateCode): string | null {
  switch (state) {
    case 'unlocking':
      return 'Unlocking this device…';
    case 'verifyingIdentityOnline':
      return 'Checking your identity with the network…';
    case 'removingLocalUser':
      return 'Removing local data…';
    default:
      return null;
  }
}

/** Exact privacy-safe combined credential error text (normative). */
export const COMBINED_ERROR_COPY = COMBINED_CREDENTIAL_ERROR;

/**
 * Map a typed outcome code to privacy-safe error copy + action copy.
 * Unknown failures receive generic text plus the per-occurrence support code.
 */
export function errorCopyForOutcome(outcomeCode: string | null): { title: string; detail: string } {
  switch (outcomeCode) {
    case 'INIT_STORAGE_UNAVAILABLE':
      return { title: 'Storage is temporarily unavailable', detail: 'Try again in a moment.' };
    case 'INIT_UNSUPPORTED_VAULT_VERSION':
      return { title: 'This device uses an unsupported vault version', detail: 'Update HushVoting! or follow the recovery guidance.' };
    case 'INIT_CORRUPT_VAULT':
      return { title: 'Local data could not be read', detail: 'You can restore from recovery words or a credential file.' };
    case 'INIT_UNSAFE_COORDINATION':
    case 'COORDINATION_UNSAFE':
      return { title: 'This browser cannot secure a session', detail: 'Use a supported browser or another device.' };
    case 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED':
      return { title: 'Unable to unlock', detail: COMBINED_ERROR_COPY };
    case 'UNLOCK_THROTTLED':
      return { title: 'Too many attempts', detail: 'Wait before trying again.' };
    case 'VERIFY_TIMEOUT':
    case 'VERIFY_NETWORK_UNAVAILABLE':
      return { title: 'Network unavailable', detail: 'Your identity could not be verified right now.' };
    case 'VERIFY_SIGNING_KEY_MISMATCH':
    case 'VERIFY_ENCRYPTION_KEY_MISMATCH':
      return { title: 'Identity mismatch', detail: 'This device no longer matches the network identity.' };
    case 'VERIFY_PROFILE_MISSING':
      return { title: 'No profile found', detail: 'Create the identity on this device to continue.' };
    case 'MISSING_PLATFORM_PROTECTION':
      return { title: 'Required protection is unavailable', detail: 'Update your device or browser and try again.' };
    case 'INVALID_MNEMONIC':
      return { title: 'Recovery phrase is invalid', detail: 'Check the word count, spelling, and checksum.' };
    case 'TRANSACTION_REJECTED':
      return { title: 'The request was rejected', detail: 'Try again or lock this device.' };
    case 'REMOVAL_BLOCKED_REMEDIATION':
      return { title: 'Removal could not complete', detail: 'Follow the recovery guidance or try again.' };
    case 'SESSION_INVALIDATED':
    case 'AUTHORITY_LOST':
      return { title: 'Session ended', detail: 'Unlock again to continue.' };
    default:
      return { title: 'Something went wrong', detail: 'Try again, or lock this device and retry.' };
  }
}

/** Safe action-label mapping (never offers remote reset or sign-out). */
export function actionLabelForIntent(intent: string): string {
  switch (intent) {
    case 'INTENT.RETRY':
      return 'Try again';
    case 'INTENT.LOCK':
      return AUTH_TERMINOLOGY.lock;
    case 'INTENT.UNLOCK':
      return AUTH_TERMINOLOGY.unlock;
    case 'INTENT.REMOVE_LOCAL_USER':
      return AUTH_TERMINOLOGY.removeLocalUser;
    default:
      return 'Continue';
  }
}
