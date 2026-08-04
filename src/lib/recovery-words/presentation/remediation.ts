/**
 * FEAT-008 recovery-words — error, progress, accessibility, and remediation
 * projections.
 *
 * Framework-neutral. Maps every typed validation, lookup, protection,
 * staging, activation, cleanup, and capability outcome to bounded copy,
 * allowed recovery actions, status semantics, error-summary links, and
 * predictable focus. Unknown codes fail closed with a generic safe message —
 * never free-form parsing, never echoed secrets, addresses, or platform
 * internals.
 *
 * Normative source: FEAT-008 FeatureDescription "Error Model",
 * "Validation feedback", "Accessibility and Responsive UX",
 * "Secret-safe evidence", "Candidate Outcome UX" (safe source labels).
 */
import type { RecoveryFailureCode } from '../contracts/lifecycle';
import type { RecoveryAction } from '../contracts/projection';

/** Bounded remediation surface for one typed failure. */
export interface RecoveryRemediation {
  readonly code: RecoveryFailureCode;
  /** Safe, bounded copy; never echoes words/keys/addresses/credentials. */
  readonly message: string;
  /** Allowed recovery actions for this error (closed). */
  readonly actions: readonly RecoveryAction[];
  /** Focus destination: 'input' (first invalid position) or 'summary'. */
  readonly focusTarget: 'input' | 'summary' | 'primaryAction';
  /** True when the error keeps the concealed grid for correction. */
  readonly retainsGrid: boolean;
}

/** Closed remediation table (single source for the renderer). */
const REMEDIATION_TABLE: Readonly<Record<RecoveryFailureCode, Omit<RecoveryRemediation, 'code'>>> = {
  VAULT_NOT_VERIFIED_EMPTY: { message: 'A local identity already exists on this device.', actions: ['lock'], focusTarget: 'primaryAction', retainsGrid: false },
  WRONG_COUNT: { message: 'Recovery phrases must contain exactly 12 or 24 words.', actions: ['clearAll', 'pastePhrase'], focusTarget: 'input', retainsGrid: true },
  UNKNOWN_WORD: { message: 'One or more recovery words are not in the supported word list.', actions: ['clearAll', 'pastePhrase'], focusTarget: 'input', retainsGrid: true },
  CHECKSUM_FAILURE: { message: 'The recovery phrase failed its checksum; please review the words.', actions: ['clearAll', 'pastePhrase'], focusTarget: 'input', retainsGrid: true },
  UNSUPPORTED_INPUT: { message: 'Only 12- or 24-word English phrases without a passphrase are supported.', actions: ['clearAll'], focusTarget: 'summary', retainsGrid: false },
  PRODUCER_DERIVATION_FAILURE: { message: 'This phrase could not be fully validated; please re-enter it.', actions: ['clearAll'], focusTarget: 'summary', retainsGrid: false },
  PARTIAL_CANDIDATE_LOOKUP: { message: 'Identity checks are incomplete; retry the unresolved checks.', actions: ['retryUnresolvedLookups', 'back'], focusTarget: 'primaryAction', retainsGrid: false },
  SIGNING_ENCRYPTION_MISMATCH: { message: 'The recovered keys do not match the profile exactly; recovery cannot continue.', actions: ['back'], focusTarget: 'summary', retainsGrid: false },
  EPOCH_EXPIRED: { message: 'This recovery session expired; please enter your recovery words again.', actions: ['clearAll'], focusTarget: 'summary', retainsGrid: false },
  STALE_EPOCH: { message: 'This action is no longer valid; please try again.', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  DOUBLE_DISPATCH: { message: 'Please wait for the current check to finish.', actions: [], focusTarget: 'summary', retainsGrid: false },
  OWNERSHIP_LOST: { message: 'Recovery is already in progress in another window.', actions: ['retry'], focusTarget: 'primaryAction', retainsGrid: false },
  NETWORK_UNAVAILABLE: { message: 'A connection is required to check your identity; retry when online.', actions: ['retryUnresolvedLookups', 'back'], focusTarget: 'primaryAction', retainsGrid: false },
  MALFORMED_PROFILE: { message: 'The identity service returned an unexpected result; please retry.', actions: ['retryUnresolvedLookups', 'back'], focusTarget: 'summary', retainsGrid: false },
  PROTECTION_CANCELLED: { message: 'Protection setup was cancelled; choose an option to continue.', actions: ['chooseProtectionMode', 'back'], focusTarget: 'primaryAction', retainsGrid: false },
  ENCRYPTED_STAGE_FAILURE: { message: 'Saving your restored identity failed; please enter your words again.', actions: ['clearAll'], focusTarget: 'summary', retainsGrid: false },
  STAGED_RESTART_FAILURE: { message: 'The saved restore is damaged or unsupported; contact support.', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  PROFILE_DISAPPEARED: { message: 'Your profile is no longer on this network; review the recreate step.', actions: ['confirmRecreateProfile', 'back'], focusTarget: 'primaryAction', retainsGrid: false },
  REGISTRATION_REJECTED: { message: 'The identity service rejected the registration; review the details.', actions: ['back'], focusTarget: 'summary', retainsGrid: false },
  REGISTRATION_PENDING: { message: 'Registration is pending confirmation; please wait.', actions: [], focusTarget: 'primaryAction', retainsGrid: false },
  CLEANUP_FAILURE: { message: 'Local cleanup could not be verified; retry the removal.', actions: ['retry'], focusTarget: 'primaryAction', retainsGrid: false },
  QUARANTINED: { message: 'Recovery is blocked until local cleanup completes.', actions: ['retry'], focusTarget: 'primaryAction', retainsGrid: false },
  UNKNOWN_OUTCOME: { message: 'Something unexpected happened; please try again.', actions: ['retry', 'back'], focusTarget: 'summary', retainsGrid: false },
  ENVELOPE_MALFORMED: { message: 'The saved restore is damaged; contact support.', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  MNEMONIC_RECORD_INJECTED: { message: 'The saved restore is invalid; contact support.', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  UNSUPPORTED_RECOVERY_VERSION: { message: 'This restore was created by a newer version; update HushVoting!', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  PROTECTION_METADATA_INVALID: { message: 'The saved protection settings are invalid; contact support.', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  UNSUPPORTED_PROTECTION_MODE: { message: 'The saved protection mode is unsupported; contact support.', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  UNSUPPORTED_PROTECTION_VERSION: { message: 'The saved protection settings are from a newer version; update HushVoting!', actions: ['retry'], focusTarget: 'summary', retainsGrid: false },
  UNQUALIFIED_PASSWORDLESS: { message: 'Passwordless protection is not available on this device; choose another option.', actions: ['chooseProtectionMode'], focusTarget: 'primaryAction', retainsGrid: false },
};

/** Deterministic failure → remediation mapping (unknown codes fail closed). */
export function mapErrorToRemediation(code: RecoveryFailureCode): RecoveryRemediation {
  const entry = REMEDIATION_TABLE[code];
  if (!entry) {
    return {
      code,
      message: 'Something unexpected happened; please try again.',
      actions: ['retry', 'back'],
      focusTarget: 'summary',
      retainsGrid: false,
    };
  }
  return { code, ...entry };
}

/** Progress semantics: status announcements are throttled, not per-request. */
export function shouldAnnounceProgress(progressBucket: 'idle' | 'pending' | 'running' | 'done', lastAnnounced: 'idle' | 'pending' | 'running' | 'done'): boolean {
  return progressBucket !== lastAnnounced && progressBucket !== 'idle';
}

/** Stateful accessible name for the show/hide words control. */
export function showAllAccessibleName(allConcealed: boolean): string {
  return allConcealed ? 'Show all recovery words' : 'Hide all recovery words';
}

/** Error-summary link model: numbered positions only, never values. */
export function errorSummaryPositions(invalidPositions: readonly number[]): readonly number[] {
  return [...invalidPositions].sort((a, b) => a - b);
}
