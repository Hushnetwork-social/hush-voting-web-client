/**
 * FEAT-007 identity-creation — lookup-first reconciliation, outcome, polling,
 * and correction policies.
 *
 * Platform-neutral orchestration policy: every startup/unlock/foreground/
 * connectivity cycle performs `GetIdentity` first; submission happens at most
 * once per cycle and only after transport-successful authoritative absence;
 * exact bytes are reused on ambiguous retry; polling runs every three seconds
 * while eligible and stops into a defect state after three minutes; editable
 * rejection reopens Profile/Review with a fresh password capability and one
 * replacement transaction; blockchain reset creates one fresh transaction
 * from the same vault credentials (never a new mnemonic).
 *
 * Normative source: FEAT-007 FeatureDescription "Lookup-First Reconciliation",
 * "Submission Outcome Contract", "Waiting for Blockchain Confirmation",
 * "Error-specific replacement rules", "Three-minute abnormal delay".
 */
import type { LookupOutcome, SubmissionOutcome } from './wire';

export const POLL_INTERVAL_MS = 3_000 as const;
export const ABNORMAL_DELAY_MS = 180_000 as const; // 3 minutes

/** Reconciliation cycle state machine. */
export type ReconciliationState =
  | { readonly status: 'idle' }
  | { readonly status: 'lookupInFlight' }
  | { readonly status: 'submissionEligible'; readonly cycleId: string }
  | { readonly status: 'submitted'; readonly outcome: SubmissionOutcome; readonly cycleId: string }
  | { readonly status: 'confirmed'; readonly profileName: string }
  | { readonly status: 'failClosed'; readonly code: 'SIGNING_MISMATCH' | 'ENCRYPTION_MISMATCH' | 'COMPATIBILITY' | 'TRANSPORT_AMBIGUOUS' }
  | { readonly status: 'delayed'; readonly sinceMs: number };

/** Fail-closed reconciliation codes (closed union). */
export type ReconciliationFailClosedCode = 'SIGNING_MISMATCH' | 'ENCRYPTION_MISMATCH' | 'COMPATIBILITY' | 'TRANSPORT_AMBIGUOUS';

export type ReconciliationAction =
  | { readonly kind: 'wait' }
  | { readonly kind: 'submitOnce'; readonly cycleId: string }
  | { readonly kind: 'promoteConfirmed'; readonly profileName: string }
  | { readonly kind: 'failClosed'; readonly code: ReconciliationFailClosedCode }
  | { readonly kind: 'poll' }
  | { readonly kind: 'enterDelay' }
  | { readonly kind: 'checkAgainLookupOnly' }
  | { readonly kind: 'syncMetadata'; readonly profileName: string };

/** Decide the reconciliation action from a lookup outcome (lookup-first). */
export function decideLookupAction(lookup: LookupOutcome, cycleId: string): ReconciliationAction {
  switch (lookup.kind) {
    case 'exactProfile':
      // Exact signing + encryption addresses confirm the same identity;
      // synchronize blockchain metadata and promote (valid epoch required).
      return { kind: 'promoteConfirmed', profileName: lookup.profileName };
    case 'signingKeyMismatch':
      return { kind: 'failClosed', code: 'SIGNING_MISMATCH' };
    case 'encryptionKeyMismatch':
      // Signing matches but encryption differs → fail closed, never trust.
      return { kind: 'failClosed', code: 'ENCRYPTION_MISMATCH' };
    case 'authoritativeAbsent':
      // Only transport-successful authoritative absence permits submission,
      // at most once per cycle.
      return { kind: 'submitOnce', cycleId };
    case 'malformedSuccess':
    case 'compatibilityError':
      return { kind: 'failClosed', code: 'COMPATIBILITY' };
    case 'transportFailure':
      // Ambiguous connectivity: preserve exact transaction; never infer
      // absence or rejection; never submit.
      return { kind: 'failClosed', code: 'TRANSPORT_AMBIGUOUS' };
    default:
      return { kind: 'failClosed', code: 'COMPATIBILITY' };
  }
}

/** Submission outcome → local lifecycle + next action. */
export type SubmissionDecision =
  | { readonly kind: 'promoteSavedWaiting'; readonly outcome: 'accepted' | 'pending' }
  | { readonly kind: 'resolveByLookup' } // ALREADY_EXISTS → exact lookup
  | { readonly kind: 'reopenProfile'; readonly validationCode: string } // editable
  | { readonly kind: 'terminalFailClosed'; readonly validationCode: string }
  | { readonly kind: 'failClosed'; readonly code: 'UNKNOWN_REJECTION' | 'COMPATIBILITY' }
  | { readonly kind: 'preserveAmbiguous' }; // transport failure

export function decideSubmissionAction(outcome: SubmissionOutcome): SubmissionDecision {
  switch (outcome.kind) {
    case 'accepted':
    case 'pending':
      // Promote provisional → saved-waiting; wait for exact GetIdentity.
      return { kind: 'promoteSavedWaiting', outcome: outcome.kind };
    case 'alreadyExists':
      return { kind: 'resolveByLookup' };
    case 'editableRejection':
      return { kind: 'reopenProfile', validationCode: outcome.validationCode };
    case 'terminalRejection':
      return { kind: 'terminalFailClosed', validationCode: outcome.validationCode };
    case 'unknownRejection':
      return { kind: 'failClosed', code: 'UNKNOWN_REJECTION' };
    case 'compatibilityError':
      return { kind: 'failClosed', code: 'COMPATIBILITY' };
    case 'transportFailure':
      return { kind: 'preserveAmbiguous' };
    default:
      return { kind: 'failClosed', code: 'COMPATIBILITY' };
  }
}

/** Polling eligibility: foreground, online, visible, authority-valid, not delayed. */
export function shouldPoll(foregrounded: boolean, online: boolean, visible: boolean, authorityEpochValid: boolean, delayed: boolean): boolean {
  return foregrounded && online && visible && authorityEpochValid && !delayed;
}

/** Three-minute abnormal delay: stop polling, lookup-only Check again. */
export function evaluateDelay(acceptedSinceMs: number, nowMs: number): { readonly delayed: boolean; readonly elapsedMs: number } {
  const elapsedMs = nowMs - acceptedSinceMs;
  return { delayed: elapsedMs >= ABNORMAL_DELAY_MS, elapsedMs };
}

/**
 * Replacement-transaction eligibility (error-specific). A new transaction is
 * permitted ONLY for: corrected editable pre-admission rejection; previously
 * confirmed profile authoritatively absent after blockchain reset; or a
 * legitimately missing retained record with authenticated verification and
 * authoritative absence. Never every three seconds, after restart, while
 * PENDING is known, after transport timeout, or after cryptographic/unknown
 * rejection.
 */
export interface ReplacementEligibilityInput {
  readonly editableCorrection: boolean;
  readonly blockchainResetAuthoritativeAbsent: boolean;
  readonly missingRecordRebuildEligible: boolean;
  readonly pendingKnown: boolean;
  readonly transportTimeoutWithoutAbsence: boolean;
  readonly cryptographicOrUnknownRejection: boolean;
}

export function canReplaceTransaction(input: ReplacementEligibilityInput): boolean {
  if (input.pendingKnown || input.transportTimeoutWithoutAbsence || input.cryptographicOrUnknownRejection) {
    return false;
  }
  return input.editableCorrection || input.blockchainResetAuthoritativeAbsent || input.missingRecordRebuildEligible;
}

/**
 * Blockchain-reset policy: a previously confirmed local identity is never
 * trusted solely from a local marker. Authoritative absence → one fresh
 * transaction from the same vault credentials and latest verified encrypted
 * profile. The mnemonic/key pair never changes because the chain was reset.
 */
export function decideBlockchainReset(previousConfirmed: boolean, authoritativeAbsent: boolean, mnemonicAvailable: boolean): { readonly ok: true } | { readonly ok: false; readonly code: 'NOT_AUTHORITATIVE' | 'MNEMONIC_UNAVAILABLE' } {
  if (!previousConfirmed) {
    return { ok: false, code: 'NOT_AUTHORITATIVE' };
  }
  if (!authoritativeAbsent) {
    return { ok: false, code: 'NOT_AUTHORITATIVE' };
  }
  if (!mnemonicAvailable) {
    return { ok: false, code: 'MNEMONIC_UNAVAILABLE' };
  }
  return { ok: true };
}
