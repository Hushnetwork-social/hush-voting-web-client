/**
 * FEAT-008 recovery-words authority — exact activation, missing-profile
 * recreation, and staged resume policy.
 *
 * Framework-neutral. Re-verifies existing profiles after protection delay,
 * activates only on exact both-key match, transitions disappeared profiles to
 * explicit recreation review, reuses the FEAT-007 unchanged registration
 * lifecycle for exact-key missing-profile creation, and resumes staged
 * persistent recovery after restart without words.
 *
 * SECRET BOUNDARY: exact public addresses and opaque refs only. The fresh
 * `GetIdentity` verification is performed by the sealed authority/worker;
 * no client parses free-form messages.
 *
 * Normative source: FEAT-008 FeatureDescription "Existing-Profile
 * Activation", "Missing-Profile Recreation", "Restart and Resume",
 * "Canonical Network Binding", "Error Model"; FEAT-007 creation handoff.
 */
import type { NetworkIdentifier, RecoveryEpoch, RecoveryResult } from '../contracts/lifecycle';
import type { ProtectionMode } from '../contracts/envelope';

/** Fresh verification outcome after protection setup (lookup-first). */
export type FreshProfileOutcome =
  | { readonly kind: 'exactExisting'; readonly signingAddress: string; readonly encryptionAddress: string; readonly alias: string; readonly visibility: 'private' | 'public' }
  | { readonly kind: 'authoritativeAbsent' }
  | { readonly kind: 'transportFailure' }
  | { readonly kind: 'mismatch' }; // exact signing AND encryption required; signing-only fails closed

/** Sealed fresh-verification seam (worker-owned exact GetIdentity). */
export interface FreshVerificationPort {
  freshLookup(signingAddress: string, encryptionAddress: string, networkIdentifier: NetworkIdentifier): Promise<FreshProfileOutcome>;
}

/**
 * Existing-profile activation policy: atomically activate ONLY on exact
 * both-key match. A disappeared profile triggers explicit recreate review
 * (never silent submission). Transport failure preserves the sealed stage and
 * remains gated — offline key possession never opens the shell.
 */
export function evaluateExistingProfileActivation(outcome: FreshProfileOutcome): RecoveryResult<{ readonly action: 'activate' | 'recreateReview' | 'remainStaged' }> {
  if (outcome.kind === 'exactExisting') {
    return { ok: true, value: { action: 'activate' } };
  }
  if (outcome.kind === 'authoritativeAbsent') {
    return { ok: true, value: { action: 'recreateReview' } };
  }
  if (outcome.kind === 'mismatch') {
    return {
      ok: false,
      code: 'SIGNING_ENCRYPTION_MISMATCH',
      message: 'The recovered keys do not match the blockchain profile exactly.',
      supportCode: 'RW-ACT-1',
    };
  }
  return { ok: true, value: { action: 'remainStaged' } };
}

/** Missing-profile recreation review (alias empty, visibility Private by default). */
export interface RecreateReviewInput {
  readonly epoch: RecoveryEpoch;
  readonly networkIdentifier: NetworkIdentifier;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
}

/** Sealed FEAT-007 registration seam — unchanged payload/lifecycle reused. */
export interface RegistrationPort {
  /** Lookup-first submission; ACCEPTED/PENDING wait-only; exact signing confirmation. */
  submitFullIdentity(input: RecreateReviewInput, alias: string, visibility: 'private' | 'public'): Promise<RecoveryResult<{ readonly status: 'ACCEPTED' | 'PENDING' | 'CONFIRMED' | 'REJECTED' }>>;
}

/**
 * Missing-profile recreation policy: alias starts empty, visibility defaults
 * Private, Public requires acknowledgement, and Create confirmation is
 * mandatory before submission. The exact recovered keys are reused — FEAT-008
 * never generates replacement words or a different identity.
 */
export function prepareRecreateReview(input: RecreateReviewInput): {
  readonly reviewAlias: string;
  readonly reviewVisibility: 'private' | 'public';
  readonly publicAcknowledgementRequired: true;
  readonly usesExactRecoveredKeys: true;
  readonly networkIdentifier: string;
} {
  return {
    reviewAlias: '',
    reviewVisibility: 'private',
    publicAcknowledgementRequired: true,
    usesExactRecoveredKeys: true,
    networkIdentifier: input.networkIdentifier,
  };
}

export function validateRecreateConfirmation(alias: string, visibility: 'private' | 'public', publicAcknowledged: boolean): RecoveryResult<{ readonly alias: string; readonly visibility: 'private' | 'public' }> {
  if (visibility === 'public' && !publicAcknowledged) {
    return { ok: false, code: 'PROTECTION_CANCELLED', message: 'Public visibility requires explicit acknowledgement.', supportCode: 'RW-REC-1' };
  }
  const normalizedAlias = alias.trim();
  if (normalizedAlias.length === 0) {
    return { ok: false, code: 'REGISTRATION_REJECTED', message: 'An alias is required before creating the identity.', supportCode: 'RW-REC-2' };
  }
  return { ok: true, value: { alias: normalizedAlias, visibility } };
}

/**
 * Staged resume policy. Startup inspection with a supported staged recovery
 * shows "Finish restoring your identity" — never first-run, never word entry.
 * Unlock uses the selected protection mode, then lookup-first decides
 * activation vs recreation vs remain-staged. Words are never reconstructed.
 */
export interface StagedInspection {
  readonly staged: boolean;
  readonly protectionMode: ProtectionMode | null;
  readonly corrupted: boolean; // corruption/unsupported version → fail closed
  readonly signingAddress: string | null;
  readonly encryptionAddress: string | null;
}

export function evaluateStartup(inspection: StagedInspection): RecoveryResult<{ readonly surface: 'firstRun' | 'finishRestoring' | 'locked' }> {
  if (inspection.corrupted) {
    return { ok: false, code: 'STAGED_RESTART_FAILURE', message: 'Staged recovery data is corrupted or unsupported.', supportCode: 'RW-RES-1' };
  }
  if (inspection.staged) {
    return { ok: true, value: { surface: 'finishRestoring' } };
  }
  return { ok: true, value: { surface: 'firstRun' } };
}
