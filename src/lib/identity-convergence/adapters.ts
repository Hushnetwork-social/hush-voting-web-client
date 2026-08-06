/**
 * FEAT-011 Task 4.3 — complete Create/Words/File candidate convergence
 * adapters over the completed FEAT-007/008/009 authorities.
 *
 * These adapters are thin policy mappings over the sealed upstream handoffs:
 * they never re-implement derivation, proof, or custody. They close the
 * documented gaps: lookup-first creation, complete Approved candidate
 * resolution (never partial-set absence), P-01-only shortcuts removed, and
 * explicit same-key review defaults per origin.
 *
 * SECRET BOUNDARY: adapters receive only closed outcome/proof handoffs with
 * full public addresses (restricted authority side); React/XState consume only
 * the safe projections from `contracts.ts`.
 */

import type { CandidateLookupOutcome, CandidateResolution, MissingProfileOrigin, MissingProfileReview, IdentityVisibility } from './contracts';

/**
 * Resolve the complete Approved candidate set into one closed decision.
 * `expectedTotal` is the authority-known Approved candidate count; absence is
 * established only when EVERY candidate returned an explicit not-found.
 * Partial sets and multiple matches fail closed; a single exact match wins.
 */
export function resolveCompleteCandidateSet(
  outcomes: ReadonlyArray<CandidateLookupOutcome>,
  expectedTotal: number,
): CandidateResolution {
  const completed = outcomes.filter((o) => o.kind === 'explicitNotfound').length;
  const exact = outcomes.filter((o) => o.kind === 'exactMatch');

  if (exact.length > 1) {
    return { kind: 'multipleMatches', count: exact.length };
  }

  if (exact.length === 1) {
    return { kind: 'exactMatch', proof: exact[0].proof };
  }

  if (completed < expectedTotal) {
    return { kind: 'incomplete', completed, total: expectedTotal };
  }

  return { kind: 'allAbsent' };
}

/** Create User: the exact generated pair enters lookup-first convergence. */
export function createCandidateResolution(signingAddress: string, encryptionAddress: string): CandidateLookupOutcome {
  return {
    kind: 'exactMatch',
    proof: { signingAddress, encryptionAddress, normalizedAlias: '', visibility: 'private' },
  };
}

/** Credential File: the strict both-key proof becomes the lookup candidate. */
export function fileCandidateResolution(signingAddress: string, encryptionAddress: string): CandidateLookupOutcome {
  return {
    kind: 'exactMatch',
    proof: { signingAddress, encryptionAddress, normalizedAlias: '', visibility: 'private' },
  };
}

/**
 * Missing-profile review defaults per origin (frozen):
 * create reuses the already reviewed metadata; words/returningReset start with
 * empty alias + Private visibility; credentialFile may prefill authenticated
 * file metadata as explicit-review-only (never blockchain truth).
 */
export function reviewDefaultsFor(
  origin: MissingProfileOrigin,
  createMetadata?: { readonly alias: string; readonly visibility: IdentityVisibility },
  fileMetadata?: { readonly alias: string; readonly visibility: IdentityVisibility },
): MissingProfileReview {
  switch (origin) {
    case 'create':
      return {
        origin,
        alias: createMetadata?.alias ?? '',
        visibility: createMetadata?.visibility ?? 'private',
        prefillIsAuthoritative: false,
        sameIdentityAcknowledged: false,
      };
    case 'credentialFile':
      return {
        origin,
        alias: fileMetadata?.alias ?? '',
        visibility: fileMetadata?.visibility ?? 'private',
        prefillIsAuthoritative: false,
        sameIdentityAcknowledged: false,
      };
    case 'words':
    case 'returningReset':
      return {
        origin,
        alias: '',
        visibility: 'private',
        prefillIsAuthoritative: false,
        sameIdentityAcknowledged: false,
      };
  }
}

/**
 * Six-position recovery confirmation guard (FEAT-007 requirement): creation
 * may not proceed to lookup/protection without the completed challenge.
 */
export function enforceSixPositionConfirmation(confirmed: boolean): { readonly ok: true } | { readonly ok: false; readonly code: 'RECOVERY_CONFIRMATION_REQUIRED' } {
  return confirmed ? { ok: true } : { ok: false, code: 'RECOVERY_CONFIRMATION_REQUIRED' };
}

/** Returning-reset predicate: concrete keys + authoritative absence only — mnemonic availability is irrelevant. */
export function decideReturningReset(
  keysAvailable: boolean,
  authoritativeAbsent: boolean,
  verifiedMetadataAvailable: boolean,
): { readonly ok: true } | { readonly ok: false; readonly code: 'NOT_AUTHORITATIVE' | 'KEYS_UNAVAILABLE' | 'NO_VERIFIED_METADATA' } {
  if (!authoritativeAbsent) {
    return { ok: false, code: 'NOT_AUTHORITATIVE' };
  }
  if (!keysAvailable) {
    return { ok: false, code: 'KEYS_UNAVAILABLE' };
  }
  if (!verifiedMetadataAvailable) {
    return { ok: false, code: 'NO_VERIFIED_METADATA' };
  }
  return { ok: true };
}
