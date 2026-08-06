/**
 * FEAT-011 identity convergence — closed identity-decision and public-projection contracts.
 *
 * Framework-neutral (no React, Next.js, DOM, storage, transport, or
 * state-store dependencies). Defines the closed vocabulary for the one
 * blockchain-authoritative identity decision consumed by Create User, Recovery
 * Words, Credential File, and returning unlock:
 *
 *  - complete Approved candidate resolution (never partial-set absence);
 *  - exact profile result (both public addresses must match);
 *  - authoritative absence (only explicit successful not-found);
 *  - identity contradiction (fails closed, never adoptable);
 *  - transport ambiguity (retryable, never absence, never authentication);
 *  - explicit missing-profile review (alias/visibility) and the one intent
 *    that starts registration;
 *  - atomic blockchain-authoritative metadata synchronization;
 *  - authenticated activation guarded by exact both-key indexed lookup.
 *
 * SECRET BOUNDARY: `ExactIdentityProof` (full public addresses) is restricted
 * to secret authorities and server tests. React/XState receive ONLY
 * `PublicIdentityProjection` (abbreviated addresses + opaque profile
 * reference). Nothing in this module can represent a password, mnemonic,
 * private key, transaction JSON, signature, or generic capability — and no
 * `.dat` creation/export capability exists anywhere in this module.
 *
 * Normative source: FEAT-011 FeatureDescription "Authoritative HappyPath",
 * "Terminology" (Exact identity match, Authoritative absence, Confirmed
 * identity), "Failure and Recovery Rules"; planning-analysis-report §5
 * (canonical decisions 9–11), §8.1–8.2 (convergence/lookup matrices);
 * transition-fault-matrix T1–T9.
 */

import { abbreviateAddress } from '../identity-creation/contracts';
import { validateAlias } from '../identity-creation/profile';

/** Opaque profile reference issued by the authority (never a secret or address). */
export type ProfileReference = string & { readonly __profileReference: unique symbol };

/** Opaque convergence epoch; results with a stale epoch are ignored. */
export type ConvergenceEpoch = string & { readonly __convergenceEpoch: unique symbol };

/** Immutable visibility vocabulary (existing Boolean wire value). */
export type IdentityVisibility = 'private' | 'public';

/**
 * Bounded authoritative profile metadata (server-returned, blockchain truth).
 * Used ONLY inside restricted authorities and tests; never unrestricted UI state.
 */
export interface AuthoritativeProfileMetadata {
  readonly normalizedAlias: string;
  readonly visibility: IdentityVisibility;
}

/**
 * Exact identity proof — the restricted result of a successful authoritative
 * lookup. Full public addresses live only inside the secret authority and
 * server/restricted tests. Signing-address-only success is never sufficient.
 */
export interface ExactIdentityProof extends AuthoritativeProfileMetadata {
  readonly signingAddress: string;
  readonly encryptionAddress: string;
}

/** One candidate's bounded lookup outcome (all lookups must complete). */
export type CandidateLookupOutcome =
  | { readonly kind: 'exactMatch'; readonly proof: ExactIdentityProof }
  | { readonly kind: 'explicitNotfound' };

/** Complete Approved candidate-set resolution (never order-dependent). */
export type CandidateResolution =
  | { readonly kind: 'exactMatch'; readonly proof: ExactIdentityProof }
  | { readonly kind: 'allAbsent' }
  | { readonly kind: 'multipleMatches'; readonly count: number }
  | { readonly kind: 'incomplete'; readonly completed: number; readonly total: number }
  | { readonly kind: 'contradiction'; readonly code: IdentityContradictionCode }
  | { readonly kind: 'ambiguity'; readonly reason: LookupAmbiguityReason };

/** Fail-closed contradiction codes (never offered as another identity). */
export type IdentityContradictionCode =
  | 'SIGNING_ADDRESS_MISMATCH' // returned signing differs from proven key
  | 'ENCRYPTION_ADDRESS_MISMATCH'; // signing matches, encryption differs

/** Transport/lookup ambiguity reasons — none of them is absence. */
export type LookupAmbiguityReason =
  | 'timeout'
  | 'offline'
  | 'malformedResponse'
  | 'oversizeResponse'
  | 'unknownEnum'
  | 'transportFailure'
  | 'cacheInconsistency'
  | 'partialCandidateSet';

/**
 * The one blockchain-authoritative identity decision. Only `existingIdentity`
 * and `authoritativeAbsence` are terminal lookup outcomes; everything else is
 * retryable or fail-closed and can never authenticate or create.
 */
export type IdentityLookupDecision =
  | { readonly kind: 'existingIdentity'; readonly proof: ExactIdentityProof }
  | { readonly kind: 'authoritativeAbsence' }
  | { readonly kind: 'identityContradiction'; readonly code: IdentityContradictionCode }
  | { readonly kind: 'lookupAmbiguity'; readonly reason: LookupAmbiguityReason }
  | { readonly kind: 'candidateSetIncomplete'; readonly completed: number; readonly total: number };

/** The ONLY profile data that may cross the authority boundary into UI state. */
export interface PublicIdentityProjection {
  readonly normalizedAlias: string;
  readonly visibility: IdentityVisibility;
  readonly abbreviatedSigningAddress: string;
  readonly abbreviatedEncryptionAddress: string;
  /** Opaque reference; never a full address, secret, or transaction. */
  readonly profileReference: ProfileReference;
}

/** Build the safe UI projection from a restricted proof (abbreviated addresses). */
export function projectPublicIdentity(proof: ExactIdentityProof, reference: ProfileReference): PublicIdentityProjection {
  return {
    normalizedAlias: proof.normalizedAlias,
    visibility: proof.visibility,
    abbreviatedSigningAddress: abbreviateAddress(proof.signingAddress),
    abbreviatedEncryptionAddress: abbreviateAddress(proof.encryptionAddress),
    profileReference: reference,
  };
}

/** Origin of a missing-profile review — decides review defaults. */
export type MissingProfileOrigin = 'create' | 'words' | 'credentialFile' | 'returningReset';

/**
 * Explicit missing-profile review state. Words/returning-reset start with
 * empty alias + Private visibility; credential-file may prefill authenticated
 * file metadata as review-only (never blockchain truth); create reuses the
 * already reviewed metadata. Registration starts only on explicit intent.
 */
export interface MissingProfileReview {
  readonly origin: MissingProfileOrigin;
  readonly alias: string;
  readonly visibility: IdentityVisibility;
  readonly prefillIsAuthoritative: false; // file prefill is never chain truth
  /** Same-key registration disclosure accepted by the user. */
  readonly sameIdentityAcknowledged: boolean;
}

/** Typed review intent vocabulary — only CONFIRM starts registration. */
export type MissingProfileIntent = 'REVIEW_MISSING_PROFILE' | 'CONFIRM_MISSING_PROFILE' | 'CANCEL_MISSING_PROFILE';

/**
 * Atomic blockchain-authoritative metadata synchronization (restricted).
 * Alias/visibility from the chain atomically replace safe encrypted local
 * metadata; a partial sync is unrepresentable.
 */
export interface AuthoritativeMetadataSync {
  readonly proof: ExactIdentityProof;
  readonly atomic: true;
  readonly replacesLocalMetadata: true;
}

/**
 * Authenticated activation contract. Entry into the authenticated application
 * requires exact both-key `GetIdentity` confirmation from indexed blockchain
 * state under the current epoch; local proof, acceptance, or pending status is
 * never sufficient.
 */
export interface AuthenticatedActivation {
  readonly requiresExactBothKeyIndexedLookup: true;
  readonly requiresCurrentEpoch: true;
  readonly entry: 'existingProfile' | 'registrationConfirmed';
}

/** Closed convergence failures (safe; never echo secrets or full identifiers). */
export type ConvergenceFailureCode =
  | 'INCOMPLETE_CANDIDATE_SET'
  | 'IDENTITY_CONTRADICTION'
  | 'LOOKUP_AMBIGUOUS'
  | 'METADATA_OUT_OF_BOUNDS'
  | 'STALE_EPOCH'
  | 'MISSING_EXPLICIT_CONFIRMATION'
  | 'UNKNOWN_LOOKUP_RESULT'
  | 'ACTIVATION_GUARD_FAILED'
  | 'EXPORT_UNSUPPORTED'
  | 'UNKNOWN_FAILURE';

export interface ConvergenceFailure {
  readonly ok: false;
  readonly code: ConvergenceFailureCode;
  /** Safe diagnostic text; never contains credentials, addresses, or transaction material. */
  readonly message: string;
  /** Sanitized support code (opaque, safe). */
  readonly supportCode: string;
}

export type ConvergenceResult<T> = { readonly ok: true; readonly value: T } | ConvergenceFailure;

/** Alias bounds (FEAT-007 canonical): NFC-trimmed, 1–64 grapheme clusters, ≤256 UTF-8 bytes. */
export const ALIAS_MIN_GRAPHEMES = 1;
export const ALIAS_MAX_GRAPHEMES = 64;
export const ALIAS_MAX_UTF8_BYTES = 256;

/**
 * Validate bounded authoritative metadata (returns data, never throws).
 * Reuses the FEAT-007 canonical alias validator (NFC, Intl.Segmenter grapheme
 * counting, disallowed control/bidi/invisible set) — one canonical rule.
 */
export function validateAuthoritativeMetadata(alias: string, visibility: unknown): ConvergenceResult<AuthoritativeProfileMetadata> {
  if (typeof alias !== 'string') {
    return failure('METADATA_OUT_OF_BOUNDS', 'Alias is not a string.');
  }
  if (visibility !== 'private' && visibility !== 'public') {
    return failure('METADATA_OUT_OF_BOUNDS', 'Invalid visibility.');
  }
  const aliasResult = validateAlias(alias);
  if (!aliasResult.ok) {
    return failure('METADATA_OUT_OF_BOUNDS', `Alias validation failed: ${aliasResult.message}`);
  }
  return { ok: true, value: { normalizedAlias: aliasResult.normalizedNfc, visibility } };
}

/** Closed convergence operation registry — deliberately NO export capability. */
export type ConvergenceOperationId =
  | 'startupInspection'
  | 'localProof'
  | 'resolveCandidates'
  | 'exactLookup'
  | 'reviewMissingProfile'
  | 'confirmMissingProfile'
  | 'sealAndSubmit'
  | 'reconcile'
  | 'lifecyclePromotion'
  | 'lock'
  | 'removal';

/** Compile-time proof that no generic/export surface is representable. */
export type ForbiddenConvergenceSurface = 'password' | 'mnemonic' | 'privateKey' | 'transactionJson' | 'signature' | 'fullAddress' | 'genericCapability' | 'exportAction';

/** Runtime guard: assert the projection carries no forbidden surface. */
export function assertNoSecretSurface(projection: PublicIdentityProjection): ForbiddenConvergenceSurface[] {
  const violations: ForbiddenConvergenceSurface[] = [];
  const keys = Object.keys(projection) as ReadonlyArray<keyof PublicIdentityProjection>;
  for (const key of keys) {
    if (['password', 'mnemonic', 'privateKey', 'transaction', 'signature', 'fullAddress'].includes(key)) {
      violations.push(key as ForbiddenConvergenceSurface);
    }
  }
  const json = JSON.stringify(projection);
  if (/[A-Za-z0-9+/]{40,}={0,2}/.test(json)) {
    violations.push('fullAddress');
  }
  if (json.includes('BEGIN') && json.includes('PRIVATE')) {
    violations.push('privateKey');
  }
  return violations;
}

/** Deterministic safe diagnostics for decision evaluation. */
export interface ConvergenceDiagnostic {
  readonly code: ConvergenceFailureCode | 'OK';
  readonly decisionKind: IdentityLookupDecision['kind'] | 'none';
}

/**
 * Closed decision policy — the only legal reactions to an identity decision.
 * `authenticatable`: exact both-key proof (activation guards still apply).
 * `registrationEligible`: authoritative absence only; explicit review intent required.
 * `retryable` / `failClosed`: never absence, never authentication, never creation.
 */
export type DecisionReaction = 'authenticatable' | 'registrationEligible' | 'retryable' | 'failClosed';

export function classifyLookupDecision(decision: IdentityLookupDecision): DecisionReaction {
  switch (decision.kind) {
    case 'existingIdentity':
      return 'authenticatable';
    case 'authoritativeAbsence':
      return 'registrationEligible';
    case 'lookupAmbiguity':
      return 'retryable';
    case 'candidateSetIncomplete':
      return 'retryable';
    case 'identityContradiction':
      return 'failClosed';
  }
}

/** Closed operation registry (runtime mirror of ConvergenceOperationId). */
export const CONVERGENCE_OPERATIONS: readonly ConvergenceOperationId[] = [
  'startupInspection',
  'localProof',
  'resolveCandidates',
  'exactLookup',
  'reviewMissingProfile',
  'confirmMissingProfile',
  'sealAndSubmit',
  'reconcile',
  'lifecyclePromotion',
  'lock',
  'removal',
] as const;

function failure(code: ConvergenceFailureCode, message: string, supportCode = 'CONV-0000'): ConvergenceFailure {
  return { ok: false, code, message, supportCode };
}
