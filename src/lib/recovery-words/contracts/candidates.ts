/**
 * FEAT-008 recovery-words — candidate lookup, selection, proof, and profile
 * contracts.
 *
 * Framework-neutral. Defines deterministic complete-lookup state, per-candidate
 * public outcomes, zero/one/multiple resolution, explicit no-default selection,
 * selected-key proof evidence, historical alias safety, and exact profile
 * matching. Candidate outcomes remain authority-memory-only; full public
 * addresses exist only in explicit transient reveal data.
 *
 * SECRET BOUNDARY: no private credential, phrase, seed, or full candidate
 * linkage crosses this module. Public candidates carry exact encoded public
 * addresses (used for lookup only); private derivation happens inside the
 * authority after explicit selection.
 *
 * Normative source: FEAT-008 FeatureDescription "Approved Historical Candidate
 * Resolution", "Candidate Outcome UX", "Selected-Key Control Proof",
 * "Complete lookup requirement", "No client caching"; FEAT-001
 * identity-compatibility candidate API; FEAT-007 wire normalization.
 */
import type {
  DerivedCandidates,
  LookupResult,
  PublicCandidateDescriptor,
} from '../../identity-compatibility/types';
import type { NetworkIdentifier, RecoveryEpoch, RecoveryResult } from './lifecycle';

/** Per-candidate public lookup outcome (authority-memory-only). */
export type CandidateLookupOutcome =
  | {
      readonly kind: 'exactProfile'; // exact signing AND encryption address match
      readonly profileAlias: string;
      readonly visibility: 'private' | 'public';
    }
  | {
      readonly kind: 'authoritativeNotFound'; // authoritative not-found for the bound network
    }
  | {
      readonly kind: 'unresolved'; // timeout/transport/malformed/contradictory — NEVER absence
      readonly reason: 'timeout' | 'transport' | 'malformed' | 'contradictory';
    };

/**
 * Complete-lookup state held inside the authority epoch. Every distinct
 * applicable candidate must receive an exact-profile or authoritative-not-found
 * outcome before resolution; unresolved outcomes keep resolution incomplete.
 */
export interface CandidateLookupState {
  readonly epoch: RecoveryEpoch;
  readonly networkIdentifier: NetworkIdentifier;
  /** Deterministic FEAT-001 precedence order; deduplicated exact-address pairs. */
  readonly candidates: readonly PublicCandidateDescriptor[];
  readonly outcomes: ReadonlyMap<number, CandidateLookupOutcome>; // keyed by candidate index
  readonly startedAtEpochMs: number; // monotonic authority start
}

/** Resolution is possible only when EVERY candidate is resolved. */
export function isLookupComplete(state: CandidateLookupState): boolean {
  return state.candidates.every((_, index) => state.outcomes.has(index));
}

/** Transport failure is never absence: unresolved counts as incomplete. */
export function unresolvedCandidateIndices(state: CandidateLookupState): readonly number[] {
  const indices: number[] = [];
  for (let index = 0; index < state.candidates.length; index += 1) {
    const outcome = state.outcomes.get(index);
    if (!outcome || outcome.kind === 'unresolved') {
      indices.push(index);
    }
  }
  return indices;
}

/**
 * Immutable outcome recording — returns a new state with the outcome bound to
 * the candidate index. The authority uses this while completing lookups;
 * partial outcome sets keep resolution incomplete.
 */
export function recordLookupOutcome(state: CandidateLookupState, candidateIndex: number, outcome: CandidateLookupOutcome): CandidateLookupState {
  const outcomes = new Map(state.outcomes);
  outcomes.set(candidateIndex, outcome);
  return { ...state, outcomes };
}

/** Deterministic resolution verdict — never concludes from a partial set. */
export type RecoveryResolutionVerdict =
  | { readonly kind: 'incomplete'; readonly unresolvedIndices: readonly number[] }
  | { readonly kind: 'zero'; readonly candidates: readonly PublicCandidateDescriptor[] }
  | { readonly kind: 'one'; readonly candidateIndex: number; readonly profileAlias: string; readonly visibility: 'private' | 'public' }
  | {
      readonly kind: 'multiple';
      readonly entries: ReadonlyArray<{
        readonly candidateIndex: number;
        readonly profileAlias: string;
        readonly visibility: 'private' | 'public';
      }>;
    };

/**
 * Complete deterministic resolution. Exact profile requires BOTH public
 * addresses to match (signing-only match fails closed). Zero means every
 * candidate is authoritatively absent. Multiple means more than one distinct
 * exact profile matched (no default selection).
 */
export function resolveLookup(state: CandidateLookupState): RecoveryResolutionVerdict {
  const unresolved = unresolvedCandidateIndices(state);
  if (unresolved.length > 0) {
    return { kind: 'incomplete', unresolvedIndices: unresolved };
  }
  const matches: Array<{ candidateIndex: number; profileAlias: string; visibility: 'private' | 'public' }> = [];
  for (let index = 0; index < state.candidates.length; index += 1) {
    const outcome = state.outcomes.get(index);
    if (outcome && outcome.kind === 'exactProfile') {
      matches.push({ candidateIndex: index, profileAlias: outcome.profileAlias, visibility: outcome.visibility });
    }
  }
  if (matches.length === 0) {
    return { kind: 'zero', candidates: state.candidates };
  }
  if (matches.length === 1) {
    const only = matches[0];
    return {
      kind: 'one',
      candidateIndex: only.candidateIndex,
      profileAlias: only.profileAlias,
      visibility: only.visibility,
    };
  }
  return { kind: 'multiple', entries: matches };
}

/** Exact-profile matching rule: signing AND encryption equality is mandatory. */
export function isExactProfileMatch(candidate: PublicCandidateDescriptor, signingAddress: string, encryptionAddress: string): boolean {
  return candidate.signingAddress === signingAddress && candidate.encryptionAddress === encryptionAddress;
}

/** Source-guided selection contract — never preselected, explicit only. */
export interface CandidateSelectionContract {
  readonly epoch: RecoveryEpoch;
  readonly selectedCandidateIndex: number;
  /** Provenance labels after dedup (deterministic precedence order). */
  readonly producerIds: readonly string[];
}

/**
 * Selected-key control proof evidence. The authority proves, locally:
 * 1. signing public key/address re-derived from the selected signing private key;
 * 2. encryption public key/address re-derived from the selected encryption private key;
 * 3. byte/string-exact equality with the selected candidate encodings;
 * 4. domain-separated ephemeral challenge sign+verify;
 * 5. FEAT-001 approved encryption pair operation/vector behavior.
 * No key, phrase, seed, or challenge is ever sent to HushServerNode.
 */
export interface SelectedKeyProofEvidence {
  readonly epoch: RecoveryEpoch;
  readonly producerId: string;
  readonly bothKeyExact: boolean; // exact signing AND encryption equality
  readonly challengeValidated: boolean; // domain-separated local sign+verify
  readonly vectorValidated: boolean; // FEAT-001 approved operation/vector behavior
  readonly completedAtEpochMs: number;
}

export function isProofPassed(proof: SelectedKeyProofEvidence): boolean {
  return proof.bothKeyExact && proof.challengeValidated && proof.vectorValidated;
}

/** Existing-profile activation contract (blockchain metadata authoritative). */
export interface ExistingProfileActivationContract {
  readonly epoch: RecoveryEpoch;
  readonly networkIdentifier: NetworkIdentifier;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly authoritativeAlias: string;
  readonly authoritativeVisibility: 'private' | 'public';
  /** Historical aliases render escaped with Unicode isolation; never rewritten during restore. */
  readonly historicalAliasCompatibilitySafe: boolean;
}

/** Missing-profile recreation review (alias empty, visibility Private by default). */
export interface MissingProfileReviewContract {
  readonly epoch: RecoveryEpoch;
  readonly networkIdentifier: NetworkIdentifier;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly reviewAlias: string; // starts empty; user-provided
  readonly reviewVisibility: 'private' | 'public'; // defaults to 'private'
  readonly publicAcknowledgementRequired: boolean; // Public exposure/permanence acknowledgement
  readonly usesExactRecoveredKeys: true; // never generates replacement words or a different identity
}

/**
 * Deterministic candidate-set sanity checks consumed by the authority:
 * the complete set must derive from every applicable Approved producer in
 * precedence order, and must not be partial.
 */
export function validateCompleteCandidateSet(derived: DerivedCandidates, applicableProducerIds: readonly string[]): RecoveryResult<{ readonly candidateCount: number }> {
  const derivedIds = new Set(derived.candidates.flatMap((candidate) => candidate.producerIds));
  const missing = applicableProducerIds.filter((producerId) => !derivedIds.has(producerId));
  if (missing.length > 0) {
    return {
      ok: false,
      code: 'PRODUCER_DERIVATION_FAILURE',
      message: 'Candidate derivation is incomplete; the complete set is rejected.',
      supportCode: 'RW-PRODUCER-1',
    };
  }
  return { ok: true, value: { candidateCount: derived.candidates.length } };
}

/** Re-export the sealed FEAT-001 lookup type for downstream consumers. */
export type { LookupResult };
