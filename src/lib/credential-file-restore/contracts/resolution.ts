/**
 * FEAT-009 credential-file restore — profile resolution and exact identity
 * lookup contracts.
 *
 * Framework-neutral. Defines the closed vocabulary for resolving the
 * validated concrete keys against the unchanged unsigned public
 * `GetIdentity` lookup: typed lookup outcomes, exact both-key binding,
 * signing-only mismatch, authoritative not-found vs transport/malformed,
 * missing-profile review metadata, and FEAT-007 exact-key recreation
 * obligations. Connectivity is never not-found; imported metadata never
 * mutates an existing chain profile.
 *
 * SECRET BOUNDARY: no resolution contract carries private keys, source
 * identifiers, passwords, plaintext, mnemonic, or full ordinary addresses
 * beyond explicit abbreviated review fields.
 *
 * Normative source: FEAT-009 FeatureDescription "Identity Resolution",
 * "Missing Profile After Reset/Never Registered", "Missing-Profile
 * Transaction", "Security and Privacy Requirements"; FEAT-007 lookup/
 * profile normalizers; unchanged HushServerNode `GetIdentity` contract.
 */

/** Closed public-lookup outcome (unsigned; public signing address only). */
export type LookupOutcome =
  | { readonly kind: 'existing'; readonly profile: ResolvedChainProfile } // exact both-key match
  | { readonly kind: 'authoritativeNotFound' } // typed not-found; only path to missing-profile review
  | { readonly kind: 'signingOnlyMatch' } // signing match, different encryption address; fail closed
  | { readonly kind: 'transportFailure' } // connectivity; never creation
  | { readonly kind: 'malformed' } // gross malformed/oversized response; fail closed
  | { readonly kind: 'unknownStatus' }; // unknown/contradictory; fail closed

/** Bounded chain-authoritative profile (metadata is authoritative). */
export interface ResolvedChainProfile {
  readonly alias: string; // escaped/isolated/bounded rendering contract
  readonly isPublic: boolean;
  readonly signingAddress: string; // exact match required (full value inside authority)
  readonly encryptionAddress: string; // exact match required
  readonly networkLabel: string;
}

/** Missing-profile review metadata (authenticated backup metadata may prefill). */
export interface MissingProfileReview {
  readonly authenticatedProfileName: string; // prefill candidate; current alias rules apply
  readonly authenticatedIsPublic: boolean; // reviewable; Public requires exposure acknowledgement
  readonly signingAddressAbbreviated: string;
  readonly encryptionAddressAbbreviated: string;
  readonly networkLabel: string;
  readonly requiresExplicitCreate: true; // "Create HushNetwork identity" explicit action only
}

/** Profile resolution result. */
export type ResolutionResult =
  | { readonly kind: 'existing'; readonly profile: ResolvedChainProfile }
  | { readonly kind: 'missing'; readonly review: MissingProfileReview }
  | { readonly kind: 'signingOnlyMatch' }
  | { readonly kind: 'transportFailure' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'unknownStatus' };

/** FEAT-007 closed missing-profile transaction statuses (unchanged vocabulary). */
export type CreationTransactionStatus =
  | 'ACCEPTED'
  | 'PENDING'
  | 'ALREADY_EXISTS'
  | 'REJECTED'
  | 'INVALID_PROOF' // HushServerNode invalid-signature/identity-proof; distinct from lookup failure
  | 'TIMEOUT'
  | 'CONFIRMED' // exact block confirmation; the only activation truth for missing profiles
  | 'UNKNOWN';

/** Closed recreation outcome (exact imported keys only; never new keys). */
export type RecreationOutcome =
  | { readonly kind: 'confirmed' } // exact block confirmation; activation allowed
  | { readonly kind: 'accepted' } // mempool acceptance; NOT success
  | { readonly kind: 'pending' } // polling in progress (3s cadence; 3min abnormal delay)
  | { readonly kind: 'alreadyExists' } // same-key profile exists; re-resolve exact
  | { readonly kind: 'rejected'; readonly code: CreationTransactionStatus } // stable safe code only
  | { readonly kind: 'invalidProof' } // distinct safe HushServerNode rejection message
  | { readonly kind: 'timeout' }
  | { readonly kind: 'unknown' };

export const LOOKUP_RPC_TIMEOUT_MS = 10_000;
export const PROFILE_POLL_INTERVAL_MS = 3_000;
export const PROFILE_ABNORMAL_DELAY_MS = 3 * 60_000;
