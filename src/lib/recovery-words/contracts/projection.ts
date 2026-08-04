/**
 * FEAT-008 recovery-words — safe UI projection contracts.
 *
 * Framework-neutral. These are the ONLY data shapes that may cross the
 * authority boundary toward the UI. They carry word-count state, numbered
 * validation positions (never word values), safe source/network labels,
 * abbreviated public addresses, profile metadata, typed outcomes, allowed
 * actions, and coarse progress. Full public addresses exist only in explicit
 * transient reveal data, never in ordinary projection state.
 *
 * SECRET BOUNDARY: no projection can represent a phrase word, seed, private
 * key, Device password, WebAuthn PRF output, wrapping key, full address,
 * credential ID, transaction, signature, or complete candidate linkage.
 *
 * Normative source: FEAT-008 FeatureDescription "Recovery-Word Entry
 * Contract" (word visibility/validation feedback), "Candidate Outcome UX",
 * "Initial Protection Choice", "Encrypted Derived-Key Staging", "Restart and
 * Resume", "Navigation and History", "Concurrency and Ownership",
 * "Accessibility and Responsive UX"; FEAT-007 creation presentation
 * vocabulary; FEAT-002 safe projections.
 */
import type { ProtectionMode } from './envelope.js';
import type {
  NetworkIdentifier,
  RecoveryFailure,
  RecoveryStage,
} from './lifecycle.js';

/** Abbreviate a public address to `<first 8>…<last 6>` (design baseline). */
export function abbreviateAddress(address: string): string {
  if (address.length <= 14) {
    return address;
  }
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

/**
 * Word-grid projection — numbered validity state only. NEVER carries word
 * values: the dedicated DOM-owned input buffers are the only phrase holders.
 */
export interface WordGridProjection {
  readonly selectedWordCount: '12' | '24' | null; // no count selected initially
  readonly invalidPositions: readonly number[]; // 1-based numbered positions; no echoed values
  readonly countValid: boolean;
  readonly vocabularyValid: boolean;
  readonly checksumState: 'notRun' | 'pending' | 'passed' | 'failed'; // checksum runs inside the authority
  readonly allConcealed: boolean; // focused visible; completed unfocused concealed
  readonly busy: boolean; // exactly one authority operation in flight
  readonly canVerify: boolean; // Verify enabled only when count/vocabulary locally valid
  readonly errorSummary: ReadonlyArray<{
    readonly code: 'WRONG_COUNT' | 'UNKNOWN_WORD' | 'UNSUPPORTED_INPUT';
    readonly positions: readonly number[];
  }>;
  readonly pasteReplacementPending: boolean; // explicit whole-grid replacement confirmation
}

/** Safe candidate-review entry — one exact address pair with provenance. */
export interface CandidateReviewEntry {
  readonly candidateIndex: number; // deterministic precedence order
  readonly sourceLabel: string; // human-readable origin/application/version-era label
  readonly abbreviatedSigningAddress: string;
  readonly abbreviatedEncryptionAddress: string;
  readonly producerIds: readonly string[]; // provenance after dedup
  readonly profileAlias: string | null; // blockchain-authoritative when present
  readonly visibility: 'private' | 'public' | null; // blockchain-authoritative when present
  readonly selected: boolean; // never preselected by default
}

/**
 * Candidate/profile review projection. Exposes safe labels and abbreviated
 * addresses only; full addresses are an explicit transient reveal.
 */
export interface CandidateReviewProjection {
  readonly outcome: 'exactlyOneExisting' | 'multipleExisting' | 'zeroExistingOneCandidate' | 'zeroExistingMultipleCandidates';
  readonly entries: readonly CandidateReviewEntry[];
  readonly networkLabel: string;
  readonly selectionRequired: boolean; // no default selection ever
  readonly uncertainGuidance: string | null; // "I'm not sure" guidance for zero-match source-guided selection
  readonly revealState: {
    readonly revealedCandidateIndex: number | null; // transient explicit full-address reveal
    readonly fullSigningAddress: string | null; // transient; labelled public; never persisted in state
    readonly fullEncryptionAddress: string | null; // transient; labelled public
  };
  readonly busy: boolean;
}

/**
 * Protection-choice projection — reflects platform qualification without
 * revealing any secret. Device-password protection is checked by default and
 * may be unchecked only into a qualified passwordless/session-only path.
 */
export interface ProtectionProjection {
  readonly defaultPasswordChecked: boolean;
  readonly allowedModes: readonly ProtectionMode[]; // qualified, versioned, fail-closed
  readonly sessionOnlyAcknowledgementRequired: boolean;
  readonly passwordlessQualified: boolean;
  readonly platformHints: ReadonlyArray<'webauthn-platform-required' | 'secret-service-required' | 'hardware-keystore-required' | 'secure-lock-required'>;
  readonly busy: boolean;
}

/**
 * Staged-restore preview — the ONLY data exposed while a staged identity
 * exists. Non-authenticated, blocks Create/Restore, never reveals or
 * reconstructs the discarded words.
 */
export interface StagedPreviewProjection {
  readonly stage: 'finishRestoring';
  readonly nonAuthenticated: true;
  readonly blocksCreateRestore: true;
  readonly protectionMode: ProtectionMode; // how the stage will be unlocked
  readonly abbreviatedSigningAddress: string;
  readonly abbreviatedEncryptionAddress: string;
  readonly networkLabel: string;
  readonly corrupted: boolean; // corruption/unsupported version → fail closed
}

/**
 * Whole-recovery view projection — one closed view per authority state with
 * deterministic allowed actions and focus destinations.
 */
export interface RecoveryViewProjection {
  readonly stage: RecoveryStage;
  readonly progress: number; // coarse 0..1 within the current stage
  readonly coarseCount: { readonly done: number; readonly total: number } | null; // safe counted progress ("2 of 4")
  readonly networkLabel: string | null;
  readonly busy: boolean;
  readonly allowedActions: readonly RecoveryAction[];
  readonly errorSummary: ReadonlyArray<{
    readonly code: RecoveryFailure['code'];
    readonly positions?: readonly number[]; // numbered input positions; never values
  }>;
  readonly focusFirstInvalidPosition: number | null;
  readonly ownerState: 'owner' | 'blockedByOtherOwner' | 'awaitingRelease';
}

/** Closed set of user actions the current view may dispatch. */
export type RecoveryAction =
  | 'selectWordCount'
  | 'pastePhrase'
  | 'confirmPasteReplacement'
  | 'cancelPasteReplacement'
  | 'clearAll'
  | 'toggleShowAll'
  | 'verify'
  | 'retryUnresolvedLookups'
  | 'selectCandidate'
  | 'revealFullAddress'
  | 'concealFullAddress'
  | 'copyFullAddress'
  | 'confirmExistingProfile'
  | 'chooseProtectionMode'
  | 'acknowledgeNoRetention'
  | 'confirmRecreateProfile'
  | 'submitRegistration'
  | 'cancelRecovery'
  | 'back'
  | 'lock'
  | 'removeLocalUser'
  | 'finishRestoringUnlock'
  | 'retry';

/**
 * Runtime check that a projection carries no forbidden secret surface.
 * Used by tests and by composition guards in later phases.
 */
export function assertNoRecoverySecretSurface(projection: unknown): string[] {
  const violations: string[] = [];
  const json = JSON.stringify(projection ?? null);
  if (!json) {
    return violations;
  }
  const forbidden = [
    'mnemonic',
    'seed',
    'privateKey',
    'devicePassword',
    'prfOutput',
    'wrappingKey',
    'credentialId',
    'transactionJson',
    'signature',
  ] as const;
  for (const key of forbidden) {
    if (json.toLowerCase().includes(`"${key}"`)) {
      violations.push(key);
    }
  }
  // Ordinary projection state may carry full addresses ONLY inside the
  // transient revealState block. Detect accidental widening elsewhere.
  const withoutReveal = json.replace(/("revealState"[^}]*})/g, '{}');
  if (withoutReveal.includes('fullSigningAddress') || withoutReveal.includes('fullEncryptionAddress')) {
    violations.push('fullAddress');
  }
  return violations;
}

/** Re-export for consumers that need the branded network identifier type. */
export type { NetworkIdentifier };
