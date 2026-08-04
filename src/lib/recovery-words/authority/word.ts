/**
 * FEAT-008 recovery-words authority — bounded word validation and candidate
 * derivation policy.
 *
 * Framework-neutral. Owns the workflow rules for verified-empty entry, one
 * authority operation at a time, NFKD/case/whitespace normalization, 12/24
 * vocabulary/checksum validation, every applicable Approved public candidate,
 * deduplication, safe progress, and the 10-minute foreground custody epoch.
 * The actual BIP-39 validation and key derivation live inside the sealed
 * platform authority (browser worker / Ubuntu / Android) through
 * `MnemonicDerivationPort`; this module never holds the phrase itself beyond
 * the single bounded `verifyAndDerive` call.
 *
 * SECRET BOUNDARY: the phrase enters this module only as one bounded string
 * parameter and is never stored, logged, or projected. Outputs are public
 * candidate descriptors and typed outcomes.
 *
 * Normative source: FEAT-008 FeatureDescription "Recovery-Word Entry
 * Contract", "Transient Mnemonic Custody and No-Persistence Rule", "Approved
 * Historical Candidate Resolution", "Attempt control", "Performance and
 * Resource Budgets"; FEAT-001 identity-compatibility API.
 */
import type { DerivedCandidates, PublicCandidateDescriptor } from '../../identity-compatibility/types';
import { deriveCandidates } from '../../identity-compatibility/candidates';
import type { RecoveryFailure, RecoveryResult } from '../contracts/lifecycle';
import { validateCompleteCandidateSet } from '../contracts/candidates';

/** Unprovisioned foreground authority epoch (maximum 10 minutes). */
export const RECOVERY_EPOCH_MAX_MS = 600_000 as const;
/** Show derivation/lookup/provisioning progress after this threshold. */
export const PROGRESS_THRESHOLD_MS = 150 as const;
/** Small fixed minimum interval between authority commands (CPU/UI bound). */
export const VERIFY_MIN_INTERVAL_MS = 50 as const;

/** Supported word counts (exactly 12 or 24; never 15/18/21). */
export type SupportedWordCount = 12 | 24;

/** Word-grid policy state (numbered positions only; never word values). */
export interface WordGridPolicyState {
  readonly selectedWordCount: SupportedWordCount | null; // no count selected initially
  readonly positions: ReadonlyArray<{
    readonly index: number; // 1-based
    readonly filled: boolean;
    readonly locallyValid: boolean; // vocabulary-level check; checksum runs inside authority
  }>;
  readonly allConcealed: boolean;
  readonly pasteReplacementPending: boolean;
  readonly lastCommandAtMs: number | null; // attempt-interval enforcement
}

/**
 * NFKD/case/whitespace normalization per the Recovery-Word Entry Contract:
 * NFKD normalize, trim, locale-independent lowercase, treat
 * spaces/tabs/CR/LF as separators, collapse repeated separators, rejoin with
 * one ASCII space. Normalization never turns an unknown word into a known
 * word.
 */
export function normalizePhrase(input: string): string {
  const nfkd = input.normalize('NFKD');
  const lowered = nfkd.toLowerCase();
  const words = lowered.split(/[ \t\r\n]+/).filter((word) => word.length > 0);
  return words.join(' ');
}

/** Count normalized words without mutating the phrase. */
export function countNormalizedWords(normalized: string): number {
  if (normalized.length === 0) {
    return 0;
  }
  return normalized.split(' ').length;
}

/** Map a FEAT-001 compatibility failure code to the FEAT-008 closed vocabulary. */
export function mapMnemonicFailure(code: RecoveryFailure['code'] | string): RecoveryFailure['code'] {
  switch (code) {
    case 'INVALID_WORD_COUNT':
      return 'WRONG_COUNT';
    case 'UNKNOWN_WORD':
      return 'UNKNOWN_WORD';
    case 'INVALID_CHECKSUM':
      return 'CHECKSUM_FAILURE';
    case 'UNSUPPORTED_PASSPHRASE':
    case 'UNSUPPORTED_PRODUCER':
    case 'UNSUPPORTED_VERSION':
      return 'UNSUPPORTED_INPUT';
    case 'DERIVATION_FAILURE':
    case 'INVALID_PRIVATE_SCALAR':
    case 'INVALID_KEY_ENCODING':
      return 'PRODUCER_DERIVATION_FAILURE';
    default:
      return 'UNKNOWN_OUTCOME';
  }
}

/**
 * Sealed derivation seam. The browser worker / Ubuntu / Android authority
 * implements this with the approved producer contracts; FEAT-008 never derives
 * Unsupported/Unverified/test-only/undocumented algorithms.
 */
export interface MnemonicDerivationPort {
  /** Validate + derive every applicable Approved public candidate. */
  derive(normalizedPhrase: string): RecoveryResult<DerivedCandidates>;
}

/** Production adapter over the FEAT-001 Approved candidate API. */
export function createFeat001DerivationPort(): MnemonicDerivationPort {
  return {
    derive(normalizedPhrase: string): RecoveryResult<DerivedCandidates> {
      const result = deriveCandidates(normalizedPhrase);
      if (!result.ok) {
        return { ok: false, code: mapMnemonicFailure(result.code), message: 'Candidate derivation failed.', supportCode: 'RW-DERIVE-1' };
      }
      return { ok: true, value: result.value };
    },
  };
}

/**
 * Bounded Verify handoff policy: one command in flight, minimum interval,
 * epoch deadline. Returns the derived public candidate set or a typed
 * failure. On any unexpected applicable-producer failure the complete set is
 * rejected (fail closed) and the caller must clear all secret state.
 */
export function verifyAndDerive(
  port: MnemonicDerivationPort,
  rawPhrase: string,
  applicableProducerIds: readonly string[],
  nowMs: number,
  lastCommandAtMs: number | null,
): RecoveryResult<{ readonly candidates: readonly PublicCandidateDescriptor[]; readonly rejectedProducers: DerivedCandidates['rejectedProducers'] }> {
  if (lastCommandAtMs !== null && nowMs - lastCommandAtMs <= VERIFY_MIN_INTERVAL_MS) {
    return { ok: false, code: 'DOUBLE_DISPATCH', message: 'Another validation command is already in flight.', supportCode: 'RW-OP-1' };
  }
  const normalized = normalizePhrase(rawPhrase);
  const wordCount = countNormalizedWords(normalized);
  if (wordCount !== 12 && wordCount !== 24) {
    return { ok: false, code: 'WRONG_COUNT', message: 'Supported phrases are exactly 12 or 24 words.', supportCode: 'RW-COUNT-1' };
  }
  const derived = port.derive(normalized);
  if (!derived.ok) {
    return derived;
  }
  const complete = validateCompleteCandidateSet(derived.value, applicableProducerIds);
  if (!complete.ok) {
    return complete;
  }
  return {
    ok: true,
    value: { candidates: derived.value.candidates, rejectedProducers: derived.value.rejectedProducers },
  };
}

/** Epoch custody: unprovisioned authority may last at most 10 foreground minutes. */
export function createEpochDeadline(startedAtMs: number): number {
  return startedAtMs + RECOVERY_EPOCH_MAX_MS;
}

export function isEpochExpired(deadlineMs: number, nowMs: number): boolean {
  return nowMs > deadlineMs;
}

/** Lifecycle/concealment events that must clear page + authority phrase state. */
export type RecoveryClearEvent = 'back' | 'lock' | 'lifecycleLoss' | 'cancellation' | 'timeout' | 'ownershipLoss' | 'networkChange';

/** Deterministic clear policy — any of these destroys transient secret state. */
export function mustClearOn(event: RecoveryClearEvent, stage: 'preVerify' | 'postVerify' | 'staged'): boolean {
  // Network change invalidates the complete lookup/selection/stage and
  // requires fresh word entry at EVERY stage (canonical network binding).
  if (event === 'networkChange') {
    return true;
  }
  if (stage === 'staged') {
    // Staged keys persist; Back locks instead of destroying. Lifecycle loss
    // still clears the *session*; the encrypted stage survives for resume.
    return event === 'lock' || event === 'lifecycleLoss' || event === 'ownershipLoss';
  }
  return true; // pre- and post-Verify transient phrase/candidate state clears on any event
}
