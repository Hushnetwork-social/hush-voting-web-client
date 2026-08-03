/**
 * FEAT-007 identity-creation — candidate generation and recovery
 * confirmation authority.
 *
 * Platform-neutral policy for the Create User secret journey. The actual P-01
 * generation, entropy, mnemonic custody, and signing live inside the sealed
 * platform authority (browser worker / Ubuntu / Android). This module owns the
 * workflow rules: preflight gating, explicit generation, hidden-candidate
 * destruction, bounded 24-word reveal, six-position unpredictable challenge,
 * three-attempt invalidation, regeneration with destructive confirmation, and
 * concealment triggers. No secret value is representable here — the machine
 * holds only opaque candidate references and safe projections.
 *
 * Normative source: FEAT-007 FeatureDescription "Create User Journey" steps
 * 1–5, "P-01 Identity Generation Contract", "Accessibility and Responsive UX",
 * "Performance and Resource Budgets"; EPIC-001 design baseline wireframes
 * 1–4.
 */

/** Opaque reference to a candidate held inside the sealed authority. */
export type CandidateRef = string & { readonly __candidateRef: unique symbol };

/** Preflight outcome of the active platform security/persistence check. */
export type PreflightOutcome =
  | { readonly kind: 'passed' }
  | { readonly kind: 'unsupported'; readonly code: 'UNSUPPORTED_PLATFORM' | 'UNSAFE_CAPABILITY' }
  | { readonly kind: 'temporaryUnavailable' }
  | { readonly kind: 'failClosed' };

/** Generation policy timings (FeatureDescription budgets). */
export const GENERATION_PROGRESS_THRESHOLD_MS = 150 as const;
export const GENERATION_HARD_BOUND_MS = 10_000 as const;
export const REVEAL_MAX_MS = 60_000 as const;
export const RECOVERY_MAX_ATTEMPTS = 3 as const;
export const RECOVERY_CHALLENGE_POSITIONS = 6 as const;

export type GenerationOutcome =
  | { readonly kind: 'generated'; readonly candidateRef: CandidateRef }
  | { readonly kind: 'hiddenCandidateDestroyed' } // invalid scalar retry path (internal)
  | { readonly kind: 'timeout' }
  | { readonly kind: 'exhausted' }
  | { readonly kind: 'authorityRevoked' }
  | { readonly kind: 'failClosed' };

/** Concealment trigger — any of these removes visual + accessibility content. */
export type ConcealTrigger = 'timeout' | 'back' | 'routeChange' | 'lifecycleLoss' | 'lock' | 'regeneration' | 'authorityRevoked';

/** Deterministic reveal policy evaluation. */
export interface RevealDecision {
  readonly visible: boolean;
  readonly reason: 'active' | 'revealed' | 'concealed';
  readonly trigger: ConcealTrigger | null;
}

/** Recovery challenge state machine (position-only mismatch, three attempts). */
export type RecoveryChallengeState =
  | { readonly status: 'pending'; readonly positions: readonly number[]; readonly attemptsRemaining: number }
  | { readonly status: 'passed' }
  | { readonly status: 'invalidated' };

export type RecoveryAttemptResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly mismatchPosition: number; readonly attemptsRemaining: number }
  | { readonly ok: false; readonly invalidated: true };

/** Sealed generation port (implemented by browser worker / native authority). */
export interface CandidateGenerationPort {
  preflight(): Promise<PreflightOutcome>;
  /** Explicit user action only; creates exactly one valid P-01 candidate. */
  generate(): Promise<GenerationOutcome>;
  /** Destroy a hidden invalid candidate; never repairs or reveals it. */
  destroyHiddenCandidate(): Promise<void>;
  /** Destructive regeneration: destroys the complete old candidate. */
  regenerateWithConfirmation(confirmed: true): Promise<GenerationOutcome>;
  /** Explicit bounded reveal (words leave the authority only through this). */
  revealWords(candidateRef: CandidateRef): Promise<{ readonly ok: true } | { readonly ok: false; readonly code: 'REVOKED' | 'EXPIRED' }>;
  conceal(trigger: ConcealTrigger): Promise<void>;
  destroyCandidate(candidateRef: CandidateRef): Promise<void>;
}

/** Pure CSPRNG shuffle over indices (Fisher–Yates). */
export function secureShuffle(count: number): number[] {
  if (count <= 0) {
    return [];
  }
  const indices = Array.from({ length: count }, (_, i) => i);
  const bytes = new Uint8Array(count * 4);
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new Error('crypto.getRandomValues unavailable');
  }
  for (let i = count - 1; i > 0; i--) {
    const j = bytes[i * 4] % (i + 1);
    const tmp = indices[i]!;
    indices[i] = indices[j]!;
    indices[j] = tmp;
  }
  return indices;
}

/**
 * Select six unpredictable distinct positions (1-based word indices) and
 * randomize their display order. `wordCount` must be 24 (new creation).
 */
export function selectChallengePositions(wordCount: number, positionCount: number = RECOVERY_CHALLENGE_POSITIONS): number[] {
  if (wordCount < positionCount) {
    throw new Error('wordCount must be >= challenge positions');
  }
  const shuffled = secureShuffle(wordCount);
  const positions = shuffled.slice(0, positionCount).map((p) => p + 1);
  // Randomize display order too.
  const display = secureShuffle(positionCount).map((i) => positions[i]!);
  return display;
}

/** Evaluate one recovery attempt: mismatch identifies only the requested position. */
export function evaluateRecoveryAttempt(positions: readonly number[], provided: ReadonlyMap<number, string>, expected: ReadonlyMap<number, string>): RecoveryAttemptResult {
  for (const pos of positions) {
    const given = provided.get(pos);
    const want = expected.get(pos);
    if (given !== want) {
      return { ok: false, mismatchPosition: pos, attemptsRemaining: 0 }; // attempts bookkeeping handled by state
    }
  }
  return { ok: true };
}

/** Advance the challenge state after one attempt. */
export function advanceChallenge(state: RecoveryChallengeState, attemptResult: RecoveryAttemptResult): RecoveryChallengeState {
  if (state.status !== 'pending') {
    return state;
  }
  if (attemptResult.ok) {
    return { status: 'passed' };
  }
  if ('invalidated' in attemptResult && attemptResult.invalidated) {
    return { status: 'invalidated' };
  }
  const remaining = state.attemptsRemaining - 1;
  if (remaining <= 0) {
    return { status: 'invalidated' };
  }
  return { status: 'pending', positions: state.positions, attemptsRemaining: remaining };
}

/** Create the initial pending challenge. */
export function beginChallenge(wordCount: number): RecoveryChallengeState {
  return { status: 'pending', positions: selectChallengePositions(wordCount), attemptsRemaining: RECOVERY_MAX_ATTEMPTS };
}

/** Reveal policy: visible only while an active reveal epoch is live and under the 60 s bound. */
export function revealDecision(revealedAtMs: number | null, nowMs: number, trigger: ConcealTrigger | null): RevealDecision {
  if (trigger !== null) {
    return { visible: false, reason: 'concealed', trigger };
  }
  if (revealedAtMs === null) {
    return { visible: false, reason: 'active', trigger: null };
  }
  if (nowMs - revealedAtMs > REVEAL_MAX_MS) {
    return { visible: false, reason: 'concealed', trigger: 'timeout' };
  }
  return { visible: true, reason: 'revealed', trigger: null };
}
