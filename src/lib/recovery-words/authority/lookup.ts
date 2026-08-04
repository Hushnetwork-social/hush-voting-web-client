/**
 * FEAT-008 recovery-words authority — complete public lookup and candidate
 * resolution policy.
 *
 * Framework-neutral. Queries every distinct applicable candidate sequentially
 * with a per-request transport bound, retains bounded in-epoch public
 * outcomes, retries unresolved candidates only, and produces zero/one/multiple
 * review states only after the complete set resolves. Transport failure is
 * never profile absence; partial resolution never permits selection or
 * profile creation.
 *
 * SECRET BOUNDARY: only public candidate descriptors cross this module.
 * Outcomes are authority-memory-only and cleared at epoch end/completion.
 * The actual transport is injected through `RecoveryLookupPort` (browser BFF
 * POST / native gRPC implemented in Phase 6).
 *
 * Normative source: FEAT-008 FeatureDescription "Complete lookup
 * requirement", "Safe progress", "No client caching", "Candidate Outcome UX",
 * "Error Model"; FEAT-007 transport normalization.
 */
import type { PublicCandidateDescriptor } from '../../identity-compatibility/types';
import type { NetworkIdentifier, RecoveryEpoch, RecoveryResult } from '../contracts/lifecycle';
import type { CandidateLookupOutcome } from '../contracts/candidates';
import { recordLookupOutcome, resolveLookup, type CandidateLookupState } from '../contracts/candidates';

/** Per-candidate request timeout (shared 10-second bound). */
export const LOOKUP_REQUEST_TIMEOUT_MS = 10_000 as const;
/** Safe counted progress appears only after this threshold. */
export const LOOKUP_PROGRESS_THRESHOLD_MS = 150 as const;

/** Sealed lookup seam (browser BFF / native approved gRPC in Phase 6). */
export interface RecoveryLookupPort {
  lookupCandidate(candidate: PublicCandidateDescriptor, networkIdentifier: NetworkIdentifier): Promise<CandidateLookupOutcome>;
}

/** Create an empty complete-lookup state for the epoch/network. */
export function beginLookup(
  epoch: RecoveryEpoch,
  networkIdentifier: NetworkIdentifier,
  candidates: readonly PublicCandidateDescriptor[],
  startedAtEpochMs: number,
): CandidateLookupState {
  return { epoch, networkIdentifier, candidates, outcomes: new Map(), startedAtEpochMs };
}

/**
 * Run one sequential pass over the unresolved candidates in deterministic
 * precedence order. Each request is bounded by `timeoutMs` (default the
 * shared 10-second bound); a timeout/transport failure records `unresolved`
 * (never absence). Returns the updated state and safe progress counts.
 */
export async function runSequentialLookupPass(
  state: CandidateLookupState,
  port: RecoveryLookupPort,
  nowMs: number,
  timeoutMs: number = LOOKUP_REQUEST_TIMEOUT_MS,
): Promise<{ readonly state: CandidateLookupState; readonly attempted: number; readonly unresolvedAfter: number }> {
  let current = state;
  let attempted = 0;
  for (let index = 0; index < current.candidates.length; index += 1) {
    if (current.outcomes.has(index)) {
      continue; // completed or previously unresolved-retried this pass
    }
    attempted += 1;
    const candidate = current.candidates[index]!;
    const outcome = await withTimeout(port.lookupCandidate(candidate, current.networkIdentifier), timeoutMs);
    current = recordLookupOutcome(current, index, outcome);
  }
  return { state: current, attempted, unresolvedAfter: countUnresolved(current) };
}

function countUnresolved(state: CandidateLookupState): number {
  let count = 0;
  for (let index = 0; index < state.candidates.length; index += 1) {
    const outcome = state.outcomes.get(index);
    if (!outcome || outcome.kind === 'unresolved') {
      count += 1;
    }
  }
  return count;
}

/** Retry ONLY unresolved candidates within the same valid epoch. */
export async function retryUnresolved(
  state: CandidateLookupState,
  port: RecoveryLookupPort,
  nowMs: number,
  timeoutMs: number = LOOKUP_REQUEST_TIMEOUT_MS,
): Promise<{ readonly state: CandidateLookupState; readonly retried: number }> {
  let current = state;
  let retried = 0;
  for (let index = 0; index < current.candidates.length; index += 1) {
    const outcome = current.outcomes.get(index);
    if (outcome && outcome.kind !== 'unresolved') {
      continue;
    }
    retried += 1;
    const candidate = current.candidates[index]!;
    const fresh = await withTimeout(port.lookupCandidate(candidate, current.networkIdentifier), timeoutMs);
    current = recordLookupOutcome(current, index, fresh);
  }
  return { state: current, retried };
}

/** Promise.race helper with a fixed timeout (rejects nothing; yields unresolved). */
async function withTimeout(promise: Promise<CandidateLookupOutcome>, timeoutMs: number): Promise<CandidateLookupOutcome> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<CandidateLookupOutcome>((resolve) => {
    timer = setTimeout(() => resolve({ kind: 'unresolved', reason: 'timeout' }), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/** Safe counted progress ("Checking identity formats 2 of 4"). */
export function safeProgress(state: CandidateLookupState): { readonly done: number; readonly total: number } {
  let done = 0;
  for (let index = 0; index < state.candidates.length; index += 1) {
    const outcome = state.outcomes.get(index);
    if (outcome && outcome.kind !== 'unresolved') {
      done += 1;
    }
  }
  return { done, total: state.candidates.length };
}

/** Deterministic resolution gate — never conclude from a partial set. */
export function resolutionVerdict(state: CandidateLookupState): RecoveryResult<ReturnType<typeof resolveLookup>> {
  const verdict = resolveLookup(state);
  if (verdict.kind === 'incomplete') {
    return {
      ok: false,
      code: 'PARTIAL_CANDIDATE_LOOKUP',
      message: 'Candidate resolution is incomplete; no selection or profile action is available.',
      supportCode: 'RW-LOOKUP-1',
    };
  }
  return { ok: true, value: verdict };
}
