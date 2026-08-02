/**
 * FEAT-003 vault-core session — conservative session timing.
 *
 * Use monotonic time while running. On suspend/resume, conservatively compare available
 * monotonic and bounded wall-clock evidence and apply the longer credible elapsed
 * duration. Backward or implausible wall-clock changes cannot extend a session; when
 * elapsed time cannot be established safely, Lock.
 *
 * Normative source: FEAT-003 FeatureDescription "Session timing".
 */

/** Timing evidence captured before a suspend and after a resume. */
export interface TimingEvidence {
  /** Monotonic milliseconds (performance.now semantics). */
  readonly monotonicMs: number;
  /** Bounded wall-clock milliseconds (epoch ms). */
  readonly wallClockMs: number;
}

export type ElapsedAssessment =
  | { readonly ok: true; readonly elapsedMs: number }
  | { readonly ok: false; readonly code: 'UNRELIABLE_CLOCK'; readonly message: string };

/**
 * Determine the credible elapsed duration across suspend/resume.
 * - monotonic forward delta is authoritative when plausible;
 * - wall-clock forward delta is used only when bounded and consistent;
 * - backward or implausible wall-clock evidence cannot extend the session;
 * - when neither source yields a credible bound, lock (fail closed).
 */
export function assessElapsed(before: TimingEvidence, after: TimingEvidence): ElapsedAssessment {
  const monoDelta = after.monotonicMs - before.monotonicMs;
  const wallDelta = after.wallClockMs - before.wallClockMs;
  const monotonicCredible = Number.isFinite(monoDelta) && monoDelta >= 0 && monoDelta < 365 * 24 * 3600 * 1000;
  const wallCredible = Number.isFinite(wallDelta) && wallDelta >= 0 && wallDelta < 365 * 24 * 3600 * 1000;
  if (!monotonicCredible && !wallCredible) {
    return { ok: false, code: 'UNRELIABLE_CLOCK', message: 'no credible elapsed evidence' };
  }
  if (monotonicCredible && wallCredible) {
    // Conservative: apply the longer credible duration.
    return { ok: true, elapsedMs: Math.max(monoDelta, wallDelta) };
  }
  if (monotonicCredible) return { ok: true, elapsedMs: monoDelta };
  return { ok: true, elapsedMs: wallDelta };
}

/**
 * Apply idle/background lock policy. Returns a lock decision based on the credible
 * elapsed duration since last activity.
 */
export type LockPolicyDecision = 'stay-unlocked' | 'lock';

export function applyLockPolicy(
  elapsedMs: number,
  policy: { readonly idleLimitMs: number },
): LockPolicyDecision {
  if (elapsedMs >= policy.idleLimitMs) return 'lock';
  return 'stay-unlocked';
}
