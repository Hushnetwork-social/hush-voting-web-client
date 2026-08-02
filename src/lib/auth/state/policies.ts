/**
 * FEAT-002 authentication policy helpers — pure functions shared by the
 * state machine and its tests. Framework-neutral: no XState import here.
 *
 * Covers:
 * - stale-result rejection (epoch/operation scoping);
 * - session epoch lifecycle (lock, removal, replacement, takeover,
 *   authority loss, invalidation all increment the epoch);
 * - one-operation-per-state duplication guard;
 * - timing boundary checks (progress, init, verify, KDF).
 */

import { AUTH_TIMING, type SessionEpoch } from '../types.js';

/** True when a late actor result belongs to a superseded session. */
export function isStaleEpoch(resultEpoch: SessionEpoch, currentEpoch: SessionEpoch): boolean {
  return resultEpoch !== currentEpoch;
}

/** Next session epoch after any global security event. */
export function nextEpoch(current: SessionEpoch): SessionEpoch {
  return (current + 1) as SessionEpoch;
}

/** Initial epoch for a fresh authority. */
export const INITIAL_EPOCH = 0 as SessionEpoch;

/**
 * Duplicate-submission guard: any pending operation blocks starting a new one.
 * State eligibility for starting operations is enforced by the machine's
 * transition handlers; this helper only rejects overlaps.
 */
export function isOperationActive(activeOperationKind: string | null): boolean {
  return activeOperationKind !== null;
}

/** Deterministic progress/error timing checks (bounded operations). */
export function hasExceededProgressThreshold(elapsedMs: number): boolean {
  return elapsedMs > AUTH_TIMING.progressThresholdMs;
}

export function hasExceededInitTimeout(elapsedMs: number): boolean {
  return elapsedMs > AUTH_TIMING.initTimeoutMs;
}

export function hasExceededVerifyTimeout(elapsedMs: number): boolean {
  return elapsedMs > AUTH_TIMING.verifyTimeoutMs;
}

export function hasExceededKdfHardLimit(elapsedMs: number): boolean {
  return elapsedMs > AUTH_TIMING.kdfHardLimitMs;
}

/** Lease staleness boundary (used by Phase 4 fallback ownership; pure here). */
export function isLeaseStale(lastHeartbeatMs: number, nowMs: number): boolean {
  return nowMs - lastHeartbeatMs > AUTH_TIMING.leaseStalenessMs;
}
