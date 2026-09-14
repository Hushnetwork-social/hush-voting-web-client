/**
 * FEAT-016 Task 3.1/3.2 — query, freshness, and outcome policy.
 *
 * Closed decision policy for the entitlement query path: fresh envelope
 * minting (a new UTC `signedAt` for every attempt), the bounded ten-second
 * transport deadline, the single fresh-envelope retry on the first
 * `UNAUTHENTICATED` and forced Lock on the second, the three-second query-only
 * cadence, and the thirty-second (or earlier paused-chain) delayed-confirmation
 * threshold counted in monotonic foreground/reachable time only.
 *
 * Normative source: FEAT-016 FeatureDescription "Timing, Polling, and
 * Connectivity", "Signed Query Contract" (query retry/authentication failure),
 * Deep-Dive decision 8; FEAT-015 ten-second bounded transport deadline.
 */

import {
  LICENCE_QUERY_METHOD,
  type LicenceActorBinding,
  type LicenceFreshQueryEnvelope,
} from './contracts';
import type { EntitlementQueryOutcome } from './parser';

/** Query-only polling cadence while waiting for indexed activation. */
export const ENTITLEMENT_QUERY_POLL_INTERVAL_MS = 3_000 as const;

/** Delayed confirmation: no active result after 30 s of reachable foreground time. */
export const ENTITLEMENT_CONFIRMATION_DELAYED_MS = 30_000 as const;

/** Bounded ten-second transport deadline for one signed query call (FEAT-015). */
export const ENTITLEMENT_QUERY_DEADLINE_MS = 10_000 as const;

/** One completely fresh envelope attempt is allowed after the first rejection. */
export const ENTITLEMENT_MAX_UNAUTHENTICATED_RETRIES = 1 as const;

/** Max attempts bounded defense (never an unbounded retry loop). */
export const ENTITLEMENT_MAX_QUERY_ATTEMPTS_PER_OPERATION = 64 as const;

/** Format a UTC epoch-millisecond value as the canonical ISO-8601 UTC stamp. */
export function signedAtUtcIso(nowMs: number): string {
  return new Date(nowMs).toISOString();
}

/** Mint one fresh query envelope with a new UTC signedAt for this attempt. */
export function createFreshQueryEnvelope(
  actorAddress: LicenceActorBinding,
  nowMs: number,
): LicenceFreshQueryEnvelope {
  return {
    actorAddress,
    method: LICENCE_QUERY_METHOD,
    request: {},
    signedAt: signedAtUtcIso(nowMs),
  };
}

/** True when the outcome is the typed first/second UNAUTHENTICATED rejection. */
export function isUnauthenticatedOutcome(outcome: EntitlementQueryOutcome): boolean {
  return outcome.outcome === 'unauthenticated';
}

/**
 * Unauth policy: after the first UNAUTHENTICATED, mint one completely fresh
 * envelope and retry; after the second, the session must Lock with safe
 * device-time/support guidance (typed forced-lock outcome).
 */
export function decideUnauthenticatedPolicy(
  consecutiveUnauthenticated: number,
): 'retryOnce' | 'forcedLock' {
  return consecutiveUnauthenticated > ENTITLEMENT_MAX_UNAUTHENTICATED_RETRIES
    ? 'forcedLock'
    : 'retryOnce';
}

/** Coarse query-outcome classifier used by the coordinator/machine. */
export type QueryOutcomeClass =
  | 'ready' // compatible active indexed truth
  | 'noActive' // bootstrap: sign/submit one baseline
  | 'unavailable' // authority unavailable; retryable, never no-active/Free
  | 'unsupported' // compatible-client/update gate; never coerced
  | 'authenticationFailure' // unauthenticated (retry-once then forced Lock)
  | 'terminalGuidance' // permissionDenied / invalidArgument / unimplemented
  | 'transient' // deadline/unknown/malformed-shaped transport failure
  | 'malformed'; // success envelope that failed closed parsing

export function classifyQueryOutcome(outcome: EntitlementQueryOutcome): QueryOutcomeClass {
  switch (outcome.outcome) {
    case 'ready':
      return 'ready';
    case 'noActive':
      return 'noActive';
    case 'unavailable':
      return 'unavailable';
    case 'unsupported':
      return 'unsupported';
    case 'unauthenticated':
      return 'authenticationFailure';
    case 'permissionDenied':
    case 'invalidArgument':
    case 'unimplemented':
      return 'terminalGuidance';
    case 'transportFailure':
      return 'transient';
    case 'malformed':
      return 'malformed';
  }
}
