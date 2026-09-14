/**
 * FEAT-016 Task 3.2 — query freshness and fail-closed outcome policy tests.
 *
 * Proves every Retry/attempt mints a fresh `signedAt` over the unchanged empty
 * business request (no previous timestamp reuse, no request ID/nonce); the
 * unauth retry policy is retry-once then forced Lock; the classification maps
 * the closed parser outcomes to coordinator classes; and cadence/deadline
 * constants are frozen.
 */

import { describe, expect, it } from 'vitest';
import {
  ENTITLEMENT_CONFIRMATION_DELAYED_MS,
  ENTITLEMENT_MAX_UNAUTHENTICATED_RETRIES,
  ENTITLEMENT_QUERY_DEADLINE_MS,
  ENTITLEMENT_QUERY_POLL_INTERVAL_MS,
  classifyQueryOutcome,
  createFreshQueryEnvelope,
  decideUnauthenticatedPolicy,
  isUnauthenticatedOutcome,
  signedAtUtcIso,
} from './policy';
import type { EntitlementQueryOutcome } from './parser';

const ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';

function outcome(kind: EntitlementQueryOutcome['outcome']): EntitlementQueryOutcome {
  switch (kind) {
    case 'ready':
      throw new Error('ready needs projection; use classification-only tests');
    case 'noActive':
      return {
        outcome: 'noActive',
        template: {
          TransitionIntent: 'baseline_free',
          RequestedPlanId: 'hushvoting.direct.free',
          ObservedCatalogueVersion: 'hushvoting-licence-catalogue/v1.0.0',
        },
      };
    case 'unavailable':
      return { outcome: 'unavailable', code: 'licence_index_unavailable' };
    case 'unsupported':
      return { outcome: 'unsupported', reason: 'unknown-plan-family' };
    case 'unauthenticated':
      return { outcome: 'unauthenticated' };
    case 'permissionDenied':
      return { outcome: 'permissionDenied' };
    case 'invalidArgument':
      return { outcome: 'invalidArgument' };
    case 'unimplemented':
      return { outcome: 'unimplemented' };
    case 'transportFailure':
      return { outcome: 'transportFailure' };
    case 'malformed':
      return { outcome: 'malformed' };
  }
}

describe('fresh envelope minting', () => {
  it('mints a new signedAt for every attempt over the unchanged empty request', () => {
    const first = createFreshQueryEnvelope(ACTOR as never, 1_752_000_000_000);
    const second = createFreshQueryEnvelope(ACTOR as never, 1_752_000_003_000);
    expect(first.signedAt).not.toBe(second.signedAt);
    expect(first.method).toBe('GetMyEntitlement');
    expect(first.request).toEqual({});
    expect(second.request).toEqual({});
    // No nonce/request ID ever added.
    expect(Object.keys(first).sort()).toEqual(['actorAddress', 'method', 'request', 'signedAt']);
  });

  it('formats signedAt as canonical UTC ISO-8601 with milliseconds', () => {
    const iso = signedAtUtcIso(Date.UTC(2026, 8, 6, 0, 0, 0, 123));
    expect(iso).toBe('2026-09-06T00:00:00.123Z');
  });

  it('freezes cadence and deadline constants', () => {
    expect(ENTITLEMENT_QUERY_POLL_INTERVAL_MS).toBe(3_000);
    expect(ENTITLEMENT_CONFIRMATION_DELAYED_MS).toBe(30_000);
    expect(ENTITLEMENT_QUERY_DEADLINE_MS).toBe(10_000);
    expect(ENTITLEMENT_MAX_UNAUTHENTICATED_RETRIES).toBe(1);
  });
});

describe('unauthenticated retry policy', () => {
  it('retries once with a completely fresh envelope then forces Lock', () => {
    expect(decideUnauthenticatedPolicy(1)).toBe('retryOnce');
    expect(decideUnauthenticatedPolicy(2)).toBe('forcedLock');
  });

  it('recognizes only the typed UNAUTHENTICATED outcome', () => {
    expect(isUnauthenticatedOutcome(outcome('unauthenticated'))).toBe(true);
    expect(isUnauthenticatedOutcome(outcome('unavailable'))).toBe(false);
  });
});

describe('query outcome classification', () => {
  it('maps every closed outcome to the coarse coordinator class', () => {
    expect(classifyQueryOutcome(outcome('unavailable'))).toBe('unavailable');
    expect(classifyQueryOutcome(outcome('noActive'))).toBe('noActive');
    expect(classifyQueryOutcome(outcome('unauthenticated'))).toBe('authenticationFailure');
    expect(classifyQueryOutcome(outcome('permissionDenied'))).toBe('terminalGuidance');
    expect(classifyQueryOutcome(outcome('invalidArgument'))).toBe('terminalGuidance');
    expect(classifyQueryOutcome(outcome('unimplemented'))).toBe('terminalGuidance');
    expect(classifyQueryOutcome(outcome('transportFailure'))).toBe('transient');
    expect(classifyQueryOutcome(outcome('malformed'))).toBe('malformed');
    expect(classifyQueryOutcome(outcome('unsupported'))).toBe('unsupported');
  });
});
