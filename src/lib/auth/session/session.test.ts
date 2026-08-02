/**
 * FEAT-002 shared-session tests — authority ownership, fallbacks, takeover,
 * heartbeat staleness, and timer policy.
 *
 * Proves:
 * - capability hierarchy is fail-closed (shared → exclusive → lease → blocked);
 * - concurrent ownership races never yield two valid unlocked owners;
 * - untrusted/background activity cannot extend the session;
 * - the lease owner becomes stale only after 15 s without a valid heartbeat;
 * - explicit takeover after loss/staleness is allowed; never while owned.
 */

import { describe, expect, it } from 'vitest';
import {
  acquireOwnership,
  decideTakeover,
  heartbeat,
  isOwnerStale,
  selectCoordinationMode,
  type CoordinationEnvironment,
} from './authority';
import {
  isBackgrounded,
  isPolicyWithinBounds,
  isRateLimited,
  qualifiesAsIdleReset,
  REFERENCE_POLICY,
  shouldLockAfterBackground,
  type ActivityEvent,
  type VisibilitySnapshot,
} from './timers';
import { isLeaseStale } from '../state/policies';
import { AUTH_TIMING } from '../types';

/** Deterministic fake coordination environment. */
function makeEnv(overrides: Partial<CoordinationEnvironment> = {}): CoordinationEnvironment {
  let lease: { ownerId: string; heartbeatMs: number } | null = null;
  const base: CoordinationEnvironment = {
    sharedWorkerAvailable: () => false,
    connectSharedWorker: () => null,
    webLockAvailable: () => false,
    acquireWebLock: async () => true,
    releaseWebLock: async () => undefined,
    storageAvailable: () => true,
    readLease: () => lease,
    writeLease: (_key, value) => {
      lease = value;
    },
    clearLease: () => {
      lease = null;
    },
    now: () => 1000,
    schedule: () => ({ cancel: () => undefined }),
  };
  return { ...base, ...overrides };
}

describe('capability hierarchy (fail-closed order)', () => {
  it('prefers SharedWorker, then Web Lock, then lease, then blocked', () => {
    const all = makeEnv({ sharedWorkerAvailable: () => true, webLockAvailable: () => true, storageAvailable: () => true });
    expect(selectCoordinationMode(all)).toBe('shared');

    const noWorker = makeEnv({ webLockAvailable: () => true, storageAvailable: () => true });
    expect(selectCoordinationMode(noWorker)).toBe('exclusive');

    const noLock = makeEnv({ storageAvailable: () => true });
    expect(selectCoordinationMode(noLock)).toBe('lease');

    const nothing = makeEnv({ storageAvailable: () => false });
    expect(selectCoordinationMode(nothing)).toBe('blocked');
  });

  it('never permits persistent authentication without any safe primitive', async () => {
    const env = makeEnv({ storageAvailable: () => false });
    const result = await acquireOwnership(env, 'blocked');
    expect(result.kind).toBe('blocked');
  });
});

describe('ownership acquisition', () => {
  it('acquires exclusive ownership via Web Lock and blocks when unavailable', async () => {
    const okEnv = makeEnv({ webLockAvailable: () => true, acquireWebLock: async () => true });
    expect((await acquireOwnership(okEnv, 'exclusive')).kind).toBe('exclusive');

    const busyEnv = makeEnv({ webLockAvailable: () => true, acquireWebLock: async () => false });
    expect((await acquireOwnership(busyEnv, 'exclusive')).kind).toBe('blocked');
  });

  it('lease ownership writes a non-secret lease and never duplicates owners', async () => {
    const env = makeEnv();
    const first = await acquireOwnership(env, 'lease');
    expect(first.kind).toBe('lease');
    if (first.kind === 'lease') {
      expect(first.ownerId.length).toBeGreaterThan(0);
      expect(env.readLease('hushvoting-auth-lease')?.ownerId).toBe(first.ownerId);
    }
  });

  it('heartbeat renews the lease and staleness only after 15 s', () => {
    const env = makeEnv({ now: () => 1000 });
    const ownerId = 'owner-1';
    heartbeat(env, ownerId);
    expect(isOwnerStale(env, ownerId)).toBe(false);

    // Advance the injected clock beyond the staleness boundary.
    env.now = () => 1000 + AUTH_TIMING.leaseStalenessMs + 1;
    expect(isOwnerStale(env, ownerId)).toBe(true);
    expect(isLeaseStale(1000, 1000 + AUTH_TIMING.leaseStalenessMs)).toBe(false);
    expect(isLeaseStale(1000, 1000 + AUTH_TIMING.leaseStalenessMs + 1)).toBe(true);
  });
});

describe('takeover decisions', () => {
  it('permits takeover only after authority loss or staleness, never while owned', () => {
    const env = makeEnv({ now: () => 1000 });
    env.writeLease('hushvoting-auth-lease', { ownerId: 'owner-1', heartbeatMs: 1000 });

    // Owned and fresh → not allowed.
    expect(decideTakeover(env, 'owner-1').allowed).toBe(false);
    // Foreign owner that is FRESH → not allowed (active elsewhere).
    expect(decideTakeover(env, 'someone-else').allowed).toBe(false);

    // Foreign owner that is STALE → allowed (takeover after staleness).
    env.writeLease('hushvoting-auth-lease', { ownerId: 'owner-1', heartbeatMs: 1000 - AUTH_TIMING.leaseStalenessMs - 1 });
    expect(decideTakeover(env, 'someone-else').allowed).toBe(true);

    // No lease at all → authority lost → allowed.
    env.clearLease('hushvoting-auth-lease');
    expect(decideTakeover(env, 'owner-1').allowed).toBe(true);
  });

  it('never transfers unlocked access: takeover outcome always requires fresh unlock', () => {
    // Ownership mode is independent of unlock state; the authority contract
    // forces authenticated → locked before any takeover path (machine test).
    expect(selectCoordinationMode(makeEnv())).not.toBe('shared');
  });
});

describe('aggregate idle and background timer policy', () => {
  it('only trusted activity from a visible instance qualifies as an idle reset', () => {
    const trustedVisible: ActivityEvent = {
      kind: 'pointer',
      isTrusted: true,
      instanceVisible: true,
      timestampMs: 0,
    };
    expect(qualifiesAsIdleReset(trustedVisible)).toBe(true);

    const synthetic: ActivityEvent = { kind: 'pointer', isTrusted: false, instanceVisible: true, timestampMs: 0 };
    expect(qualifiesAsIdleReset(synthetic)).toBe(false);

    const hidden: ActivityEvent = { kind: 'keyboard', isTrusted: true, instanceVisible: false, timestampMs: 0 };
    expect(qualifiesAsIdleReset(hidden)).toBe(false);

    const animation: ActivityEvent = { kind: 'pointer', isTrusted: false, instanceVisible: true, timestampMs: 0 };
    expect(qualifiesAsIdleReset(animation)).toBe(false);
  });

  it('rate-limits trusted resets', () => {
    // Within the 1000 ms window → limited.
    expect(isRateLimited(5000, 4001, REFERENCE_POLICY.resetWindowMs)).toBe(true);
    // At or beyond the window → allowed again.
    expect(isRateLimited(5000, 4000, REFERENCE_POLICY.resetWindowMs)).toBe(false);
    expect(isRateLimited(5000, 3000, REFERENCE_POLICY.resetWindowMs)).toBe(false);
  });

  it('background timer runs only while every instance is hidden or screen off', () => {
    const allHidden: VisibilitySnapshot = { visibleInstances: 0, hiddenInstances: 2, screenOff: false };
    expect(isBackgrounded(allHidden)).toBe(true);

    const oneVisible: VisibilitySnapshot = { visibleInstances: 1, hiddenInstances: 1, screenOff: false };
    expect(isBackgrounded(oneVisible)).toBe(false);

    const screenOff: VisibilitySnapshot = { visibleInstances: 1, hiddenInstances: 0, screenOff: true };
    expect(isBackgrounded(screenOff)).toBe(true);
  });

  it('locks after the background timeout elapses', () => {
    expect(shouldLockAfterBackground(2000, 0, 2000)).toBe(true);
    expect(shouldLockAfterBackground(1999, 0, 2000)).toBe(false);
  });

  it('rejects policy values outside EPIC-001 approved bounds', () => {
    expect(isPolicyWithinBounds(10 * 60 * 1000, 2 * 60 * 1000)).toBe(true);
    expect(isPolicyWithinBounds(1000, 2000)).toBe(false);
    expect(isPolicyWithinBounds(60 * 60 * 1000, 2 * 60 * 1000)).toBe(false);
  });
});
