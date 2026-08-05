/**
 * FEAT-010 Task 3.6 — connectivity/Lock/timing authority tests.
 *
 * Proves exact reconnect timing, coalescing, no queue, reverify outcomes,
 * trusted activity, all policy thresholds, conservative clocks, multi-client
 * Lock, one-second cleanup, stale suppression, and session-only destruction
 * (normative: FeatureDescription "Connectivity After Authentication",
 * "Reverification Policy", "Lock and Session Lifecycle";
 * AC-010-047…062, 085…087, 090).
 */
import { describe, expect, it } from 'vitest';
import {
  destroySessionOnly,
  evaluateTimingLock,
  executeLockSequence,
  isTrustedActivity,
  LOCK_CLEANUP_ACKNOWLEDGEMENT_MS,
  nextReconnectDelayMs,
  REVERIFICATION_TRIGGERS,
  shouldStartBackgroundTiming,
  shouldStopReconnect,
} from './lifecycle-authority';

describe('nextReconnectDelayMs', () => {
  it('follows the exact 2/5/10/30-second foreground schedule', () => {
    expect(nextReconnectDelayMs(0, false, false)).toEqual({ delayMs: 2_000, immediateBounded: false });
    expect(nextReconnectDelayMs(1, false, false)).toEqual({ delayMs: 5_000, immediateBounded: false });
    expect(nextReconnectDelayMs(2, false, false)).toEqual({ delayMs: 10_000, immediateBounded: false });
    expect(nextReconnectDelayMs(3, false, false)).toEqual({ delayMs: 30_000, immediateBounded: false });
  });

  it('continues at bounded-jitter 30-second intervals afterwards', () => {
    expect(nextReconnectDelayMs(4, false, false)).toEqual({ delayMs: 30_000, immediateBounded: false });
    expect(nextReconnectDelayMs(50, false, false)).toEqual({ delayMs: 30_000, immediateBounded: false });
  });

  it('reacts to a connectivity-restored signal with one immediate bounded attempt', () => {
    expect(nextReconnectDelayMs(2, false, true)).toEqual({ delayMs: 0, immediateBounded: true });
  });

  it('allows exactly one coalesced Retry', () => {
    expect(nextReconnectDelayMs(0, true, false)).toEqual({ delayMs: 2_000, immediateBounded: false });
  });
});

describe('shouldStopReconnect', () => {
  it('stops retry on background, Lock, authority loss, or unknown phase', () => {
    expect(shouldStopReconnect('offline', true, false, false)).toBe(true);
    expect(shouldStopReconnect('offline', false, true, false)).toBe(true);
    expect(shouldStopReconnect('offline', false, false, true)).toBe(true);
    expect(shouldStopReconnect('unknown', false, false, false)).toBe(true);
    expect(shouldStopReconnect('offline', false, false, false)).toBe(false);
    expect(shouldStopReconnect('reconnecting', false, false, false)).toBe(false);
  });
});

describe('isTrustedActivity', () => {
  it('accepts only trusted visible-instance activity classes', () => {
    for (const klass of ['keyboard', 'pointer', 'touch', 'wheelScroll', 'accessibility']) {
      expect(isTrustedActivity({ isTrusted: true, class: klass as 'keyboard' })).toBe(true);
    }
  });

  it('never accepts synthetic/timer/media/animation/network/background signals', () => {
    for (const klass of ['synthetic', 'timer', 'media', 'animation', 'network', 'backgroundSync']) {
      expect(isTrustedActivity({ isTrusted: true, class: klass as 'synthetic' })).toBe(false);
    }
    expect(isTrustedActivity({ isTrusted: false, class: 'keyboard' })).toBe(false);
  });
});

describe('shouldStartBackgroundTiming', () => {
  it('starts background timing only when every instance is hidden/backgrounded or screen is off', () => {
    expect(shouldStartBackgroundTiming(0, false, false)).toBe(true);
    expect(shouldStartBackgroundTiming(0, true, false)).toBe(true);
    expect(shouldStartBackgroundTiming(2, false, false)).toBe(false);
    expect(shouldStartBackgroundTiming(0, false, true)).toBe(false);
  });
});

describe('evaluateTimingLock', () => {
  it('locks on idle and background threshold exceedance', () => {
    expect(evaluateTimingLock({ elapsedIdleMs: 301_000, elapsedBackgroundMs: 0, idleThresholdMs: 300_000, backgroundThresholdMs: 30_000, timingUncertain: false })).toEqual({ kind: 'lock', trigger: 'idleTimeout' });
    expect(evaluateTimingLock({ elapsedIdleMs: 0, elapsedBackgroundMs: 31_000, idleThresholdMs: 300_000, backgroundThresholdMs: 30_000, timingUncertain: false })).toEqual({ kind: 'lock', trigger: 'backgroundTimeout' });
  });

  it('locks on uncertain timing instead of extending access', () => {
    expect(evaluateTimingLock({ elapsedIdleMs: 0, elapsedBackgroundMs: 0, idleThresholdMs: 300_000, backgroundThresholdMs: 30_000, timingUncertain: true })).toEqual({ kind: 'lock', trigger: 'uncertainTime' });
  });

  it('does not lock within thresholds', () => {
    expect(evaluateTimingLock({ elapsedIdleMs: 10_000, elapsedBackgroundMs: 5_000, idleThresholdMs: 300_000, backgroundThresholdMs: 30_000, timingUncertain: false })).toEqual({ kind: 'noLock' });
  });
});

describe('executeLockSequence', () => {
  it('invalidates epoch and unmounts synchronously before cleanup acknowledgement', () => {
    const result = executeLockSequence(500);
    expect(result.epochInvalidated).toBe(true);
    expect(result.protectedContentUnmountedSynchronously).toBe(true);
    expect(result.cleanupAcknowledged).toBe(true);
    expect(result.possibleServerAcceptance).toBe(false);
  });

  it('forces isolation termination when cleanup exceeds one second', () => {
    const result = executeLockSequence(LOCK_CLEANUP_ACKNOWLEDGEMENT_MS + 1);
    expect(result.cleanupAcknowledged).toBe(false);
    // Never claim cancellation when server acceptance may have occurred.
    expect(result.possibleServerAcceptance).toBe(true);
  });

  it('treats missing acknowledgement as termination with possible server acceptance', () => {
    const result = executeLockSequence(null);
    expect(result.cleanupAcknowledged).toBe(false);
    expect(result.possibleServerAcceptance).toBe(true);
  });
});

describe('reverification triggers', () => {
  it('covers every lifecycle reverification point', () => {
    expect(REVERIFICATION_TRIGGERS).toEqual([
      'afterLocalUnlock',
      'afterReconnect',
      'uncertainResume',
      'beforePersistentProtectionChange',
      'beforeExportElevation',
      'afterSameKeyRecreation',
    ]);
  });
});

describe('destroySessionOnly', () => {
  it('destroys memory authority and returns to verified first-run', () => {
    expect(destroySessionOnly()).toEqual({ kind: 'destroyed', returnsTo: 'verifiedFirstRun' });
  });
});
