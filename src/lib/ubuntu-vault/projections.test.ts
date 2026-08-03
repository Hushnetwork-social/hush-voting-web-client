/**
 * FEAT-005 bridge projection tests — FEAT-002 safe surface.
 *
 * Proves provider states project to exactly the closed safe action sets of the
 * target (fallback only for confirmed absence; transient states never select
 * fallback; unqualified/invalidated block provisioning), native outcomes map
 * to safe decisions, and no raw detail leaks through the projection.
 *
 * Normative source: FEAT-005 FeatureDescription "Availability state model",
 * "Error Handling"; FEAT-002 auth ports.
 */
import { describe, expect, it } from 'vitest';
import {
  PROVIDER_ACTION_MAP,
  PROVIDER_PREDICATES,
  isSafeProtectionSummary,
  projectNativeOutcome,
} from './projections';
import type { NativeOutcome, ProviderAvailability } from './contracts';

const STATES: readonly ProviderAvailability[] = [
  'availableUnlocked',
  'availableLocked',
  'promptCancelled',
  'temporarilyUnavailable',
  'unavailable',
  'unqualifiedProvider',
  'protectionInvalidated',
];

describe('ubuntu-vault projections — closed provider actions', () => {
  it('every provider state has a closed action set', () => {
    for (const state of STATES) {
      const actions = PROVIDER_ACTION_MAP[state];
      expect(actions.length).toBeGreaterThan(0);
      for (const action of actions) {
        expect([
          'unlockKeyring',
          'retry',
          'enableOsProtection',
          'passwordOnlyFallback',
          'portableRecovery',
          'cancel',
        ]).toContain(action);
      }
    }
  });

  it('password-only fallback appears ONLY for confirmed absence', () => {
    for (const state of STATES) {
      const hasFallback = PROVIDER_ACTION_MAP[state].includes('passwordOnlyFallback');
      expect(hasFallback).toBe(state === 'unavailable');
      expect(PROVIDER_PREDICATES.isFallbackEligible(state)).toBe(state === 'unavailable');
    }
  });

  it('locked/cancelled/timeout/temp failures are transient, never absence', () => {
    expect(PROVIDER_PREDICATES.isTransient('availableLocked')).toBe(true);
    expect(PROVIDER_PREDICATES.isTransient('promptCancelled')).toBe(true);
    expect(PROVIDER_PREDICATES.isTransient('temporarilyUnavailable')).toBe(true);
    expect(PROVIDER_PREDICATES.isTransient('unavailable')).toBe(false);
    expect(PROVIDER_PREDICATES.isTransient('unqualifiedProvider')).toBe(false);
    // Transient states never offer fallback.
    expect(PROVIDER_ACTION_MAP.availableLocked).not.toContain('passwordOnlyFallback');
    expect(PROVIDER_ACTION_MAP.promptCancelled).not.toContain('passwordOnlyFallback');
    expect(PROVIDER_ACTION_MAP.temporarilyUnavailable).not.toContain('passwordOnlyFallback');
  });

  it('unqualified and invalidated block persistent provisioning', () => {
    expect(PROVIDER_PREDICATES.blocksPersistentProvisioning('unqualifiedProvider')).toBe(true);
    expect(PROVIDER_PREDICATES.blocksPersistentProvisioning('protectionInvalidated')).toBe(true);
    expect(PROVIDER_PREDICATES.blocksPersistentProvisioning('unavailable')).toBe(false);
    // Unqualified provider never unlocks fallback.
    expect(PROVIDER_ACTION_MAP.unqualifiedProvider).not.toContain('passwordOnlyFallback');
  });
});

describe('ubuntu-vault projections — native outcome decisions', () => {
  it('successful outcomes continue with a safe kind', () => {
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'unlocked' })).toEqual({
      action: 'continue',
      kind: 'unlocked',
    });
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'locked' })).toEqual({ action: 'locked' });
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'preview' })).toEqual({
      action: 'continue',
      kind: 'preview',
    });
  });

  it('non-auth operation completions are never mistaken for unlock', () => {
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'signed' })).toEqual({
      action: 'operationComplete',
      kind: 'signed',
    });
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'datImported' })).toEqual({
      action: 'operationComplete',
      kind: 'datImported',
    });
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'datExported' })).toEqual({
      action: 'operationComplete',
      kind: 'datExported',
    });
    expect(projectNativeOutcome({ outcome: 'ok', kind: 'revealPrepared' })).toEqual({
      action: 'operationComplete',
      kind: 'revealPrepared',
    });
  });

  it('retryable failures map to retry without raw detail', () => {
    const outcome: NativeOutcome = { outcome: 'err', code: 'wrongPasswordOrDamagedData' };
    const decision = projectNativeOutcome(outcome);
    expect(decision).toEqual({ action: 'retry', code: 'wrongPasswordOrDamagedData' });
    expect(JSON.stringify(decision)).not.toMatch(/(password|path|dbus|home)/);
  });

  it('protection-invalidated and ambiguous states map to recovery', () => {
    expect(projectNativeOutcome({ outcome: 'err', code: 'platformProtectionInvalidated' })).toEqual({
      action: 'recover',
      code: 'platformProtectionInvalidated',
    });
    expect(projectNativeOutcome({ outcome: 'err', code: 'wrapperAmbiguous' })).toEqual({
      action: 'recover',
      code: 'wrapperAmbiguous',
    });
  });

  it('unknown/stale/forbidden codes fail closed to blocked', () => {
    const blocked = projectNativeOutcome({ outcome: 'err', code: 'operationForbidden' });
    expect(blocked).toEqual({ action: 'blocked', code: 'operationForbidden' });
  });

  it('never emits a blank screen or indefinite spinner', () => {
    for (const code of ['noVault', 'unsupportedVaultVersion', 'malformedEnvelope', 'buildVersionMismatch', 'removalIncomplete'] as const) {
      const decision = projectNativeOutcome({ outcome: 'err', code });
      expect(['continue', 'locked', 'retry', 'recover', 'blocked']).toContain(decision.action);
    }
  });
});

describe('ubuntu-vault projections — protection summary', () => {
  it('accepts only the safe non-secret summary shape', () => {
    expect(
      isSafeProtectionSummary({
        mode: 'osBacked',
        fallbackAcknowledged: false,
        upgradeEligibleAfterUnlock: true,
      }),
    ).toBe(true);
    expect(isSafeProtectionSummary({ mode: 'passwordOnly', fallbackAcknowledged: true, upgradeEligibleAfterUnlock: false })).toBe(true);
    expect(isSafeProtectionSummary({ mode: 'hardwareBacked', fallbackAcknowledged: true, upgradeEligibleAfterUnlock: false })).toBe(false);
    expect(isSafeProtectionSummary(null)).toBe(false);
    expect(isSafeProtectionSummary({ mode: 'osBacked' })).toBe(false);
  });
});
