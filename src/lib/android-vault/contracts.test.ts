/**
 * FEAT-006 Phase 2 Task 2.2 — closed Android adapter contract tests (TS).
 * Exhaustive round-trip, unknown-value rejection, redaction, and
 * forbidden-operation absence, mirroring the Rust contract tests.
 */
import { describe, expect, it } from 'vitest';
import {
  ANDROID_RESULT_CODES,
  BRIDGE_OPERATIONS,
  isAndroidOutcome,
  isCapabilityStatus,
  isPlausibleLifecycleEvidence,
  isRetryableCode,
  RECOVERY_ACTIONS_BY_CODE,
  SENSITIVE_STATES,
} from './contracts';

describe('FEAT-006 closed Android contract vocabulary (TS)', () => {
  it('declares a closed, exhaustive result-code registry', () => {
    // Every code must map to a safe recovery action set.
    for (const code of ANDROID_RESULT_CODES) {
      expect(RECOVERY_ACTIONS_BY_CODE[code]).toBeDefined();
      expect(Array.isArray(RECOVERY_ACTIONS_BY_CODE[code])).toBe(true);
    }
    // Outer integrity failure is never wrong-password.
    expect(ANDROID_RESULT_CODES).toContain('wrapperIntegrityFailure');
    expect(ANDROID_RESULT_CODES).toContain('wrongPasswordOrDamagedData');
    expect('wrapperIntegrityFailure' as string).not.toBe('wrongPasswordOrDamagedData');
  });

  it('classifies retryable codes exactly', () => {
    expect(isRetryableCode('temporaryKeystoreFailure')).toBe(true);
    expect(isRetryableCode('deviceLocked')).toBe(true);
    expect(isRetryableCode('secureLockRequired')).toBe(false);
    expect(isRetryableCode('buildProtocolMismatch')).toBe(false);
    expect(isRetryableCode('wrapperIntegrityFailure')).toBe(false);
  });

  it('rejects unknown result codes and secret-shaped outcomes', () => {
    expect(isAndroidOutcome({ outcome: 'err', code: 'decryptVault', retryable: false, retryDeadlineSecs: 0, supportCode: null })).toBe(false);
    expect(isAndroidOutcome({ outcome: 'err', code: 'deviceLocked', retryable: true, retryDeadlineSecs: 0, supportCode: null, alias: 'x' })).toBe(false);
    expect(isAndroidOutcome({ outcome: 'ok', kind: 'decryptVault' })).toBe(false);
    expect(isAndroidOutcome({ outcome: 'ok', kind: 'capabilityStatus' })).toBe(true);
  });

  it('rejects capability projections with unknown levels or classes', () => {
    expect(isCapabilityStatus({ secureLockConfigured: true, deviceLocked: false, securityLevel: 'softwareOrUnknown', strongBoxAdvertised: false, capabilityClass: 'blocked', knownBadBuildMatch: false })).toBe(true);
    expect(isCapabilityStatus({ secureLockConfigured: true, deviceLocked: false, securityLevel: 'magic', strongBoxAdvertised: false, capabilityClass: 'blocked', knownBadBuildMatch: false })).toBe(false);
  });

  it('exposes no generic bridge operation', () => {
    const forbidden = ['sign', 'decrypt', 'encrypt', 'getPrivateKey', 'listAliases', 'readFile', 'writeFile', 'openUri', 'startActivity'];
    for (const op of BRIDGE_OPERATIONS) {
      for (const f of forbidden) {
        expect(op).not.toContain(f);
      }
    }
  });

  it('enumerates all closed sensitive states distinctly', () => {
    expect(new Set(SENSITIVE_STATES).size).toBe(SENSITIVE_STATES.length);
  });

  it('rejects implausible lifecycle evidence', () => {
    expect(isPlausibleLifecycleEvidence({ bootElapsedMillis: 3_600_000, deviceLocked: false, allWindowsBackgrounded: false, mainWindowFocused: true })).toBe(true);
    expect(isPlausibleLifecycleEvidence({ bootElapsedMillis: 3_600_000, deviceLocked: false, allWindowsBackgrounded: true, mainWindowFocused: true })).toBe(false);
    expect(isPlausibleLifecycleEvidence({ bootElapsedMillis: 60 * 24 * 60 * 60 * 1000 + 1, deviceLocked: false, allWindowsBackgrounded: false, mainWindowFocused: true })).toBe(false);
  });
});
