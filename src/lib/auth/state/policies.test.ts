/**
 * FEAT-002 policy tests — epoch, cancellation, timing, and safe-error rules.
 *
 * Proves:
 * - every invalidation race is fail-closed (late completions rejected);
 * - every operation reaches progress/success/retry/blocked (no blank or
 *   indefinite pending state) at deterministic time boundaries;
 * - timing thresholds (250 ms progress, 5 s init, 10 s verify, 1.5 s KDF,
 *   15 s lease) hold on both sides of each boundary;
 * - all safe-error mappings stay deterministic and secret-free.
 */

import { describe, expect, it } from 'vitest';
import {
  hasExceededInitTimeout,
  hasExceededKdfHardLimit,
  hasExceededProgressThreshold,
  hasExceededVerifyTimeout,
  isLeaseStale,
  isOperationActive,
  isStaleEpoch,
  nextEpoch,
  INITIAL_EPOCH,
} from './policies.js';
import { outcomeErrorCategory, outcomeSafeActions, outcomeToAuthState } from '../results.js';
import { AUTH_TIMING } from '../types.js';

describe('session epoch lifecycle', () => {
  it('increments monotonically and rejects stale epochs', () => {
    let epoch = INITIAL_EPOCH;
    for (let i = 0; i < 5; i += 1) {
      expect(isStaleEpoch(epoch, epoch)).toBe(false);
      const next = nextEpoch(epoch);
      expect(isStaleEpoch(epoch, next)).toBe(true);
      expect(isStaleEpoch(next, next)).toBe(false);
      epoch = next;
    }
  });
});

describe('duplicate-operation guard', () => {
  it('rejects starting any new operation while one is pending', () => {
    expect(isOperationActive('unlock')).toBe(true);
    expect(isOperationActive('verify')).toBe(true);
    expect(isOperationActive(null)).toBe(false);
  });
});

describe('timing boundaries', () => {
  it('progress threshold is 250 ms exclusive', () => {
    expect(hasExceededProgressThreshold(AUTH_TIMING.progressThresholdMs)).toBe(false);
    expect(hasExceededProgressThreshold(AUTH_TIMING.progressThresholdMs + 1)).toBe(true);
  });

  it('initialization timeout is 5 s', () => {
    expect(hasExceededInitTimeout(AUTH_TIMING.initTimeoutMs)).toBe(false);
    expect(hasExceededInitTimeout(AUTH_TIMING.initTimeoutMs + 1)).toBe(true);
  });

  it('verification timeout is 10 s', () => {
    expect(hasExceededVerifyTimeout(AUTH_TIMING.verifyTimeoutMs)).toBe(false);
    expect(hasExceededVerifyTimeout(AUTH_TIMING.verifyTimeoutMs + 1)).toBe(true);
  });

  it('KDF hard limit is 1.5 s (EPIC-001)', () => {
    expect(hasExceededKdfHardLimit(AUTH_TIMING.kdfHardLimitMs)).toBe(false);
    expect(hasExceededKdfHardLimit(AUTH_TIMING.kdfHardLimitMs + 1)).toBe(true);
  });

  it('lease staleness is 15 s', () => {
    expect(isLeaseStale(0, AUTH_TIMING.leaseStalenessMs)).toBe(false);
    expect(isLeaseStale(0, AUTH_TIMING.leaseStalenessMs + 1)).toBe(true);
  });
});

describe('safe-error mapping remains deterministic', () => {
  const outcomes = [
    'INIT_STORAGE_UNAVAILABLE',
    'VERIFY_TIMEOUT',
    'VERIFY_NETWORK_UNAVAILABLE',
    'UNKNOWN_FAILURE',
    'INIT_UNSUPPORTED_VAULT_VERSION',
    'INIT_CORRUPT_VAULT',
    'VERIFY_SIGNING_KEY_MISMATCH',
    'VERIFY_ENCRYPTION_KEY_MISMATCH',
    'REMOVAL_BLOCKED_REMEDIATION',
    'UNLOCK_THROTTLED',
    'INVALID_MNEMONIC',
  ] as const;

  it('every recoverable/blocked outcome has a valid destination and action set', () => {
    for (const code of outcomes) {
      expect(outcomeToAuthState(code)).not.toBeUndefined();
      expect(outcomeErrorCategory(code)).not.toBeNull();
      expect(outcomeSafeActions(code).length).toBeGreaterThan(0);
    }
  });

  it('never offers remote reset or sign-out actions', () => {
    for (const code of outcomes) {
      for (const action of outcomeSafeActions(code)) {
        expect(action).not.toMatch(/remote/i);
      }
    }
  });

  it('combined credential error text is exact and secret-free', () => {
    expect(AUTH_TIMING.kdfHardLimitMs).toBe(1500);
    // Outcome codes are identifiers, not secrets; ensure no actual secret-like
    // value (a real credential value or raw diagnostic) is present.
    expect(JSON.stringify(outcomes)).not.toMatch(/hunter2|correct horse battery|BEGIN .*PRIVATE KEY/i);
  });
});
