/**
 * FEAT-010 Task 2.8 — exhaustive lifecycle-policy, fresh-authorization, and
 * evidence-schema tests.
 *
 * Covers every approved policy choice/warning, immediate-lock case, activity
 * class, reconnect step, fresh-authorization purpose/expiry/invalidation,
 * evidence allowlist, and prohibited-identifier rejection (normative:
 * FeatureDescription "Lock and Session Lifecycle", "Observability",
 * "Secret-safe evidence"; AC-010-056…065, 083…090, 097, 099).
 */
import { describe, expect, it } from 'vitest';
import {
  APPROVED_BACKGROUND_CHOICES,
  APPROVED_IDLE_CHOICES,
  BACKGROUND_LOCK_DEFAULT,
  FRESH_AUTHORIZATION_MAX_AGE_MS,
  IDLE_LOCK_DEFAULT,
  RECONNECT_COALESCED_RETRIES,
  RECONNECT_JITTER_INTERVAL_MS,
  RECONNECT_STEPS_MS,
  evaluateFreshAuthorization,
  isNewPolicyAlreadyExceeded,
  prepareLockPolicyMutation,
  requiresOneTimeWarningBackground,
  requiresOneTimeWarningIdle,
  type FreshAuthorization,
  type LockPolicySettings,
} from './lifecycle-policy';
import { validateEvidenceRecord, validateExternalBlockerEntry, type EvidenceRecord } from './evidence';

// ---------------------------------------------------------------------------
// Policy choices, warnings, defaults, reconnect schedule
// ---------------------------------------------------------------------------

describe('lock-policy choices and defaults', () => {
  it('exposes the exact defaults (5 min idle, 30 s background)', () => {
    expect(IDLE_LOCK_DEFAULT).toBe(5);
    expect(BACKGROUND_LOCK_DEFAULT).toBe(30);
  });

  it('exposes the exact approved choices', () => {
    expect(APPROVED_IDLE_CHOICES).toEqual([1, 5, 15, 30, 60, 'until-restart']);
    expect(APPROVED_BACKGROUND_CHOICES).toEqual(['immediate', 30, 120, 300, 900, 'until-restart']);
  });

  it('requires one-time warnings only for weaker-than-default choices', () => {
    expect(requiresOneTimeWarningIdle(1)).toBe(true);
    expect(requiresOneTimeWarningIdle(5)).toBe(false);
    expect(requiresOneTimeWarningIdle(60)).toBe(false);
    expect(requiresOneTimeWarningIdle('until-restart')).toBe(true);

    expect(requiresOneTimeWarningBackground('immediate')).toBe(true);
    expect(requiresOneTimeWarningBackground(30)).toBe(false);
    expect(requiresOneTimeWarningBackground(120)).toBe(false);
    expect(requiresOneTimeWarningBackground(900)).toBe(true);
    expect(requiresOneTimeWarningBackground('until-restart')).toBe(true);
  });

  it('exposes the exact reconnect schedule and bounds', () => {
    expect(RECONNECT_STEPS_MS).toEqual([2_000, 5_000, 10_000, 30_000]);
    expect(RECONNECT_JITTER_INTERVAL_MS).toBe(30_000);
    expect(RECONNECT_COALESCED_RETRIES).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Fresh authorization
// ---------------------------------------------------------------------------

describe('fresh authorization', () => {
  const auth: FreshAuthorization = { id: 'fa-1', purpose: 'lock-policy-change', issuedAtMs: 1_000, maxAgeMs: FRESH_AUTHORIZATION_MAX_AGE_MS };

  it('is valid within its lifetime for its exact purpose', () => {
    expect(evaluateFreshAuthorization(auth, 'lock-policy-change', 30_000, 'none')).toEqual({ kind: 'valid' });
  });

  it('is rejected for a different purpose (one authorization, one purpose)', () => {
    expect(evaluateFreshAuthorization(auth, 'device-password-change', 30_000, 'none')).toEqual({ kind: 'wrongPurpose' });
    expect(evaluateFreshAuthorization(auth, 'protection-mode-change', 30_000, 'none')).toEqual({ kind: 'wrongPurpose' });
    expect(evaluateFreshAuthorization(auth, 'export-elevation', 30_000, 'none')).toEqual({ kind: 'wrongPurpose' });
  });

  it('expires at the 60-second bound', () => {
    expect(evaluateFreshAuthorization(auth, 'lock-policy-change', 1_000 + FRESH_AUTHORIZATION_MAX_AGE_MS + 1, 'none')).toEqual({ kind: 'expired' });
  });

  it('is invalidated by every listed event', () => {
    for (const event of ['used', 'expired', 'navigation', 'foregroundLoss', 'lock', 'epochLoss', 'authorityLoss', 'removal']) {
      expect(evaluateFreshAuthorization(auth, 'lock-policy-change', 30_000, event as 'lock')).toEqual({ kind: 'invalidated' });
    }
  });

  it('rejects missing authorization', () => {
    expect(evaluateFreshAuthorization(null, 'lock-policy-change', 30_000, 'none')).toEqual({ kind: 'invalidated' });
    expect(evaluateFreshAuthorization(undefined, 'lock-policy-change', 30_000, 'none')).toEqual({ kind: 'invalidated' });
  });
});

// ---------------------------------------------------------------------------
// Lock-policy mutation (CAS/read-back/immediate lock)
// ---------------------------------------------------------------------------

describe('lock-policy mutation', () => {
  const current: LockPolicySettings = { idleLock: 5, backgroundLock: 30, generation: 7 };

  it('commits approved choices with matching generation and read-back', () => {
    expect(prepareLockPolicyMutation(current, { idleLock: 15, backgroundLock: 120 }, 7, true)).toEqual({ kind: 'committed' });
  });

  it('rejects unapproved choices', () => {
    expect(prepareLockPolicyMutation(current, { idleLock: 3 as 5, backgroundLock: 30 }, 7, true)).toEqual({ kind: 'invalidChoice' });
    expect(prepareLockPolicyMutation(current, { idleLock: 5, backgroundLock: 45 as 30 }, 7, true)).toEqual({ kind: 'invalidChoice' });
  });

  it('rejects generation conflicts (CAS)', () => {
    expect(prepareLockPolicyMutation(current, { idleLock: 15, backgroundLock: 120 }, 6, true)).toEqual({ kind: 'generationConflict' });
  });

  it('rejects read-back mismatches', () => {
    expect(prepareLockPolicyMutation(current, { idleLock: 15, backgroundLock: 120 }, 7, false)).toEqual({ kind: 'readBackMismatch' });
  });

  it('flags an already-exceeded new threshold for immediate Lock', () => {
    expect(isNewPolicyAlreadyExceeded({ idleLock: 1, backgroundLock: 30, generation: 8 }, 70_000, 0)).toBe(true); // idle 1 min exceeded at 70 s
    expect(isNewPolicyAlreadyExceeded({ idleLock: 30, backgroundLock: 30, generation: 8 }, 70_000, 0)).toBe(false);
    expect(isNewPolicyAlreadyExceeded({ idleLock: 5, backgroundLock: 'immediate', generation: 8 }, 0, 1)).toBe(true); // any background time
    expect(isNewPolicyAlreadyExceeded({ idleLock: 5, backgroundLock: 30, generation: 8 }, 0, 31_000)).toBe(true); // 30 s exceeded
    expect(isNewPolicyAlreadyExceeded({ idleLock: 'until-restart', backgroundLock: 'until-restart', generation: 8 }, 10_000_000, 10_000_000)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Evidence schema
// ---------------------------------------------------------------------------

function validRecord(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    recordId: 'feat010-web-create-001',
    featureId: 'FEAT-010',
    criterionId: 'AC-010-092',
    target: 'web',
    digests: [{ label: 'build-web', digest: 'a'.repeat(64) }],
    result: 'PASS',
    coarseTimingBucketMs: 250,
    ...overrides,
  };
}

describe('validateEvidenceRecord', () => {
  it('accepts a valid secret-safe record', () => {
    expect(validateEvidenceRecord(validRecord()).ok).toBe(true);
  });

  it('rejects prohibited identifiers (alias/full address/endpoint/transaction/file/key/timestamp/secret/device)', () => {
    const cases: Array<Partial<EvidenceRecord>> = [
      { recordId: 'alias:jane' },
      { digests: [{ label: 'signingAddress A1B2C3', digest: 'a'.repeat(64) }] }, // full-address-shaped label
      { recordId: 'endpoint https://x' },
      { recordId: 'txId abc' },
      { recordId: 'sourceUri file.dat' },
      { recordId: 'keyId k1' },
      { recordId: 'issuedAt 123' },
      { recordId: 'mnemonic abandon' },
      { recordId: 'deviceId d1' },
      { criterionId: 'AC-010-092 password x' },
    ];
    for (const overrides of cases) {
      const result = validateEvidenceRecord(validRecord(overrides));
      expect(result.ok).toBe(false);
      expect(result.diagnostics.some((d) => d.code === 'FORBIDDEN_IDENTIFIER')).toBe(true);
    }
  });

  it('rejects invalid targets, results, digests, buckets, and ids', () => {
    expect(validateEvidenceRecord(validRecord({ target: 'emulator' as 'web' })).ok).toBe(false);
    expect(validateEvidenceRecord(validRecord({ result: 'SUCCESS' as 'PASS' })).ok).toBe(false);
    expect(validateEvidenceRecord(validRecord({ digests: [] })).ok).toBe(false);
    expect(validateEvidenceRecord(validRecord({ digests: [{ label: 'build', digest: 'z'.repeat(64) }] })).ok).toBe(false);
    expect(validateEvidenceRecord(validRecord({ coarseTimingBucketMs: -1 })).ok).toBe(false);
    expect(validateEvidenceRecord(validRecord({ criterionId: 'AC-010-0999' })).ok).toBe(false);
    expect(validateEvidenceRecord(validRecord({ featureId: 'FEAT-009' as 'FEAT-010' })).ok).toBe(false);
  });

  it('rejects non-object payloads', () => {
    for (const payload of [null, undefined, 'text', 42, []]) {
      expect(validateEvidenceRecord(payload).ok).toBe(false);
    }
  });
});

describe('validateExternalBlockerEntry', () => {
  it('accepts truthful PASS/FAIL/NOT_SUPPLIED entries', () => {
    for (const state of ['PASS', 'FAIL', 'NOT_SUPPLIED']) {
      const result = validateExternalBlockerEntry({ id: 'EXT-009-001', owner: 'hush-server-node', state, releaseImpact: 'server hardening' });
      expect(result.ok).toBe(true);
    }
  });

  it('rejects fabricated or malformed states', () => {
    const result = validateExternalBlockerEntry({ id: 'EXT-009-001', owner: 'x', state: 'DONE', releaseImpact: 'y' });
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_RESULT' });
  });

  it('rejects unknown blocker ids', () => {
    const result = validateExternalBlockerEntry({ id: 'NOT-A-BLOCKER', owner: 'x', state: 'NOT_SUPPLIED', releaseImpact: 'y' });
    expect(result.ok).toBe(false);
  });

  it('rejects secret-shaped content in blocker entries', () => {
    const result = validateExternalBlockerEntry({ id: 'EXT-009-001', owner: 'x', state: 'NOT_SUPPLIED', releaseImpact: 'server at https://x' });
    expect(result.ok).toBe(false);
    expect(result.diagnostics.some((d) => d.code === 'FORBIDDEN_IDENTIFIER')).toBe(true);
  });
});
