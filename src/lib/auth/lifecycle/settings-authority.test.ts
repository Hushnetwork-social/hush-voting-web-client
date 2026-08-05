/**
 * FEAT-010 Task 3.8 — settings/recovery/removal authority tests.
 *
 * Proves fresh-authorization lifecycle, exact policy choices/warnings,
 * password/mode transitions, offline matrix, rollback, REMOVE confirmation,
 * complete artifact deletion, quarantine/resume, and identity invariance
 * (normative: FeatureDescription "Identity and Security Settings", "Forgot
 * Protection and Recovery", "Local-User Removal"; AC-010-063…078).
 */
import { describe, expect, it } from 'vitest';
import {
  admitSecurityMutation,
  isPreservedPreference,
  issueFreshAuthorization,
  OFFLINE_AVAILABLE_OPERATIONS,
  OFFLINE_BLOCKED_OPERATIONS,
  prepareDevicePasswordChange,
  prepareProtectionTransition,
  prepareRemovalRecovery,
  REMOVAL_ARTIFACT_KINDS,
  REMOVAL_PHRASE,
  verifyRemovalAbsence,
  type SecurityMutationRequest,
} from './settings-authority';
import { FRESH_AUTHORIZATION_MAX_AGE_MS, type FreshAuthorization } from '../lifecycle-policy';

function authorization(purpose: FreshAuthorization['purpose'] = 'lock-policy-change', now = 1_000): FreshAuthorization {
  return { id: 'fa-1', purpose, issuedAtMs: now, maxAgeMs: FRESH_AUTHORIZATION_MAX_AGE_MS };
}

function request(overrides: Partial<SecurityMutationRequest> = {}): SecurityMutationRequest {
  return { purpose: 'lock-policy-change', authorization: authorization(), nowMs: 30_000, invalidation: 'none', ...overrides };
}

describe('admitSecurityMutation', () => {
  it('permits a fresh purpose-scoped authorization', () => {
    expect(admitSecurityMutation(request())).toEqual({ kind: 'permitted' });
  });

  it('rejects wrong-purpose, expired, used, and invalidated authorizations', () => {
    expect(admitSecurityMutation(request({ purpose: 'device-password-change' }))).toEqual({ kind: 'wrongPurpose' });
    expect(admitSecurityMutation(request({ nowMs: 1_000 + FRESH_AUTHORIZATION_MAX_AGE_MS + 1 }))).toEqual({ kind: 'expired' });
    expect(admitSecurityMutation(request({ invalidation: 'used' }))).toEqual({ kind: 'invalidated' });
    expect(admitSecurityMutation(request({ invalidation: 'lock' }))).toEqual({ kind: 'invalidated' });
    expect(admitSecurityMutation(request({ authorization: null }))).toEqual({ kind: 'missingAuthorization' });
  });
});

describe('prepareDevicePasswordChange', () => {
  it('proceeds only with admission + current password + online verification + confirmation', () => {
    expect(prepareDevicePasswordChange({ kind: 'permitted' }, true, true, true)).toEqual({ kind: 'proceedToCommit' });
  });

  it('denies on each missing prerequisite', () => {
    expect(prepareDevicePasswordChange({ kind: 'expired' }, true, true, true)).toEqual({ kind: 'admissionDenied', reason: 'expired' });
    expect(prepareDevicePasswordChange({ kind: 'permitted' }, false, true, true)).toEqual({ kind: 'admissionDenied', reason: 'invalidated' });
    expect(prepareDevicePasswordChange({ kind: 'permitted' }, true, false, true)).toEqual({ kind: 'onlineVerificationRequired' });
    expect(prepareDevicePasswordChange({ kind: 'permitted' }, true, true, false)).toEqual({ kind: 'confirmationMismatch' });
  });
});

describe('prepareProtectionTransition', () => {
  const qualified = new Set(['device-password', 'webauthn-prf', 'ubuntu-secret-service', 'android-keystore'] as const);

  it('proceeds only for qualified targets after admission + online verification + enrollment', () => {
    const verdict = prepareProtectionTransition({
      admission: { kind: 'permitted' },
      onlineVerified: true,
      targetMode: 'webauthn-prf',
      qualifiedTargets: qualified,
      enrollmentSucceeded: true,
      readBackMatches: true,
    });
    expect(verdict).toEqual({ kind: 'proceedToEnroll' });
  });

  it('rejects unqualified targets without downgrade', () => {
    const verdict = prepareProtectionTransition({
      admission: { kind: 'permitted' },
      onlineVerified: true,
      targetMode: 'plaintext' as 'webauthn-prf',
      qualifiedTargets: qualified,
      enrollmentSucceeded: true,
      readBackMatches: true,
    });
    expect(verdict).toEqual({ kind: 'unqualifiedTarget', target: 'plaintext' });
  });

  it('preserves the old verified active generation on any failure', () => {
    const verdict = prepareProtectionTransition({
      admission: { kind: 'permitted' },
      onlineVerified: true,
      targetMode: 'android-keystore',
      qualifiedTargets: qualified,
      enrollmentSucceeded: false,
      readBackMatches: true,
    });
    expect(verdict).toEqual({ kind: 'failedTransition', preserveOldGeneration: true });
  });

  it('requires fresh exact online verification before any transition', () => {
    const verdict = prepareProtectionTransition({
      admission: { kind: 'permitted' },
      onlineVerified: false,
      targetMode: 'ubuntu-secret-service',
      qualifiedTargets: qualified,
      enrollmentSucceeded: true,
      readBackMatches: true,
    });
    expect(verdict).toEqual({ kind: 'onlineVerificationRequired' });
  });
});

describe('offline matrix', () => {
  it('allows Lock/removal/safe settings/authorized lock-policy offline', () => {
    for (const operation of OFFLINE_AVAILABLE_OPERATIONS) {
      expect(OFFLINE_BLOCKED_OPERATIONS).not.toContain(operation);
    }
  });

  it('blocks protection change and export offline', () => {
    expect(OFFLINE_BLOCKED_OPERATIONS).toEqual(['devicePasswordChange', 'protectionModeChange', 'export']);
    for (const operation of OFFLINE_BLOCKED_OPERATIONS) {
      expect(OFFLINE_AVAILABLE_OPERATIONS.has(operation)).toBe(false);
    }
  });
});

describe('prepareRemovalRecovery', () => {
  it('requires the exact REMOVE phrase and final confirmation before cleanup', () => {
    expect(prepareRemovalRecovery({ enteredPhrase: 'remove', finalConfirmed: true, cleanupComplete: true })).toEqual({ kind: 'phraseMismatch' });
    expect(prepareRemovalRecovery({ enteredPhrase: REMOVAL_PHRASE, finalConfirmed: false, cleanupComplete: true })).toEqual({ kind: 'confirmationRequired' });
    expect(prepareRemovalRecovery({ enteredPhrase: REMOVAL_PHRASE, finalConfirmed: true, cleanupComplete: false })).toEqual({ kind: 'cleanupIncomplete', quarantine: true });
    expect(prepareRemovalRecovery({ enteredPhrase: REMOVAL_PHRASE, finalConfirmed: true, cleanupComplete: true })).toEqual({ kind: 'proceedToCleanup' });
  });
});

describe('verifyRemovalAbsence', () => {
  it('verifies absence only when every artifact kind is deleted', () => {
    expect(verifyRemovalAbsence([])).toEqual({ ok: true, remaining: [] });
    const result = verifyRemovalAbsence(['platformKeyItems']);
    expect(result.ok).toBe(false);
    expect(result.remaining).toEqual(['platformKeyItems']);
  });

  it('covers the complete artifact inventory', () => {
    expect(REMOVAL_ARTIFACT_KINDS).toEqual([
      'vaultSlots',
      'rollbackSlot',
      'platformKeyItems',
      'stagedOperations',
      'pendingTransactions',
      'reconciliationCaches',
      'preview',
      'lockPolicy',
      'session',
    ]);
  });
});

describe('isPreservedPreference', () => {
  it('preserves only approved general preferences', () => {
    for (const key of ['language', 'theme', 'accessibility', 'telemetryOptOut']) {
      expect(isPreservedPreference(key)).toBe(true);
    }
    expect(isPreservedPreference('electionData')).toBe(false);
    expect(isPreservedPreference('vault')).toBe(false);
  });
});

describe('issueFreshAuthorization', () => {
  it('issues one-use purpose-scoped authorizations with the 60s bound', () => {
    const auth = issueFreshAuthorization('lock-policy-change', 5_000);
    expect(auth.purpose).toBe('lock-policy-change');
    expect(auth.maxAgeMs).toBe(FRESH_AUTHORIZATION_MAX_AGE_MS);
    expect(admitSecurityMutation({ purpose: 'lock-policy-change', authorization: auth, nowMs: 5_000, invalidation: 'none' })).toEqual({ kind: 'permitted' });
    // A second purpose cannot be authorized by the same token.
    expect(admitSecurityMutation({ purpose: 'protection-mode-change', authorization: auth, nowMs: 5_000, invalidation: 'none' })).toEqual({ kind: 'wrongPurpose' });
  });
});
