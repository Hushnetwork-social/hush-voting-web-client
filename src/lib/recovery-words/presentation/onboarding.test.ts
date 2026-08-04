/**
 * FEAT-008 Task 4.4 — unit/integration tests for recovery child-actor
 * registration and view-state composition with authentication/navigation.
 * Coverage targets: AC-008-001–004, 016–017, 023, 054–071 (presentation
 * portion); production synthetic-actor exclusion, kind assertion, completion
 * mapping, staged gate.
 */
import { describe, expect, it } from 'vitest';
import {
  assertRecoveryWordsKind,
  completionResult,
  composeRecoveryView,
  RECOVERY_WORDS_ACTOR_REGISTRATION,
  surfaceForStaged,
  validateRecoveryWordsRegistration,
} from './onboarding.js';
import { assertNoRecoverySecretSurface } from '../contracts/projection';

describe('recovery words actor registration', () => {
  it('is mandatory and non-synthetic in production', () => {
    expect(RECOVERY_WORDS_ACTOR_REGISTRATION.capability).toBe('onboardingRestoreRecoveryWords');
    expect(RECOVERY_WORDS_ACTOR_REGISTRATION.availability).toBe('mandatory');
    expect(RECOVERY_WORDS_ACTOR_REGISTRATION.synthetic).toBe(false);
  });

  it('rejects duplicate and synthetic registrations (fail closed)', () => {
    expect(validateRecoveryWordsRegistration(false, false)).toEqual({ ok: true });
    expect(validateRecoveryWordsRegistration(true, false)).toEqual({ ok: false, code: 'DUPLICATE' });
    expect(validateRecoveryWordsRegistration(false, true)).toEqual({ ok: false, code: 'SYNTHETIC_IN_PRODUCTION' });
  });

  it('accepts only the recovery-words onboarding kind', () => {
    expect(assertRecoveryWordsKind('restoreRecoveryWords')).toEqual({ ok: true });
    expect(assertRecoveryWordsKind('createUser')).toEqual({ ok: false, code: 'WRONG_ONBOARDING_KIND' });
    expect(assertRecoveryWordsKind('restoreCredentialFile')).toEqual({ ok: false, code: 'WRONG_ONBOARDING_KIND' });
  });
});

describe('completion mapping', () => {
  it('maps restored/created/session states to ONBOARDING_COMPLETED', () => {
    expect(completionResult('restoredExistingProfile')).toEqual({ code: 'ONBOARDING_COMPLETED', localUserRef: 'recovery:restoredExistingProfile' });
    expect(completionResult('createdMissingProfile').code).toBe('ONBOARDING_COMPLETED');
    expect(completionResult('sessionOnlyRestored').code).toBe('ONBOARDING_COMPLETED');
  });

  it('maps cancellation to ONBOARDING_BACK and quarantine to a safe failure', () => {
    expect(completionResult('cancelled')).toEqual({ code: 'ONBOARDING_BACK' });
    expect(completionResult('quarantined')).toEqual({ code: 'UNKNOWN_FAILURE', supportCode: 'RW-QUARANTINE-1' });
  });
});

describe('staged resume surface gate', () => {
  it('shows finishRestoring while staged data exists; never first-run/word entry', () => {
    expect(surfaceForStaged(true, false)).toBe('finishRestoring');
    expect(surfaceForStaged(true, true)).toBe('wordEntry'); // corrupted → fail-closed re-entry
    expect(surfaceForStaged(false, false)).toBe('wordEntry');
  });
});

describe('view composition', () => {
  it('composes one closed view with safe remediation copy for typed errors', () => {
    const view = composeRecoveryView('wordEntry', {
      operationInFlight: false,
      canGoBack: true,
      lastError: { code: 'UNKNOWN_WORD', message: 'x' },
      progressStarted: false,
      progressComplete: false,
      evidenceCategory: null,
      focusFirstInvalidPosition: 2,
      ownerState: 'owner',
    });
    expect(view.screen).toBe('wordEntry');
    expect(view.error?.code).toBe('UNKNOWN_WORD');
    // Remediation copy is bounded and safe; never echoes the word values.
    expect(view.error?.message).not.toMatch(/abandon|ability|zoo/i);
    expect(view.focusFirstInvalidPosition).toBe(2);
    expect(assertNoRecoverySecretSurface(view)).toEqual([]);
  });
});
