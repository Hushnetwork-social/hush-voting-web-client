/**
 * FEAT-007 Task 4.2 — unit/model tests for actor and view-state mapping.
 * Coverage: AC-007-001–002, 016, 021, 023, 031, 039, 043–044, 061–067
 * (presentation portion).
 */
import { describe, expect, it } from 'vitest';
import { CREATE_USER_ACTOR_REGISTRATION, mapStageToScreen, toViewState, validateCreateUserRegistration } from './presentation.js';

describe('mapStageToScreen — deterministic screen model', () => {
  it('maps every creation stage to exactly one screen', () => {
    const cases: ReadonlyArray<[Parameters<typeof mapStageToScreen>[0], string]> = [
      ['preflight', 'preflight'],
      ['profile', 'profile'],
      ['generating', 'generate'],
      ['recovery', 'recovery'],
      ['protect', 'protect'],
      ['review', 'review'],
      ['provisionalResume', 'finishCreating'],
      ['waiting', 'waiting'],
      ['delay', 'delay'],
      ['connection', 'connection'],
      ['correcting', 'correcting'],
      ['cancelling', 'cancelling'],
      ['locked', 'locked'],
      ['terminal', 'locked'],
    ];
    for (const [stage, screen] of cases) {
      expect(mapStageToScreen(stage)).toBe(screen);
    }
  });
});

describe('toViewState — safe action/error/progress model', () => {
  const base = {
    stage: 'profile' as const,
    canGoBack: true,
    operationInFlight: false,
    lastError: null,
    progressStarted: false,
    progressComplete: false,
    localBoundaryCrossed: false,
    evidenceCategory: null,
  };

  it('shows an enabled primary action on interactive screens', () => {
    const v = toViewState(base);
    expect(v.screen).toBe('profile');
    expect(v.primaryAction).toBe('enabled');
  });

  it('disables the action while an operation is in flight (no double dispatch)', () => {
    expect(toViewState({ ...base, operationInFlight: true }).primaryAction).toBe('inProgress');
  });

  it('disables the action on busy waiting/connection/preflight screens', () => {
    expect(toViewState({ ...base, stage: 'waiting' }).primaryAction).toBe('disabled');
    expect(toViewState({ ...base, stage: 'connection' }).primaryAction).toBe('disabled');
    expect(toViewState({ ...base, stage: 'preflight' }).primaryAction).toBe('disabled');
  });

  it('hides the action on locked/terminal surfaces', () => {
    expect(toViewState({ ...base, stage: 'locked' }).primaryAction).toBe('hidden');
    expect(toViewState({ ...base, stage: 'terminal' }).primaryAction).toBe('hidden');
  });

  it('reports progress only after the 150 ms threshold (coarse buckets)', () => {
    expect(toViewState({ ...base, progressStarted: false, progressComplete: false, operationInFlight: false }).progressBucket).toBe('idle');
    expect(toViewState({ ...base, operationInFlight: true, progressStarted: false }).progressBucket).toBe('pending');
    expect(toViewState({ ...base, progressStarted: true, progressComplete: false }).progressBucket).toBe('running');
    expect(toViewState({ ...base, progressComplete: true }).progressBucket).toBe('done');
  });

  it('never leaks a secret into the view state (safe error surface only)', () => {
    const v = toViewState({ ...base, lastError: { code: 'PASSWORD_POLICY', message: 'password too short' } });
    expect(v.error).toEqual({ code: 'PASSWORD_POLICY', message: 'password too short' });
    expect(JSON.stringify(v)).not.toMatch(/mnemonic|privateKey|transactionJson|signature/i);
  });

  it('flags the local boundary for history invalidation', () => {
    expect(toViewState({ ...base, stage: 'waiting', localBoundaryCrossed: true }).localBoundaryCrossed).toBe(true);
  });
});

describe('create-user actor registration', () => {
  it('is mandatory, non-synthetic, and exactly one', () => {
    expect(CREATE_USER_ACTOR_REGISTRATION).toEqual({ capability: 'onboardingCreateUser', availability: 'mandatory', synthetic: false });
  });

  it('rejects duplicates and synthetic actors in production (fail closed)', () => {
    expect(validateCreateUserRegistration(false, false)).toEqual({ ok: true });
    expect(validateCreateUserRegistration(true, false)).toEqual({ ok: false, code: 'DUPLICATE' });
    expect(validateCreateUserRegistration(false, true)).toEqual({ ok: false, code: 'SYNTHETIC_IN_PRODUCTION' });
  });
});
