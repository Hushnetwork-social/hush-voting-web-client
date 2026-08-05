/**
 * FEAT-007 Task 4.4 — unit/integration tests for navigation and lifecycle
 * control. Coverage: AC-007-011, 037–043, 052, 058–062 (presentation portion).
 */
import { describe, expect, it } from 'vitest';
import {
  canProvisionConcurrently,
  decideHistoryEntry,
  inspectOnboardingToken,
  invalidatePreCreationHistory,
  localUserExistsEvent,
  unifiedBack,
} from './navigation-control';

describe('decideHistoryEntry — one opaque entry per navigation-relevant step', () => {
  it('pushes history only for navigation-relevant steps', () => {
    expect(decideHistoryEntry('createProfile', null)).toEqual({ push: true, destination: 'createProfile' });
    expect(decideHistoryEntry('createReview', null)).toEqual({ push: true, destination: 'createReview' });
  });

  it('never pushes for minor changes (field edits, validation, reveal toggles)', () => {
    for (const minor of ['fieldEdit', 'validationMessage', 'revealToggle', 'acknowledgementToggle'] as const) {
      expect(decideHistoryEntry('createProfile', minor)).toEqual({ push: false, destination: null });
    }
  });
});

describe('unifiedBack — browser/Android/in-app Back share one authority', () => {
  it('does not offer Back at the safe first-run root', () => {
    expect(unifiedBack('createEntry', 1)).toBe('root');
  });

  it('walks the typed creation steps backwards', () => {
    expect(unifiedBack('createReview', 5)).toBe('createProtect');
    expect(unifiedBack('createProtect', 4)).toBe('createConfirmRecovery');
    expect(unifiedBack('createConfirmRecovery', 3)).toBe('createRecovery');
    expect(unifiedBack('createRecovery', 2)).toBe('createGenerate');
    expect(unifiedBack('createGenerate', 2)).toBe('createProfile');
    expect(unifiedBack('createProfile', 2)).toBe('createPreflight');
    expect(unifiedBack('createPreflight', 2)).toBe('createEntry');
  });

  it('never reopens creation from the waiting gate (Back → lock path)', () => {
    expect(unifiedBack('createWaiting', 3)).toBe('locked');
    expect(unifiedBack('createDelay', 3)).toBe('locked');
    expect(unifiedBack('createConnection', 3)).toBe('locked');
  });
});

describe('invalidatePreCreationHistory — after the provisional boundary', () => {
  it('invalidates pre-creation history and locks on Back', () => {
    expect(invalidatePreCreationHistory(3, true)).toEqual({ invalidated: true, safeBackTarget: 'locked' });
  });

  it('leaves history untouched before the boundary', () => {
    expect(invalidatePreCreationHistory(3, false)).toEqual({ invalidated: false, safeBackTarget: null });
  });
});

describe('inspectOnboardingToken — vault-inspection guard', () => {
  it('rejects forged or manually navigated tokens', () => {
    expect(inspectOnboardingToken(false, false)).toEqual({ allowed: false, reason: 'forgedToken' });
  });

  it('blocks first-run creation while a local/provisional user exists', () => {
    expect(inspectOnboardingToken(true, true)).toEqual({ allowed: false, reason: 'localUserExists' });
  });

  it('allows only a valid token with an empty vault', () => {
    expect(inspectOnboardingToken(true, false)).toEqual({ allowed: true, reason: 'ok' });
  });
});

describe('cross-tab ownership', () => {
  it('publishes only the non-secret local-user event', () => {
    const event = localUserExistsEvent();
    expect(event).toEqual({ kind: 'localUserNowExists' });
    expect(JSON.stringify(event)).not.toMatch(/alias|address|transaction|password|mnemonic/i);
  });

  it('prevents concurrent provisioning by a second owner', () => {
    expect(canProvisionConcurrently(1)).toEqual({ allowed: true, reason: 'singleOwner' });
    expect(canProvisionConcurrently(2)).toEqual({ allowed: false, reason: 'multipleOwners' });
  });
});
