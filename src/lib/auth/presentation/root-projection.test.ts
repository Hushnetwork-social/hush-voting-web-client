/**
 * FEAT-010 Task 4.2 — root/onboarding/verification/navigation projection tests.
 *
 * Proves every state-to-screen mapping, unknown fail-closed path, child kind,
 * staged resume, verification outcome, Back cleanup state, safe destination,
 * and forbidden field (normative: FeatureDescription "Typed Onboarding
 * Composition", "Startup and Reconciliation", "Navigation and Back";
 * AC-010-007…013, 024…026, 035, 039…043, 083…087).
 */
import { describe, expect, it } from 'vitest';
import {
  projectChildBack,
  projectRootScreen,
  projectStagedResume,
  safeResumeDestination,
  STAGED_RESUME_TITLES,
  type RootStateView,
} from './root-projection';

const states: Array<[RootStateView, string]> = [
    [{ phase: 'initializing' }, 'startup'],
    [{ phase: 'noLocalUser' }, 'firstRun'],
    [{ phase: 'onboarding', childKind: 'createUser' }, 'childFlow'],
    [{ phase: 'onboarding', childKind: 'recoveryWords' }, 'childFlow'],
    [{ phase: 'onboarding', childKind: 'credentialFile' }, 'childFlow'],
    [{ phase: 'verifying', retryAllowed: true }, 'verification'],
    [{ phase: 'missingProfile' }, 'missingProfile'],
    [{ phase: 'quarantine', quarantineReason: 'contradictory' }, 'quarantine'],
    [{ phase: 'blocked', supportCode: 'BLOCK-X' }, 'blocked'],
    [{ phase: 'locked' }, 'locked'],
    [{ phase: 'authenticated' }, 'home'],
];

describe('projectRootScreen', () => {
  it('maps every phase to exactly one closed screen', () => {
    for (const [state, kind] of states) {
      expect(projectRootScreen(state).kind).toBe(kind);
    }
  });

  it('never uses Setting up… as a fallback for a missing child projection', () => {
    const result = projectRootScreen({ phase: 'onboarding' });
    expect(result.kind).toBe('blocked');
    if (result.kind === 'blocked') {
      expect(result.supportCode).toBe('ROOT-NO-CHILD');
    }
  });

  it('fails closed with a bounded support code on blocked states', () => {
    const result = projectRootScreen({ phase: 'blocked' });
    expect(result).toEqual({ kind: 'blocked', supportCode: 'ROOT-BLOCKED' });
  });

  it('projects quarantine with the exact reason', () => {
    expect(projectRootScreen({ phase: 'quarantine', quarantineReason: 'incompleteRemoval' })).toEqual({ kind: 'quarantine', reason: 'incompleteRemoval' });
  });
});

describe('projectStagedResume', () => {
  it('uses exact staged titles', () => {
    expect(projectStagedResume('createUser').title).toBe('Resume creating your identity');
    expect(projectStagedResume('recoveryWords').title).toBe('Finish restoring your identity');
    expect(projectStagedResume('credentialFile').title).toBe('Finish restoring your identity');
    expect(STAGED_RESUME_TITLES.recoveryWords).toBe(STAGED_RESUME_TITLES.credentialFile);
  });
});

describe('safeResumeDestination', () => {
  it('permits only home and settings landing after fresh authentication', () => {
    expect(safeResumeDestination('home')).toBe('home');
    expect(safeResumeDestination('settingsLanding')).toBe('settingsLanding');
  });

  it('restarts every sensitive destination', () => {
    for (const destination of ['devicePasswordForm', 'protectionChange', 'freshAuthPrompt', 'export', 'removalConfirmation', 'revealedContent', 'pendingOperation', null, undefined]) {
      expect(safeResumeDestination(destination)).toBeNull();
    }
  });
});

describe('projectChildBack', () => {
  it('waits for child cleanup before returning to first-run', () => {
    expect(projectChildBack(false)).toEqual({ kind: 'cleanupPending' });
    expect(projectChildBack(true)).toEqual({ kind: 'cleanupComplete' });
  });
});

describe('projection secret-boundary', () => {
  it('produces no secret-shaped fields across the root projection space', () => {
    const serialized = JSON.stringify({
      screens: states.map(([state]) => projectRootScreen(state)),
      staged: projectStagedResume('recoveryWords'),
    });
    for (const marker of ['password', 'mnemonic', 'privateKey', 'seed', 'transaction', 'endpoint', 'authority', 'capability']) {
      expect(serialized.toLowerCase()).not.toContain(marker);
    }
  });
});
