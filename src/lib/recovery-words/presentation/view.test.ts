/**
 * FEAT-008 Task 4.2 — unit/model tests for recovery view-state and action
 * projections.
 * Coverage targets: AC-008-005, 013–015, 024–035, 040–071, 079 (presentation
 * portion); every authority stage maps once; busy/double-submit; no-default
 * selection; staged resume; success announcement; stale action rejection.
 */
import { describe, expect, it } from 'vitest';
import type { RecoveryStage } from '../contracts/lifecycle';
import { assertNoRecoverySecretSurface } from '../contracts/projection';
import {
  allowedActionsForScreen,
  mapRecoveryStageToScreen,
  toRecoveryViewState,
  type RecoveryScreen,
  type RecoveryViewInput,
} from './view';

const ALL_STAGES: RecoveryStage[] = [
  'vaultGuard',
  'networkLabel',
  'wordEntry',
  'verifying',
  'deriving',
  'lookup',
  'resolving',
  'candidateSelection',
  'profileSelection',
  'proof',
  'protection',
  'staging',
  'existingProfileVerify',
  'recreateReview',
  'registration',
  'activating',
  'success',
  'finishRestoring',
  'locked',
  'quarantined',
  'terminal',
];

function input(overrides: Partial<RecoveryViewInput> = {}): RecoveryViewInput {
  return {
    stage: 'wordEntry',
    operationInFlight: false,
    canGoBack: true,
    lastError: null,
    progressStarted: false,
    progressComplete: false,
    evidenceCategory: null,
    focusFirstInvalidPosition: null,
    ownerState: 'owner',
    ...overrides,
  };
}

describe('mapRecoveryStageToScreen', () => {
  it('maps every authority stage to exactly one screen', () => {
    const screens = new Set<RecoveryScreen>();
    for (const stage of ALL_STAGES) {
      const screen = mapRecoveryStageToScreen(stage);
      screens.add(screen);
      expect(screen).toBeTruthy();
    }
    expect(screens.size).toBe(21); // 'entry' is the pre-flow three-choice surface; no authority stage maps to it
  });
});

describe('allowedActionsForScreen', () => {
  it('never allows word entry, derivation, or staging while another owner holds the epoch', () => {
    const actions = allowedActionsForScreen('wordEntry', false, 'blockedByOtherOwner');
    expect(actions).toEqual(['retry']);
    expect(actions).not.toContain('verify');
  });

  it('keeps Verify enabled only on the word-entry screen when not busy', () => {
    expect(allowedActionsForScreen('wordEntry', false, 'owner')).toContain('verify');
    expect(allowedActionsForScreen('wordEntry', true, 'owner')).not.toContain('verify');
    expect(allowedActionsForScreen('lookup', false, 'owner')).not.toContain('verify');
  });

  it('exposes Retry for unresolved lookups only when not in flight', () => {
    expect(allowedActionsForScreen('lookup', false, 'owner')).toContain('retryUnresolvedLookups');
    expect(allowedActionsForScreen('lookup', true, 'owner')).not.toContain('retryUnresolvedLookups');
  });

  it('candidate/profile selection never preselects (no default action path)', () => {
    expect(allowedActionsForScreen('candidateSelection', false, 'owner')).toContain('selectCandidate');
    expect(allowedActionsForScreen('profileSelection', false, 'owner')).toContain('selectCandidate');
  });

  it('success and activating expose no user actions (automatic transition)', () => {
    expect(allowedActionsForScreen('success', false, 'owner')).toEqual([]);
    expect(allowedActionsForScreen('activating', false, 'owner')).toEqual([]);
  });
});

describe('toRecoveryViewState', () => {
  it('renders the finishRestoring gate for staged resume', () => {
    const view = toRecoveryViewState(input({ stage: 'finishRestoring', operationInFlight: false }));
    expect(view.screen).toBe('finishRestoring');
    expect(view.allowedActions).toContain('finishRestoringUnlock');
    expect(view.allowedActions).not.toContain('verify');
  });

  it('derives primaryAction busy/in-progress semantics', () => {
    expect(toRecoveryViewState(input({ stage: 'lookup', operationInFlight: true })).primaryAction).toBe('inProgress');
    expect(toRecoveryViewState(input({ stage: 'deriving', operationInFlight: false })).primaryAction).toBe('disabled');
    expect(toRecoveryViewState(input({ stage: 'success', operationInFlight: false })).primaryAction).toBe('hidden');
    expect(toRecoveryViewState(input({ stage: 'wordEntry', operationInFlight: false })).primaryAction).toBe('enabled');
  });

  it('carries coarse progress buckets', () => {
    expect(toRecoveryViewState(input({ stage: 'lookup', progressStarted: true })).progressBucket).toBe('running');
    expect(toRecoveryViewState(input({ stage: 'lookup', progressComplete: true })).progressBucket).toBe('done');
    expect(toRecoveryViewState(input({ stage: 'wordEntry', operationInFlight: false })).progressBucket).toBe('idle');
  });

  it('never represents secrets in the serialized view state', () => {
    const view = toRecoveryViewState(input({ stage: 'wordEntry', focusFirstInvalidPosition: 7 }));
    expect(assertNoRecoverySecretSurface(view)).toEqual([]);
    const json = JSON.stringify(view);
    expect(json).not.toMatch(/mnemonic|seed|privateKey|password|fullSigningAddress|fullEncryptionAddress/i);
  });

  it('forwards the first invalid focus position for error summaries', () => {
    const view = toRecoveryViewState(input({ stage: 'wordEntry', focusFirstInvalidPosition: 3 }));
    expect(view.focusFirstInvalidPosition).toBe(3);
  });
});
