/**
 * FEAT-008 Task 3.10 — unit and concurrency tests for navigation, ownership,
 * timeout, and cleanup convergence.
 * Coverage targets: AC-008-001–003, 023, 064–070 (authority portion);
 * Back at every stage, stale tokens, tab/process races, safe notifications,
 * quarantine, verified absence.
 */
import { describe, expect, it } from 'vitest';
import {
  canStartRecovery,
  evaluateBack,
  evaluateCleanup,
  evaluateOwnership,
  isStaleHistoryToken,
  localUserEvent,
  webauthnCleanupHonesty,
  type BackStage,
  type VaultInspection,
} from './convergence.js';

describe('Back policy (root-only navigation)', () => {
  it('clears inputs before Verify', () => {
    const decision = evaluateBack('preVerify');
    expect(decision.action).toBe('clearInputs');
  });

  it('destroys the authority after Verify but before staging', () => {
    const decision = evaluateBack('postVerifyPreStage');
    expect(decision.action).toBe('destroyAuthority');
  });

  it('locks rather than deletes once staged', () => {
    const decision = evaluateBack('staged');
    expect(decision.action).toBe('lock');
  });

  it('covers every typed stage deterministically', () => {
    const stages: BackStage[] = ['preVerify', 'postVerifyPreStage', 'staged'];
    const actions = stages.map((stage) => evaluateBack(stage).action);
    expect(actions).toEqual(['clearInputs', 'destroyAuthority', 'lock']);
  });
});

describe('opaque history tokens', () => {
  it('rejects stale/forged/restored tokens', () => {
    expect(isStaleHistoryToken(null, 'entry-1', new Set(['flow-1']))).toBe(true);
    expect(isStaleHistoryToken('forged', 'entry-1', new Set(['flow-1']))).toBe(true);
    expect(isStaleHistoryToken('entry-1', 'entry-1', new Set(['flow-1']))).toBe(false);
    expect(isStaleHistoryToken('flow-1', 'entry-1', new Set(['flow-1']))).toBe(false);
  });
});

describe('single-owner policy', () => {
  it('grants exactly one owner; non-owners are blocked with a safe reason', () => {
    expect(evaluateOwnership(true, true).kind).toBe('owner');
    expect(evaluateOwnership(false, true).kind).toBe('blocked');
    expect(evaluateOwnership(false, false).kind).toBe('awaitingRelease');
  });

  it('broadcasts only non-secret local-user events', () => {
    const event = localUserEvent('localUserExists');
    expect(event.nonSecretOnly).toBe(true);
    expect(JSON.stringify(event)).not.toMatch(/phrase|candidate|address|profile|credential|transaction/i);
  });
});

describe('cleanup convergence', () => {
  it('opens first-run only after verified absence', () => {
    expect(evaluateCleanup(true, false).ok).toBe(true);
  });

  it('quarantines on cleanup failure or unverified absence', () => {
    const failed = evaluateCleanup(false, false);
    expect(failed.ok).toBe(false);
    if (!failed.ok) {
      expect(failed.code).toBe('CLEANUP_FAILURE');
    }
    expect(evaluateCleanup(true, true).ok).toBe(false);
    expect(evaluateCleanup(false, true).ok).toBe(false);
  });

  it('reports the WebAuthn passkey deletion limit honestly', () => {
    const honesty = webauthnCleanupHonesty();
    expect(honesty.applicationOwnedRemoved).toBe(true);
    expect(honesty.externalPasskeyMayRemain).toBe(true);
  });
});

describe('verified empty-vault guard', () => {
  it('starts recovery only from verified-empty local state', () => {
    const empty: VaultInspection = { kind: 'verifiedEmpty' };
    expect(canStartRecovery(empty).ok).toBe(true);
  });

  it('blocks on active/staged/rollback/tombstone/quarantine/competing authorities', () => {
    const inspections: VaultInspection[] = [
      { kind: 'activeLocalIdentity' },
      { kind: 'stagedOrProvisional' },
      { kind: 'rollbackPending' },
      { kind: 'removalTombstone' },
      { kind: 'quarantined' },
      { kind: 'competingAuthority' },
    ];
    for (const inspection of inspections) {
      const result = canStartRecovery(inspection);
      expect(result.ok).toBe(false);
      if (!result.ok && inspection.kind === 'quarantined') {
        expect(result.code).toBe('QUARANTINED');
      }
    }
  });
});
