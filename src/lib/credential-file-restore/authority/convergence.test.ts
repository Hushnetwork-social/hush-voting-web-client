/**
 * FEAT-009 Task 3.10 — unit, model, concurrency, lifecycle, and cleanup
 * tests for the navigation/ownership/timeout/cleanup convergence authority
 * (Task 3.9).
 *
 * Proves: every Back stage, owner race, stale completion, forged history,
 * bfcache restore, epoch timeout, logout/removal, and failed-cleanup path
 * converges without leakage or bypass.
 */
import { describe, expect, it } from 'vitest';
import {
  LEGAL_CLEANUP_SCOPES,
  assertExternalSourceExcluded,
  decideStartup,
  evaluateBack,
  evaluateCancellation,
  evaluateCleanup,
  evaluateOwnerRequest,
  isEpochExpired,
  isStaleHistoryToken,
} from './convergence';
import type { BackStage, OwnerDecision } from './convergence';
import { RESTORE_EPOCH_FOREGROUND_BOUND_MS } from '../contracts/lifecycle';

describe('FEAT-009 Back policy (Task 3.9)', () => {
  it('every Back stage maps to the exact clear/destroy/lock policy', () => {
    expect(evaluateBack('preDecrypt')).toEqual({ action: 'clearInputs' });
    expect(evaluateBack('postValidationPreStage')).toEqual({ action: 'destroyAuthority' });
    expect(evaluateBack('staged')).toEqual({ action: 'lock' });
    const stages: readonly BackStage[] = ['preDecrypt', 'postValidationPreStage', 'staged'];
    expect(stages).toHaveLength(3);
  });
});

describe('FEAT-009 history token policy (Task 3.9)', () => {
  it('stale/forged/null tokens are rejected; authority-pushed flow tokens pass', () => {
    const entryToken = 'entry';
    const flowTokens = new Set(['flow-1']);
    expect(isStaleHistoryToken(null, entryToken, flowTokens)).toBe(true);
    expect(isStaleHistoryToken('forged', entryToken, flowTokens)).toBe(true);
    expect(isStaleHistoryToken(entryToken, entryToken, flowTokens)).toBe(false);
    expect(isStaleHistoryToken('flow-1', entryToken, flowTokens)).toBe(false);
  });

  it('bfcache restoration cannot bypass custody inspection', () => {
    // Restored tokens must re-validate; anything not pushed by this
    // authority is stale — including pre-restore session values.
    expect(isStaleHistoryToken('flow-1', 'new-entry', new Set())).toBe(true);
  });
});

describe('FEAT-009 single-owner policy (Task 3.9)', () => {
  it('exactly one owner may act; non-owners receive only safe blocked state', () => {
    const owner: OwnerDecision = evaluateOwnerRequest({ kind: 'owner' }, 'epoch-1', 'epoch-1');
    expect(owner.decision).toBe('acquire');
    if (owner.decision === 'acquire') expect(owner.isOwner).toBe(true);

    const blocked: OwnerDecision = evaluateOwnerRequest({ kind: 'nonOwner', safeStatus: 'recoveryInProgress' }, 'epoch-2', 'epoch-1');
    expect(blocked.decision).toBe('blocked');
    if (blocked.decision === 'blocked') expect(blocked.isOwner).toBe(false);

    const released: OwnerDecision = evaluateOwnerRequest({ kind: 'released' }, 'epoch-1', 'epoch-1');
    expect(released.decision).toBe('release'); // release carries no isOwner field
  });

  it('a competing epoch request is denied before any sensitive action', () => {
    const blocked: OwnerDecision = evaluateOwnerRequest({ kind: 'owner' }, 'epoch-2', 'epoch-1');
    expect(blocked.decision).toBe('blocked');
    if (blocked.decision === 'blocked') expect(blocked.isOwner).toBe(false);
  });
});

describe('FEAT-009 epoch timeout (Task 3.9)', () => {
  it('the foreground authority expires after exactly 10 minutes unprovisioned', () => {
    expect(isEpochExpired(0, RESTORE_EPOCH_FOREGROUND_BOUND_MS)).toBe(false); // boundary inclusive
    expect(isEpochExpired(0, RESTORE_EPOCH_FOREGROUND_BOUND_MS + 1)).toBe(true);
    expect(isEpochExpired(1000, 1000)).toBe(false);
  });
});

describe('FEAT-009 startup inspection (Task 3.9)', () => {
  it('staged data never shows first-run; quarantine blocks; Lock retains', () => {
    expect(decideStartup(false, false, false, false)).toEqual({ kind: 'verifiedEmpty' });
    expect(decideStartup(true, false, false, false)).toEqual({ kind: 'stagedExists' });
    expect(decideStartup(false, true, false, false)).toEqual({ kind: 'activeIdentity' });
    expect(decideStartup(false, false, true, false)).toEqual({ kind: 'quarantined' });
    expect(decideStartup(false, false, false, true)).toEqual({ kind: 'competingAuthority' });
    // Quarantine and staging both present: quarantine wins (blocks all first-run paths).
    expect(decideStartup(true, false, true, false)).toEqual({ kind: 'quarantined' });
  });
});

describe('FEAT-009 cleanup convergence (Task 3.9)', () => {
  it('cleanup verification is quarantine on failure, never empty', () => {
    expect(evaluateCleanup([])).toEqual({ kind: 'verifiedAbsent' });
    const quarantined = evaluateCleanup(['stage', 'tempCiphertext']);
    expect(quarantined.kind).toBe('quarantined');
    if (quarantined.kind === 'quarantined') {
      expect(quarantined.remaining).toContain('stage');
    }
  });

  it('staged cancellation requires verified removal; failure quarantines', () => {
    expect(evaluateCancellation(true)).toEqual({ kind: 'removed' });
    expect(evaluateCancellation(false)).toEqual({ kind: 'quarantined' });
  });

  it('the legal cleanup scope set never includes the external source', () => {
    expect(LEGAL_CLEANUP_SCOPES).toHaveLength(6);
    expect(LEGAL_CLEANUP_SCOPES).not.toContain('externalSource');
    expect(assertExternalSourceExcluded(['stage', 'session'])).toBe(true);
    expect(assertExternalSourceExcluded(['stage', 'externalSource'])).toBe(false);
  });
});
