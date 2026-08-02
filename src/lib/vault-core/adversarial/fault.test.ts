/**
 * FEAT-003 exhaustive fault-injection and lifecycle gates (Task 7.3).
 *
 * Exercises every persistence transition edge:
 * - the full write/verify/switch fault matrix for both first provisioning and
 *   generation commits (every combination of failing step);
 * - the complete lifecycle transition inventory with verification variants;
 * - resumable/idempotent removal, rollback bounds, cleanup boundaries, and
 *   password-change invariants.
 *
 * Fault schedules are exhaustive (not sampled): every observable step either fails
 * or succeeds, and the deterministic outcome must preserve the last verified slots,
 * never produce partial plaintext or false success, and never destroy recoverable
 * state.
 */
import { describe, expect, it } from 'vitest';
import { journalCommit, verifyNewSlotOnStartup, cleanupObsoleteSlot, type JournalState } from '../lifecycle/journal';
import {
  stagePendingRegistration,
  beginSubmission,
  reconcileToActive,
  completeRemoval,
  passwordChangeCommit,
  type LifecycleState,
} from '../lifecycle/transitions';

function emptyState(): JournalState {
  return { activeSlot: null, rollbackSlot: null, activeGeneration: 0, newSlotVerified: false };
}
function slot(gen: number) {
  return { generation: gen, bytes: new Uint8Array([gen]) };
}
function ports(write: boolean, verify: boolean, switchActive: boolean) {
  return { writeInactive: () => write, verifyInactive: () => verify, switchActive: () => switchActive };
}

describe('FEAT-003 exhaustive journal fault matrix', () => {
  it('first provisioning: every write/verify/switch failure combination preserves an empty, recoverable state', () => {
    for (const write of [true, false]) {
      for (const verify of [true, false]) {
        for (const switchOk of [true, false]) {
          const out = journalCommit(emptyState(), 0, slot(1), ports(write, verify, switchOk));
          if (write && verify && switchOk) {
            expect(out.ok).toBe(true);
            if (out.ok) {
              expect(out.state.activeGeneration).toBe(1);
              expect(out.state.activeSlot?.generation).toBe(1);
              expect(out.state.rollbackSlot).toBeNull();
            }
          } else {
            expect(out.ok).toBe(false);
            if (!out.ok) {
              // Failure must never produce a partial active slot.
              expect(out.state.activeSlot).toBeNull();
              expect(out.state.activeGeneration).toBe(0);
            }
          }
        }
      }
    }
  });

  it('generation commit: every fault schedule retains the last verified slots and never reports false success', () => {
    const committed = journalCommit(emptyState(), 0, slot(1), ports(true, true, true));
    if (!committed.ok) throw new Error('setup failed');
    for (const write of [true, false]) {
      for (const verify of [true, false]) {
        for (const switchOk of [true, false]) {
          const out = journalCommit(committed.state, 1, slot(2), ports(write, verify, switchOk));
          if (write && verify && switchOk) {
            expect(out.ok).toBe(true);
            if (out.ok) {
              expect(out.state.activeGeneration).toBe(2);
              expect(out.state.activeSlot?.generation).toBe(2);
              // Previous verified active becomes the single rollback slot.
              expect(out.state.rollbackSlot?.generation).toBe(1);
            }
          } else {
            expect(out.ok).toBe(false);
            if (!out.ok) {
              expect(out.state.activeGeneration).toBe(1);
              expect(out.state.activeSlot?.generation).toBe(1);
              expect(out.state.rollbackSlot).toBeNull();
            }
          }
        }
      }
    }
  });

  it('stale-generation and non-increasing commits are rejected before any step runs', () => {
    const committed = journalCommit(emptyState(), 0, slot(1), ports(true, true, true));
    if (!committed.ok) throw new Error('setup failed');
    const stale = journalCommit(committed.state, 0, slot(2), ports(true, true, true));
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.code).toBe('GENERATION_CONFLICT');
    const nonIncreasing = journalCommit(committed.state, 1, slot(1), ports(true, true, true));
    expect(nonIncreasing.ok).toBe(false);
    if (!nonIncreasing.ok) expect(nonIncreasing.code).toBe('GENERATION_CONFLICT');
  });

  it('rollback bounds: at most one rollback slot is retained across successive commits', () => {
    let state = emptyState();
    for (let gen = 1; gen <= 5; gen++) {
      const out = journalCommit(state, gen - 1, slot(gen), ports(true, true, true));
      if (!out.ok) throw new Error(`commit ${gen} failed`);
      state = out.state;
    }
    expect(state.activeGeneration).toBe(5);
    // Exactly one rollback slot (generation 4).
    expect(state.rollbackSlot?.generation).toBe(4);
  });

  it('obsolete-slot cleanup: after startup verification or the 24-hour boundary, rollback is removed', () => {
    const committed = journalCommit(emptyState(), 0, slot(1), ports(true, true, true));
    if (!committed.ok) throw new Error('setup failed');
    const committed2 = journalCommit(committed.state, 1, slot(2), ports(true, true, true));
    if (!committed2.ok) throw new Error('setup failed');
    // Startup verification authorizes immediate cleanup.
    const verified = verifyNewSlotOnStartup(committed2.state);
    expect(cleanupObsoleteSlot(verified, 0, 0).rollbackSlot).toBeNull();
    // 24h boundary without verification also authorizes cleanup.
    const aged = cleanupObsoleteSlot(committed2.state, 25 * 3600 * 1000, 0);
    expect(aged.rollbackSlot).toBeNull();
    // Before both, the rollback slot is retained.
    expect(cleanupObsoleteSlot(committed2.state, 3600 * 1000, 0).rollbackSlot).not.toBeNull();
  });
});

describe('FEAT-003 lifecycle transition inventory (Task 7.4 coverage)', () => {
  const noVault: LifecycleState = { status: 'NoVault', pendingSubmission: false };
  const pending: LifecycleState = { status: 'PendingRegistration', pendingSubmission: false };

  it('covers every documented transition with verification variants', () => {
    // NoVault -> PendingRegistration (verified / unverified / wrong source state).
    expect(stagePendingRegistration(noVault, true).ok).toBe(true);
    expect(stagePendingRegistration(noVault, false).ok).toBe(false);
    expect(stagePendingRegistration(pending, true).ok).toBe(false);
    // PendingRegistration -> beginSubmission (pending submission marker).
    const submitting = beginSubmission(pending);
    expect(submitting.ok).toBe(true);
    if (submitting.ok) expect(submitting.state.pendingSubmission).toBe(true);
    expect(beginSubmission(noVault).ok).toBe(false);
    // PendingRegistration -> Active (confirmed / unconfirmed / wrong source).
    expect(reconcileToActive(pending, true).ok).toBe(true);
    expect(reconcileToActive(pending, false).ok).toBe(false);
    expect(reconcileToActive(noVault, true).ok).toBe(false);
    // -> NoVault (removal), idempotent from every state.
    expect(completeRemoval({ status: 'Active', pendingSubmission: false }).ok).toBe(true);
    expect(completeRemoval(pending).ok).toBe(true);
    expect(completeRemoval(noVault).ok).toBe(true);
  });

  it('password change rewraps without re-encrypting payloads or changing identity', () => {
    const commit = passwordChangeCommit(2);
    expect(commit.rewrappedRecordCount).toBe(2);
    expect(commit.payloadsReEncrypted).toBe(0);
    expect(commit.identityChanged).toBe(false);
  });
});
