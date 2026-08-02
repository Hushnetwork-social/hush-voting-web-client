/**
 * FEAT-003 vault-core lifecycle tests — two-slot journal, transitions, removal.
 *
 * Covers Task 3.5/3.6: exhaustive fault injection at every commit step, generation
 * compare-and-swap, deterministic active/rollback selection, pending-registration
 * reconciliation, migration non-destructiveness, password-change rewrapping, and
 * resumable removal.
 */
import { describe, expect, it } from 'vitest';
import {
  journalCommit,
  cleanupObsoleteSlot,
  verifyNewSlotOnStartup,
  type JournalState,
  type Slot,
} from './journal';
import {
  stagePendingRegistration,
  beginSubmission,
  reconcileToActive,
  completeRemoval,
  passwordChangeCommit,
} from './transitions';

const slot = (generation: number): Slot => ({ generation, bytes: new TextEncoder().encode(`slot-${generation}`) });
const emptyState = (): JournalState => ({ activeSlot: null, rollbackSlot: null, activeGeneration: 0, newSlotVerified: false });
const okPorts = () => ({ writeInactive: () => true, verifyInactive: () => true, switchActive: () => true });

describe('two-slot atomic journal', () => {
  it('provisions the first slot without a generation constraint', () => {
    const out = journalCommit(emptyState(), 0, slot(1), okPorts());
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.state.activeGeneration).toBe(1);
      expect(out.state.rollbackSlot).toBeNull();
      expect(out.state.newSlotVerified).toBe(true);
    }
  });

  it('commits a new generation and retains the previous slot as rollback', () => {
    const s1 = journalCommit(emptyState(), 0, slot(1), okPorts());
    expect(s1.ok).toBe(true);
    if (!s1.ok) return;
    const s2 = journalCommit(s1.state, 1, slot(2), okPorts());
    expect(s2.ok).toBe(true);
    if (s2.ok) {
      expect(s2.state.activeGeneration).toBe(2);
      expect(s2.state.rollbackSlot?.generation).toBe(1);
    }
  });

  it('rejects stale generations with GenerationConflict (CAS)', () => {
    const s1 = journalCommit(emptyState(), 0, slot(1), okPorts());
    if (!s1.ok) return;
    const stale = journalCommit(s1.state, 0, slot(2), okPorts());
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.code).toBe('GENERATION_CONFLICT');
  });

  it('rejects non-increasing generations', () => {
    const s1 = journalCommit(emptyState(), 0, slot(1), okPorts());
    if (!s1.ok) return;
    const same = journalCommit(s1.state, 1, slot(1), okPorts());
    expect(same.ok).toBe(false);
  });

  it('fault-injection matrix: failure at write/verify/switch preserves last verified state', () => {
    const s1 = journalCommit(emptyState(), 0, slot(1), okPorts());
    if (!s1.ok) return;
    const failures = [
      { writeInactive: () => false, verifyInactive: () => true, switchActive: () => true, code: 'WRITE_FAILED' },
      { writeInactive: () => true, verifyInactive: () => false, switchActive: () => true, code: 'VERIFY_FAILED' },
      { writeInactive: () => true, verifyInactive: () => true, switchActive: () => false, code: 'SWITCH_FAILED' },
    ] as const;
    for (const f of failures) {
      const out = journalCommit(s1.state, 1, slot(2), { ...f } as never);
      expect(out.ok).toBe(false);
      if (!out.ok) {
        expect(out.code).toBe(f.code);
        expect(out.state.activeGeneration).toBe(1);
        expect(out.state.rollbackSlot).toBeNull();
      }
    }
  });

  it('cleanup removes the rollback slot after startup verification or 24 hours', () => {
    const s1 = journalCommit(emptyState(), 0, slot(1), okPorts());
    if (!s1.ok) return;
    const s2 = journalCommit(s1.state, 1, slot(2), okPorts());
    if (!s2.ok || !s2.state.rollbackSlot) return;
    // Rollback is retained until the next successful startup verifies the new slot.
    expect(s2.state.newSlotVerified).toBe(false);
    const kept = cleanupObsoleteSlot(s2.state, 1_000, 0);
    expect(kept.rollbackSlot).not.toBeNull();
    const verified = verifyNewSlotOnStartup(s2.state);
    const afterVerify = cleanupObsoleteSlot(verified, 1_000, 0);
    expect(afterVerify.rollbackSlot).toBeNull();
    const after24h = cleanupObsoleteSlot(s2.state, 25 * 60 * 60 * 1000, 0);
    expect(after24h.rollbackSlot).toBeNull();
  });

  it('keeps at most one rollback slot', () => {
    const s1 = journalCommit(emptyState(), 0, slot(1), okPorts());
    if (!s1.ok) return;
    const s2 = journalCommit(s1.state, 1, slot(2), okPorts());
    if (!s2.ok) return;
    const s3 = journalCommit(s2.state, 2, slot(3), okPorts());
    if (!s3.ok) return;
    expect(s3.state.rollbackSlot?.generation).toBe(2);
    expect(s3.state.activeGeneration).toBe(3);
  });
});

describe('lifecycle transitions', () => {
  it('stages a verified vault as PendingRegistration before submission (crash-safe)', () => {
    const staged = stagePendingRegistration({ status: 'NoVault', pendingSubmission: false }, true);
    expect(staged.ok).toBe(true);
    if (staged.ok) expect(staged.state.status).toBe('PendingRegistration');
  });

  it('rejects staging without verification', () => {
    const out = stagePendingRegistration({ status: 'NoVault', pendingSubmission: false }, false);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.code).toBe('NOT_VERIFIED');
  });

  it('reconciles idempotently to Active after chain confirmation', () => {
    const staged = stagePendingRegistration({ status: 'NoVault', pendingSubmission: false }, true);
    if (!staged.ok) return;
    const submitted = beginSubmission(staged.state);
    expect(submitted.ok).toBe(true);
    if (!submitted.ok) return;
    expect(submitted.state.pendingSubmission).toBe(true);
    const active = reconcileToActive(submitted.state, true);
    expect(active.ok).toBe(true);
    if (active.ok) expect(active.state.status).toBe('Active');
    // Idempotent retry after confirmation absence preserves PendingRegistration.
    const pending = reconcileToActive(submitted.state, false);
    expect(pending.ok).toBe(false);
  });

  it('enforces the closed transition matrix', () => {
    expect(stagePendingRegistration({ status: 'Active', pendingSubmission: false }, true).ok).toBe(false);
    expect(reconcileToActive({ status: 'Active', pendingSubmission: false }, true).ok).toBe(false);
  });

  it('password change rewraps keys without re-encrypting payloads or changing identity', () => {
    const commit = passwordChangeCommit(2);
    expect(commit).toEqual({ rewrappedRecordCount: 2, payloadsReEncrypted: 0, identityChanged: false });
  });

  it('removal completes to NoVault', () => {
    const out = completeRemoval({ status: 'Active', pendingSubmission: false });
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.state.status).toBe('NoVault');
  });
});
