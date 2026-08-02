/**
 * FEAT-004 atomic journal tests — fault injection at every boundary.
 *
 * Proves: first provisioning, generation-checked commits, inactive-write +
 * read-back verification + pointer CAS, single bounded rollback slot,
 * `GenerationConflict` on stale generation, explicit rollback promotion with
 * renewed verification, damaged-rollback rejection, and next-success/24 h
 * cleanup. Uses fake-indexeddb for fast supplementary coverage; real-browser
 * storage lifecycle coverage lands in Phase 7.
 *
 * Normative source: FEAT-004 FeatureDescription "Atomic two-slot mutation",
 * "Rollback Recovery"; Task 3.6 behavior specification.
 */
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { VAULT_DATABASE_NAME, VAULT_SLOT_KEYS } from '../contracts/storage';
import { openVaultStorage, type VaultStorageSession } from '../storage/wrapper';
import { createAtomicJournal, type JournalPorts } from './journal';

async function openSession(): Promise<VaultStorageSession> {
  const outcome = await openVaultStorage(indexedDB);
  if (!outcome.ok) {
    throw new Error(`open failed: ${outcome.code}`);
  }
  return outcome.value.session;
}

function verifyPorts(verify: (bytes: Uint8Array, generation: number) => boolean = () => true): JournalPorts {
  return { verifyCandidate: async (bytes, generation) => verify(bytes, generation), nowMs: () => Date.now() };
}

/** Deterministic encrypted-looking candidate bytes for a generation. */
function candidateBytes(generation: number): Uint8Array {
  return new Uint8Array([generation, generation, 0xaa, 0xbb]);
}

afterEach(() => {
  indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
});

describe('atomic journal — first provisioning', () => {
  it('provisions the first slot and sets the pointer', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts());
    const outcome = await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.value.activeGeneration).toBe(1);
    }
    const state = await journal.readState();
    expect(state.ok).toBe(true);
    if (state.ok) {
      expect(state.value.activeGeneration).toBe(1);
      // The first real slot lands in the inactive position (slot-b when the
      // implicit initial pointer is slot-a), per the FEAT-003 reference model.
      expect(state.value.activeSlot).toBe('slot-b');
      expect(state.value.hasRollback).toBe(false);
    }
    session.close();
  });

  it('rejects a first-provision with a non-1 generation', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts());
    const outcome = await journal.commit({ expectedGeneration: 0, candidateGeneration: 5, candidateBytes: candidateBytes(5) });
    expect(outcome.ok).toBe(false);
    session.close();
  });
});

describe('atomic journal — generation-checked mutations', () => {
  it('commits sequentially and retains the previous slot as rollback', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts());
    await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    const second = await journal.commit({ expectedGeneration: 1, candidateGeneration: 2, candidateBytes: candidateBytes(2) });
    expect(second.ok).toBe(true);
    const state = await journal.readState();
    if (state.ok) {
      expect(state.value.activeGeneration).toBe(2);
      expect(state.value.activeSlot).toBe('slot-a'); // second slot flips back
      expect(state.value.hasRollback).toBe(true);
    }
    const rollback = await journal.readRollbackCandidate();
    expect(rollback.ok).toBe(true);
    if (rollback.ok && rollback.value) {
      expect(rollback.value.slotKey).toBe('slot-b');
      expect(Array.from(rollback.value.bytes)).toEqual(Array.from(candidateBytes(1)));
    }
    session.close();
  });

  it('returns GenerationConflict on a stale expected generation and preserves the active slot', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts());
    await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    await journal.commit({ expectedGeneration: 1, candidateGeneration: 2, candidateBytes: candidateBytes(2) });
    const stale = await journal.commit({ expectedGeneration: 1, candidateGeneration: 2, candidateBytes: candidateBytes(2) });
    expect(stale.ok).toBe(false);
    if (!stale.ok) {
      expect(stale.code).toBe('GenerationConflict');
    }
    const state = await journal.readState();
    if (state.ok) {
      expect(state.value.activeGeneration).toBe(2); // authoritative state unchanged
    }
    session.close();
  });

  it('fails closed when read-back verification fails (candidate not promoted)', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts((_bytes, generation) => generation !== 2));
    await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    const outcome = await journal.commit({ expectedGeneration: 1, candidateGeneration: 2, candidateBytes: candidateBytes(2) });
    expect(outcome.ok).toBe(false);
    const state = await journal.readState();
    if (state.ok) {
      expect(state.value.activeGeneration).toBe(1); // previous slot remains authoritative
    }
    session.close();
  });
});

describe('atomic journal — rollback recovery', () => {
  it('reactivates a verified rollback only after explicit confirmation', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts());
    await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    await journal.commit({ expectedGeneration: 1, candidateGeneration: 2, candidateBytes: candidateBytes(2) });
    const rollback = await journal.readRollbackCandidate();
    expect(rollback.ok).toBe(true);
    if (!rollback.ok || !rollback.value) {
      throw new Error('rollback candidate missing');
    }

    const unconfirmed = await journal.promoteRollback({ confirmed: false, expectedGeneration: 1, rollbackBytes: rollback.value.bytes });
    expect(unconfirmed.ok).toBe(false); // explicit confirmation mandatory

    const promoted = await journal.promoteRollback({ confirmed: true, expectedGeneration: 1, rollbackBytes: rollback.value.bytes });
    expect(promoted.ok).toBe(true);
    if (promoted.ok) {
      expect(promoted.value.activeGeneration).toBe(1);
    }
    const state = await journal.readState();
    if (state.ok) {
      expect(state.value.activeGeneration).toBe(1);
      expect(state.value.activeSlot).toBe('slot-b');
    }
    session.close();
  });

  it('rejects a damaged rollback (verification failure)', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts((bytes) => bytes[0] !== 0x99));
    await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    const damaged = new Uint8Array([0x99, 0x99, 0x99, 0x99]);
    const outcome = await journal.promoteRollback({ confirmed: true, expectedGeneration: 1, rollbackBytes: damaged });
    expect(outcome.ok).toBe(false);
    session.close();
  });
});

describe('atomic journal — obsolete rollback cleanup', () => {
  it('removes the obsolete rollback slot while keeping the active slot', async () => {
    const session = await openSession();
    const journal = createAtomicJournal(session, verifyPorts());
    await journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: candidateBytes(1) });
    await journal.commit({ expectedGeneration: 1, candidateGeneration: 2, candidateBytes: candidateBytes(2) });
    const cleanup = await journal.cleanupObsoleteRollback();
    expect(cleanup.ok).toBe(true);
    const rollback = await journal.readRollbackCandidate();
    expect(rollback.ok).toBe(true);
    if (rollback.ok) {
      expect(rollback.value).toBeNull();
    }
    const state = await journal.readState();
    if (state.ok) {
      expect(state.value.activeGeneration).toBe(2);
    }
    // Active slot bytes remain readable.
    for (const slotKey of VAULT_SLOT_KEYS) {
      const read = await session.readRecord('vaultSlots', slotKey);
      expect(read.ok).toBe(true);
    }
    session.close();
  });
});
