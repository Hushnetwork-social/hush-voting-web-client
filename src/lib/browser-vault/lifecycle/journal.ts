/**
 * FEAT-004 browser-vault lifecycle — atomic two-slot journal over the wrapper.
 *
 * Implements the FEAT-003 reference journal semantics on the production
 * browser storage wrapper: read active generation, construct the complete
 * encrypted candidate for the inactive fixed slot, write it, read back and
 * verify schema/canonical bytes/ciphertext authentication/generations, then
 * atomically CAS-switch the journal pointer. The previous verified slot is
 * retained as the single bounded rollback slot. A generation mismatch returns
 * `GenerationConflict` and reloads authoritative state. Rollback recovery
 * requires explicit later confirmation and renewed verification before atomic
 * reactivation; obsolete rollback is removed only under the next-success/24 h
 * rule.
 *
 * Raw ciphertext verification is injected (`verifyCandidate`) so this layer
 * stays deterministic; the production verifier (decrypt + canonical checks)
 * lands with the secret authority (Phase 4/7) but the contract is fixed now.
 *
 * Normative source: FEAT-004 FeatureDescription "Atomic two-slot mutation",
 * "Rollback Recovery"; FEAT-003 `lifecycle/journal.ts`.
 */
import { failure, success, type VaultResult } from '../../vault-core/contracts/results';
import {
  VAULT_JOURNAL_KEY,
  type VaultJournalRecord,
  type VaultSlotKey,
} from '../contracts/storage';
import type { VaultStorageSession } from '../storage/wrapper';

/** One encrypted slot record stored under a fixed slot key. */
export interface EncryptedSlotRecord {
  readonly slotKey: VaultSlotKey;
  readonly generation: number;
  readonly bytes: Uint8Array;
}

/** Readable journal state (non-secret). */
export interface BrowserJournalState {
  readonly activeGeneration: number;
  readonly activeSlot: VaultSlotKey;
  readonly hasRollback: boolean;
}

/** Injected verification used for read-back checks and rollback promotion. */
export interface JournalPorts {
  /** Verify an encrypted candidate fully (schema, canonical bytes, auth, generations). */
  readonly verifyCandidate: (bytes: Uint8Array, generation: number) => Promise<boolean>;
  readonly nowMs: () => number;
  /** Obsolete-rollback cleanup window (ms). */
  readonly rollbackCleanupMs?: number;
}

const DEFAULT_ROLLBACK_CLEANUP_MS = 24 * 60 * 60 * 1000;

/** Atomic journal bound to one open storage session. */
export interface AtomicJournal {
  readonly readState: () => Promise<VaultResult<BrowserJournalState>>;
  readonly commit: (params: {
    readonly expectedGeneration: number;
    readonly candidateGeneration: number;
    readonly candidateBytes: Uint8Array;
  }) => Promise<VaultResult<{ readonly activeGeneration: number }>>;
  readonly readRollbackCandidate: () => Promise<VaultResult<{ readonly slotKey: VaultSlotKey; readonly bytes: Uint8Array } | null>>;
  /** Explicitly confirmed rollback recovery: re-verify and atomically reactivate. */
  readonly promoteRollback: (params: { readonly confirmed: boolean; readonly expectedGeneration: number; readonly rollbackBytes: Uint8Array }) => Promise<VaultResult<{ readonly activeGeneration: number }>>;
  /** Next-success/24 h obsolete-rollback cleanup (window enforced). */
  readonly cleanupObsoleteRollback: (params?: { readonly verifiedAtMs: number }) => Promise<VaultResult<{ readonly ok: true; readonly retained: boolean }>>;
}

function inactiveSlotOf(active: VaultSlotKey): VaultSlotKey {
  return active === 'slot-a' ? 'slot-b' : 'slot-a';
}

function isJournalRecord(value: unknown): value is VaultJournalRecord {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as VaultJournalRecord;
  return typeof record.generation === 'number' && (record.activeSlot === 'slot-a' || record.activeSlot === 'slot-b');
}

async function readJournalRecord(session: VaultStorageSession): Promise<VaultResult<{ readonly record: VaultJournalRecord | null }>> {
  const outcome = await session.readRecord('vaultJournal', VAULT_JOURNAL_KEY);
  if (!outcome.ok) {
    return outcome;
  }
  const value = outcome.value.record;
  if (value === undefined) {
    return success({ record: null });
  }
  if (!isJournalRecord(value)) {
    return failure('StorageUnavailable');
  }
  return success({ record: value });
}

/** Normalize any byte view into a same-realm Uint8Array (cross-realm safe). */
function normalizeBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value) && (value as { BYTES_PER_ELEMENT?: number }).BYTES_PER_ELEMENT === 1) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  return null;
}

async function readSlot(session: VaultStorageSession, slotKey: VaultSlotKey): Promise<VaultResult<{ readonly record: EncryptedSlotRecord | null }>> {
  const outcome = await session.readRecord('vaultSlots', slotKey);
  if (!outcome.ok) {
    return outcome;
  }
  const value = outcome.value.record;
  if (value === undefined) {
    return success({ record: null });
  }
  if (typeof value !== 'object' || value === null || typeof (value as EncryptedSlotRecord).generation !== 'number') {
    return failure('StorageUnavailable');
  }
  const bytes = normalizeBytes((value as EncryptedSlotRecord).bytes);
  if (bytes === null) {
    return failure('StorageUnavailable');
  }
  return success({ record: { slotKey, generation: (value as EncryptedSlotRecord).generation, bytes } });
}

/** Create the atomic journal over an open session. */
export function createAtomicJournal(session: VaultStorageSession, ports: JournalPorts): AtomicJournal {
  const readState = async (): Promise<VaultResult<BrowserJournalState>> => {
    const journal = await readJournalRecord(session);
    if (!journal.ok) {
      return journal;
    }
    if (journal.value.record === null) {
      return success({ activeGeneration: 0, activeSlot: 'slot-a', hasRollback: false });
    }
    const activeSlot = journal.value.record.activeSlot;
    const rollbackKey = inactiveSlotOf(activeSlot);
    const rollback = await readSlot(session, rollbackKey);
    if (!rollback.ok) {
      return rollback;
    }
    return success({
      activeGeneration: journal.value.record.generation,
      activeSlot,
      hasRollback: rollback.value.record !== null,
    });
  };

  const commit = async (params: {
    readonly expectedGeneration: number;
    readonly candidateGeneration: number;
    readonly candidateBytes: Uint8Array;
  }): Promise<VaultResult<{ readonly activeGeneration: number }>> => {
    if (params.candidateGeneration <= 0 || params.candidateGeneration !== params.expectedGeneration + 1) {
      return failure('GenerationConflict');
    }
    const state = await readState();
    if (!state.ok) {
      return state;
    }
    if (state.value.activeGeneration !== params.expectedGeneration) {
      return failure('GenerationConflict');
    }
    const inactive = inactiveSlotOf(state.value.activeSlot);

    // 1. Write the complete candidate to the inactive slot (pointer unchanged).
    const candidate: EncryptedSlotRecord = { slotKey: inactive, generation: params.candidateGeneration, bytes: params.candidateBytes };
    const write = await session.writeRecord('vaultSlots', inactive, candidate);
    if (!write.ok) {
      return write;
    }

    // 2. Read back and verify the staged slot fully.
    const readBack = await readSlot(session, inactive);
    if (!readBack.ok) {
      return readBack;
    }
    if (readBack.value.record === null || readBack.value.record.generation !== params.candidateGeneration) {
      return failure('StorageUnavailable');
    }
    const verified = await ports.verifyCandidate(readBack.value.record.bytes, params.candidateGeneration);
    if (!verified) {
      return failure('StorageUnavailable');
    }

    // 3. Atomically switch the journal pointer (CAS on the expected generation).
    const cas = await session.casJournal(
      { generation: state.value.activeGeneration, activeSlot: state.value.activeSlot },
      { generation: params.candidateGeneration, activeSlot: inactive },
    );
    if (!cas.ok) {
      return cas; // GenerationConflict or storage failure; previous slot remains authoritative
    }
    return success({ activeGeneration: params.candidateGeneration });
  };

  const readRollbackCandidate = async (): Promise<VaultResult<{ readonly slotKey: VaultSlotKey; readonly bytes: Uint8Array } | null>> => {
    const state = await readState();
    if (!state.ok) {
      return state;
    }
    if (state.value.activeGeneration === 0) {
      return success(null);
    }
    const rollbackKey = inactiveSlotOf(state.value.activeSlot);
    const rollback = await readSlot(session, rollbackKey);
    if (!rollback.ok) {
      return rollback;
    }
    if (rollback.value.record === null) {
      return success(null);
    }
    return success({ slotKey: rollbackKey, bytes: rollback.value.record.bytes });
  };

  const promoteRollback = async (params: {
    readonly confirmed: boolean;
    readonly expectedGeneration: number;
    readonly rollbackBytes: Uint8Array;
  }): Promise<VaultResult<{ readonly activeGeneration: number }>> => {
    if (!params.confirmed) {
      return failure('OperationForbidden'); // explicit confirmation is mandatory
    }
    const state = await readState();
    if (!state.ok) {
      return state;
    }
    const rollbackKey = inactiveSlotOf(state.value.activeSlot);
    const rollback = await readSlot(session, rollbackKey);
    if (!rollback.ok) {
      return rollback;
    }
    if (rollback.value.record === null || rollback.value.record.generation !== params.expectedGeneration) {
      return failure('GenerationConflict');
    }
    const verified = await ports.verifyCandidate(params.rollbackBytes, params.expectedGeneration);
    if (!verified) {
      return failure('StorageUnavailable'); // damaged rollback cannot be reactivated
    }
    // Atomically reactivate: swap the pointer back to the rollback slot.
    const cas = await session.casJournal(
      { generation: state.value.activeGeneration, activeSlot: state.value.activeSlot },
      { generation: params.expectedGeneration, activeSlot: rollbackKey },
    );
    if (!cas.ok) {
      return cas;
    }
    return success({ activeGeneration: params.expectedGeneration });
  };

  /** Next-success/24 h obsolete-rollback cleanup (window enforced). */
  const cleanupObsoleteRollback = async (params?: { readonly verifiedAtMs: number }): Promise<VaultResult<{ readonly ok: true; readonly retained: boolean }>> => {
    const state = await readState();
    if (!state.ok) {
      return state;
    }
    const rollbackKey = inactiveSlotOf(state.value.activeSlot);
    const cleanupMs = ports.rollbackCleanupMs ?? DEFAULT_ROLLBACK_CLEANUP_MS;
    const rollback = await readSlot(session, rollbackKey);
    if (!rollback.ok) {
      return rollback;
    }
    if (rollback.value.record === null) {
      return success({ ok: true, retained: false });
    }
    // FEAT-003 next-success/24 h rule: the obsolete rollback slot is removed
    // only after the new active slot was successfully verified AND the window
    // since that verification has elapsed. Without a verified-at timestamp the
    // rollback is retained (fail-safe: never delete the only recovery slot).
    if (params === undefined || params.verifiedAtMs <= 0 || ports.nowMs() - params.verifiedAtMs < cleanupMs) {
      return success({ ok: true, retained: true });
    }
    const deleted = await session.deleteRecord('vaultSlots', rollbackKey);
    return deleted.ok ? success({ ok: true as const, retained: false }) : deleted;
  };

  return { readState, commit, readRollbackCandidate, promoteRollback, cleanupObsoleteRollback };
}

export { inactiveSlotOf, isJournalRecord };
