/**
 * FEAT-004 browser-vault lifecycle — tombstone-backed local-user removal.
 *
 * Removal is globally locked, transactional, resumable, and verified:
 * 1. revoke all capabilities and Lock every tab (authority-owned);
 * 2. persist the removal tombstone sidecar;
 * 3. delete both slots, the journal, and all staged/preview/throttle/lease/
 *    identity-specific sidecars (tombstone preserved);
 * 4. close/reopen storage and verify required records are absent;
 * 5. clear the tombstone only after verified completion;
 * 6. preserve only approved non-identity preferences.
 *
 * On connection/browser failure the vault stays `RemovalInProgress` and removal
 * resumes on startup. Success is never reported after merely requesting
 * `deleteDatabase()`. Browser deletion is best-effort logical removal, not
 * guaranteed physical flash erasure; removal never changes the on-chain
 * identity.
 *
 * Normative source: FEAT-004 FeatureDescription "Local-User Removal".
 */
import { failure, success, type VaultResult } from '../../vault-core/contracts/results';
import { ALLOWED_SIDECAR_KEYS, VAULT_JOURNAL_KEY, VAULT_SLOT_KEYS } from '../contracts/storage';
import type { VaultStorageSession } from '../storage/wrapper';

const REMOVAL_TOMBSTONE_KEY = 'removalTombstone' as const;

/** Sidecar keys removed on removal (everything except the tombstone itself). */
const REMOVABLE_SIDECARS: readonly string[] = ALLOWED_SIDECAR_KEYS.filter((key) => key !== REMOVAL_TOMBSTONE_KEY);

/** Removal state projected from the tombstone sidecar. */
export type RemovalState = 'none' | 'inProgress';

/** Read the removal state (resume detection on startup). */
export async function readRemovalState(session: VaultStorageSession): Promise<VaultResult<{ readonly state: RemovalState }>> {
  const outcome = await session.readRecord('operationalSidecars', REMOVAL_TOMBSTONE_KEY);
  if (!outcome.ok) {
    return outcome;
  }
  return success({ state: outcome.value.record === undefined ? 'none' : 'inProgress' });
}

/** Begin removal: persist the tombstone BEFORE deleting anything. */
export async function beginRemoval(session: VaultStorageSession): Promise<VaultResult<{ readonly ok: true }>> {
  const write = await session.writeRecord('operationalSidecars', REMOVAL_TOMBSTONE_KEY, { removalInProgress: true });
  return write.ok ? success({ ok: true as const }) : write;
}

/** Delete all vault records while preserving the tombstone. */
async function deleteVaultRecords(session: VaultStorageSession): Promise<VaultResult<{ readonly ok: true }>> {
  for (const slotKey of VAULT_SLOT_KEYS) {
    const deleted = await session.deleteRecord('vaultSlots', slotKey);
    if (!deleted.ok) {
      return deleted;
    }
  }
  const journal = await session.deleteRecord('vaultJournal', VAULT_JOURNAL_KEY);
  if (!journal.ok) {
    return journal;
  }
  for (const sidecar of REMOVABLE_SIDECARS) {
    const deleted = await session.deleteRecord('operationalSidecars', sidecar);
    if (!deleted.ok) {
      return deleted;
    }
  }
  return success({ ok: true });
}

/** Verify required records are absent after deletion (read-back proof). */
async function verifyAbsence(session: VaultStorageSession): Promise<VaultResult<{ readonly ok: true }>> {
  for (const slotKey of VAULT_SLOT_KEYS) {
    const read = await session.readRecord('vaultSlots', slotKey);
    if (!read.ok) {
      return read;
    }
    if (read.value.record !== undefined) {
      return failure('CleanupFailed');
    }
  }
  const journal = await session.readRecord('vaultJournal', VAULT_JOURNAL_KEY);
  if (!journal.ok) {
    return journal;
  }
  if (journal.value.record !== undefined) {
    return failure('CleanupFailed');
  }
  for (const sidecar of REMOVABLE_SIDECARS) {
    const read = await session.readRecord('operationalSidecars', sidecar);
    if (!read.ok) {
      return read;
    }
    if (read.value.record !== undefined) {
      return failure('CleanupFailed');
    }
  }
  return success({ ok: true });
}

/**
 * Execute removal after the tombstone is present. Returns `CleanupFailed` when
 * verification fails; the vault remains `RemovalInProgress` and removal resumes
 * on startup. The tombstone is cleared ONLY after verified completion.
 */
export async function executeRemoval(session: VaultStorageSession): Promise<VaultResult<{ readonly ok: true }>> {
  const state = await readRemovalState(session);
  if (!state.ok) {
    return state;
  }
  if (state.value.state === 'none') {
    return failure('OperationForbidden'); // removal requires a persisted tombstone
  }
  const deleted = await deleteVaultRecords(session);
  if (!deleted.ok) {
    return deleted; // remain RemovalInProgress; resume on startup
  }
  const verified = await verifyAbsence(session);
  if (!verified.ok) {
    return verified;
  }
  const clear = await session.deleteRecord('operationalSidecars', REMOVAL_TOMBSTONE_KEY);
  return clear.ok ? success({ ok: true as const }) : clear;
}

/** Resume an interrupted removal on startup (fail closed otherwise). */
export async function resumeRemovalIfTombstoned(session: VaultStorageSession): Promise<VaultResult<{ readonly ok: true; readonly resumed: boolean }>> {
  const state = await readRemovalState(session);
  if (!state.ok) {
    return state;
  }
  if (state.value.state === 'none') {
    return success({ ok: true, resumed: false });
  }
  const outcome = await executeRemoval(session);
  if (!outcome.ok) {
    return outcome;
  }
  return success({ ok: true, resumed: true });
}
