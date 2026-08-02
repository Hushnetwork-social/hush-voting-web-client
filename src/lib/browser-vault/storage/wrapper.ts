/**
 * FEAT-004 browser-vault storage — narrow transactional wrapper.
 *
 * The sole access path to IndexedDB: a narrow typed wrapper over native
 * IndexedDB with no general ORM. The wrapper owns transaction
 * completion/abort, connection lifecycle, compare-and-swap primitives, and
 * safe exception mapping to the closed FEAT-003 result vocabulary. No general
 * workflow may open IndexedDB directly. Raw DOM/platform exceptions never
 * cross this boundary.
 *
 * Data requirements: bounded fixed-key records only; every key passes
 * `assertAllowedStorageKey`. On quota/abort/version-change the wrapper returns
 * typed results and leaves active/required rollback records untouched.
 *
 * Normative source: FEAT-004 FeatureDescription "IndexedDB Storage Model",
 * "Atomic two-slot mutation", "Failure and quota behavior".
 */
import { success, failure, type VaultResult } from '../../vault-core/contracts/results';
import {
  VAULT_JOURNAL_KEY,
  assertAllowedStorageKey,
  classifyStorageError,
  storageFailureToVaultResult,
  type VaultJournalRecord,
  type VaultSlotKey,
  type VaultStoreName,
} from '../contracts/storage';
import { assertSchemaMatches, openVaultDatabase } from './schema';

/** Runtime transaction options accepted by the wrapper. */
export interface VaultTransactionOptions {
  readonly durability?: IDBTransactionMode;
}

/**
 * One open vault storage session. Owns a single connection; exactly one
 * logical writer may hold it at a time (authority-owned, see coordination).
 */
export interface VaultStorageSession {
  readonly databaseName: string;
  readonly schemaVersion: number;
  readRecord(store: VaultStoreName, key: string): Promise<VaultResult<{ readonly record: unknown }>>;
  writeRecord(store: VaultStoreName, key: string, value: unknown): Promise<VaultResult<{ readonly ok: true }>>;
  deleteRecord(store: VaultStoreName, key: string): Promise<VaultResult<{ readonly ok: true }>>;
  clearStore(store: VaultStoreName): Promise<VaultResult<{ readonly ok: true }>>;
  /** Compare-and-swap the journal pointer under one bounded transaction. */
  casJournal(expected: VaultJournalRecord, next: VaultJournalRecord): Promise<VaultResult<{ readonly ok: true }>>;
  /** Generic compare-and-swap over an allowlisted key (used by coordination leases). */
  casRecord(store: VaultStoreName, key: string, expected: unknown, next: unknown, equal?: (a: unknown, b: unknown) => boolean): Promise<VaultResult<{ readonly ok: true }>>;
  readJournal(): Promise<VaultResult<{ readonly journal: VaultJournalRecord | null }>>;
  close(): void;
}

interface OpenedSession {
  readonly db: IDBDatabase;
  readonly session: VaultStorageSession;
}

/** Open the vault database and return a typed wrapper session. */
export async function openVaultStorage(
  factory: IDBFactory,
  options: { readonly onBlocked?: () => void } = {},
): Promise<VaultResult<{ readonly session: VaultStorageSession }>> {
  try {
    const db = await openVaultDatabase(factory, {
      onBlocked: options.onBlocked ?? (() => undefined),
      onVersionChange: () => undefined,
    });
    const opened: OpenedSession = { db, session: createSession(db) };
    return success({ session: opened.session });
  } catch (error) {
    return storageFailureToVaultResult(classifyStorageError(error));
  }
}

/** Run one request inside a bounded transaction with completion/abort mapping. */
function runTransaction<T>(
  db: IDBDatabase,
  store: VaultStoreName,
  mode: IDBTransactionMode,
  work: (objectStore: IDBObjectStore) => IDBRequest<unknown> | void,
): Promise<VaultResult<{ readonly value?: T }>> {
  return new Promise((resolve) => {
    let transaction: IDBTransaction;
    try {
      transaction = db.transaction(store, mode);
    } catch (error) {
      resolve(storageFailureToVaultResult(classifyStorageError(error)));
      return;
    }
    const objectStore = transaction.objectStore(store);
    let request: IDBRequest<unknown> | void;
    try {
      request = work(objectStore);
    } catch (error) {
      transaction.abort();
      resolve(storageFailureToVaultResult(classifyStorageError(error)));
      return;
    }
    let result: { readonly value?: T } = {};
    transaction.oncomplete = () => {
      resolve(success({ ...result }));
    };
    transaction.onerror = () => {
      resolve(storageFailureToVaultResult(classifyStorageError(transaction.error)));
    };
    transaction.onabort = () => {
      resolve(storageFailureToVaultResult(classifyStorageError(transaction.error)));
    };
    if (request && typeof request.onsuccess !== 'undefined') {
      request.onsuccess = () => {
        result = { value: request.result as T };
      };
    }
  });
}

function createSession(db: IDBDatabase): VaultStorageSession {
  const readRecord: VaultStorageSession['readRecord'] = async (store, key) => {
    try {
      assertAllowedStorageKey(store, key);
    } catch {
      return failure('OperationForbidden');
    }
    const outcome = await runTransaction<unknown>(db, store, 'readonly', (objectStore) => objectStore.get(key) as unknown as IDBRequest<unknown>);
    if (!outcome.ok) {
      return outcome;
    }
    return success({ record: outcome.value?.value });
  };

  const writeRecord: VaultStorageSession['writeRecord'] = async (store, key, value) => {
    try {
      assertAllowedStorageKey(store, key);
    } catch {
      return failure('OperationForbidden');
    }
    const outcome = await runTransaction<unknown>(db, store, 'readwrite', (objectStore) => objectStore.put(value, key) as unknown as IDBRequest<unknown>);
    return outcome.ok ? success({ ok: true as const }) : outcome;
  };

  const deleteRecord: VaultStorageSession['deleteRecord'] = async (store, key) => {
    try {
      assertAllowedStorageKey(store, key);
    } catch {
      return failure('OperationForbidden');
    }
    const outcome = await runTransaction<unknown>(db, store, 'readwrite', (objectStore) => objectStore.delete(key) as unknown as IDBRequest<unknown>);
    return outcome.ok ? success({ ok: true as const }) : outcome;
  };

  const clearStore: VaultStorageSession['clearStore'] = async (store) => {
    const outcome = await runTransaction<unknown>(db, store, 'readwrite', (objectStore) => objectStore.clear() as unknown as IDBRequest<unknown>);
    return outcome.ok ? success({ ok: true as const }) : outcome;
  };

  /** Generic CAS over an allowlisted key; `equal` defaults to deep JSON equality. */
  const casRecord: VaultStorageSession['casRecord'] = async (store, key, expected, next, equal) => {
    try {
      assertAllowedStorageKey(store, key);
    } catch {
      return failure('OperationForbidden');
    }
    const matches = equal ?? ((a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b));
    return new Promise((resolve) => {
      let conflict = false;
      let transaction: IDBTransaction;
      try {
        transaction = db.transaction(store, 'readwrite');
      } catch (error) {
        resolve(storageFailureToVaultResult(classifyStorageError(error)));
        return;
      }
      const objectStore = transaction.objectStore(store);
      const getRequest = objectStore.get(key);
      getRequest.onsuccess = () => {
        const current = getRequest.result;
        if (!matches(current, expected)) {
          conflict = true;
          transaction.abort();
          return;
        }
        objectStore.put(next, key);
      };
      transaction.oncomplete = () => resolve(success({ ok: true as const }));
      transaction.onerror = () => resolve(storageFailureToVaultResult(classifyStorageError(transaction.error)));
      transaction.onabort = () => {
        resolve(
          conflict
            ? failure('GenerationConflict')
            : storageFailureToVaultResult(classifyStorageError(transaction.error ?? new DOMException('aborted', 'AbortError'))),
        );
      };
    });
  };

  const readJournal = async (): Promise<VaultResult<{ readonly journal: VaultJournalRecord | null }>> => {
    const outcome = await runTransaction<unknown>(db, 'vaultJournal', 'readonly', (objectStore) =>
      objectStore.get(VAULT_JOURNAL_KEY),
    );
    if (!outcome.ok) {
      return outcome;
    }
    const value = outcome.value?.value as VaultJournalRecord | undefined;
    if (value === undefined) {
      return success({ journal: null });
    }
    if (typeof value !== 'object' || value === null || typeof (value as VaultJournalRecord).generation !== 'number') {
      return failure('StorageUnavailable');
    }
    return success({ journal: value });
  };

  /** CAS: reread expected generation and atomically switch the journal pointer. */
  const casJournal = async (expected: VaultJournalRecord, next: VaultJournalRecord): Promise<VaultResult<{ readonly ok: true }>> => {
    if (typeof expected.generation !== 'number' || typeof next.generation !== 'number' || !Number.isFinite(expected.generation) || !Number.isFinite(next.generation) || next.generation < 0) {
      return failure('GenerationConflict');
    }
    // Transition policy (forward-only vs verified rollback) is owned by the
    // journal layer; the wrapper CAS guarantees atomicity only.
    return new Promise((resolve) => {
      let conflict = false;
      let transaction: IDBTransaction;
      try {
        transaction = db.transaction('vaultJournal', 'readwrite');
      } catch (error) {
        resolve(storageFailureToVaultResult(classifyStorageError(error)));
        return;
      }
      const journal = transaction.objectStore('vaultJournal');
      const getRequest = journal.get(VAULT_JOURNAL_KEY);
      getRequest.onsuccess = () => {
        const current = getRequest.result as VaultJournalRecord | undefined;
        if (current !== undefined && current.generation !== expected.generation) {
          // DB-side race: the stored generation differs from the expected one.
          conflict = true;
          transaction.abort();
          return;
        }
        if (current === undefined && expected.generation !== 0) {
          conflict = true;
          transaction.abort();
          return;
        }
        journal.put(next, VAULT_JOURNAL_KEY);
      };
      transaction.oncomplete = () => resolve(success({ ok: true as const }));
      transaction.onerror = () => resolve(storageFailureToVaultResult(classifyStorageError(transaction.error)));
      transaction.onabort = () => {
        resolve(
          conflict
            ? failure('GenerationConflict')
            : storageFailureToVaultResult(classifyStorageError(transaction.error ?? new DOMException('aborted', 'AbortError'))),
        );
      };
    });
  };

  const session: VaultStorageSession = {
    databaseName: db.name,
    schemaVersion: db.version,
    readRecord,
    writeRecord,
    deleteRecord,
    clearStore,
    casJournal,
    casRecord,
    readJournal,
    close() {
      db.close();
    },
  };

  // Re-verify schema on open so a stale/mismatched connection is rejected.
  try {
    assertSchemaMatches(db);
  } catch {
    db.close();
    throw new Error('vault schema mismatch on session open');
  }

  return session;
}

export { assertSchemaMatches };
export type { VaultSlotKey };
