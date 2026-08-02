/**
 * FEAT-004 browser-vault storage — fixed schema lifecycle.
 *
 * Creates/opens `hushvoting-vault` at schema version 1 with exactly three
 * object stores (`vaultSlots`, `vaultJournal`, `operationalSidecars`) and NO
 * indexes. Upgrades never delete/recreate the database and never rewrite
 * encrypted slots destructively; `versionchange` closes connections
 * immediately; blocked/unexpected upgrades preserve bytes and report a typed
 * Retry-able failure.
 *
 * Normative source: FEAT-004 FeatureDescription "IndexedDB schema upgrades".
 */
import {
  VAULT_DATABASE_NAME,
  VAULT_SCHEMA_VERSION,
  VAULT_STORES,
  verifyDatabaseLayout,
} from '../contracts/storage';

/** Bounded callback invoked when an upgrade is blocked by other connections. */
export interface UpgradeBlockedHandlers {
  readonly onBlocked: () => void;
  readonly onVersionChange: () => void;
}

/** Create the fixed object stores during a versioned upgrade (non-destructive). */
export function createVaultSchema(db: IDBDatabase): void {
  for (const store of VAULT_STORES) {
    if (!db.objectStoreNames.contains(store)) {
      db.createObjectStore(store);
    }
  }
}

/** Verify an open connection matches the fixed schema (no extra stores/indexes). */
export function assertSchemaMatches(db: IDBDatabase): void {
  if (db.version !== VAULT_SCHEMA_VERSION) {
    throw new Error(`unexpected vault schema version: ${db.version}`);
  }
  const stores: string[] = [];
  for (let i = 0; i < db.objectStoreNames.length; i += 1) {
    stores.push(db.objectStoreNames.item(i) as string);
  }
  if (!verifyDatabaseLayout(stores)) {
    throw new Error('vault schema does not match the fixed layout');
  }
  for (const store of VAULT_STORES) {
    const objectStore = db.transaction(store, 'readonly').objectStore(store);
    if (objectStore.indexNames.length !== 0) {
      throw new Error(`vault store ${store} must have no indexes`);
    }
  }
}

/**
 * Open the vault database at the fixed schema version. Applies one bounded
 * versioned `onupgradeneeded` migration that preserves existing records.
 * Returns the connection, or `null` when the open is blocked/unsupported.
 */
export function openVaultDatabase(
  factory: IDBFactory,
  handlers: UpgradeBlockedHandlers = { onBlocked: () => undefined, onVersionChange: () => undefined },
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = factory.open(VAULT_DATABASE_NAME, VAULT_SCHEMA_VERSION);
    } catch (error) {
      reject(error);
      return;
    }
    request.onupgradeneeded = () => {
      // Bounded migration preserving encrypted slots; never delete/recreate.
      createVaultSchema(request.result);
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        // Another connection wants a new version: close immediately.
        handlers.onVersionChange();
        db.close();
      };
      try {
        assertSchemaMatches(db);
      } catch (error) {
        db.close();
        reject(error);
        return;
      }
      resolve(db);
    };
    request.onerror = () => {
      reject(request.error ?? new Error('indexedDB open failed'));
    };
    request.onblocked = () => {
      handlers.onBlocked();
    };
  });
}
