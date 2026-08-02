/**
 * FEAT-004 browser-vault contracts — fixed-key storage model and error mapping.
 *
 * One generic origin-scoped database with a fixed schema:
 *
 *   Database: hushvoting-vault | Schema version: 1
 *   Stores: vaultSlots, vaultJournal, operationalSidecars
 *
 * - `vaultSlots` uses only fixed opaque keys `slot-a` and `slot-b`.
 * - `vaultJournal` uses fixed key `current` for the active pointer/generation.
 * - `operationalSidecars` uses fixed allowlisted keys only (throttle, removal
 *   tombstone, lease/ownership, persistence acknowledgement, and other
 *   FEAT-003-allowlisted non-secret state).
 * - No database/store/key/index contains an alias, address, identity, network,
 *   endpoint, or credential-derived value.
 *
 * Raw platform exceptions never cross the boundary: every storage failure maps
 * to the closed FEAT-003 typed result vocabulary.
 *
 * Normative source: FEAT-004 FeatureDescription "IndexedDB Storage Model";
 * FEAT-003 `src/lib/vault-core/contracts/results.ts`.
 */
import { failure, type VaultFailure, type VaultResultCode } from '../../vault-core/contracts/results';

/** Generic origin-scoped database name (no identity-bearing value). */
export const VAULT_DATABASE_NAME = 'hushvoting-vault' as const;
/** Fixed schema version; upgrades bump this monotonically without recreating data. */
export const VAULT_SCHEMA_VERSION = 1 as const;

/** Closed fixed object-store names. */
export const VAULT_STORES = ['vaultSlots', 'vaultJournal', 'operationalSidecars'] as const;
export type VaultStoreName = (typeof VAULT_STORES)[number];

/** Fixed opaque slot keys; never identity-derived. */
export const VAULT_SLOT_KEYS = ['slot-a', 'slot-b'] as const;
export type VaultSlotKey = (typeof VAULT_SLOT_KEYS)[number];

/** Fixed journal key holding the active pointer + generation. */
export const VAULT_JOURNAL_KEY = 'current' as const;

/**
 * Allowlisted non-secret sidecar keys. Any other key in `operationalSidecars`
 * is a contract violation and fails closed.
 */
export const ALLOWED_SIDECAR_KEYS = [
  'throttle',
  'removalTombstone',
  'lease',
  'persistenceAck',
  'epoch',
] as const;
export type VaultSidecarKey = (typeof ALLOWED_SIDECAR_KEYS)[number];

/** Journal record shape stored under `current`. */
export interface VaultJournalRecord {
  readonly generation: number;
  readonly activeSlot: VaultSlotKey;
}

/** Runtime storage-failure classification before mapping to the result union. */
export type StorageFailureClass = 'unavailable' | 'quota' | 'generationConflict' | 'blockedUpgrade' | 'unexpectedSchema' | 'aborted';

/** Map a raw platform error (DOMException or unknown) to a closed storage class. */
export function classifyStorageError(error: unknown): StorageFailureClass {
  if (error instanceof DOMException) {
    switch (error.name) {
      case 'QuotaExceededError':
      case 'NS_ERROR_DOM_QUOTA_REACHED':
        return 'quota';
      case 'VersionError':
        return 'blockedUpgrade';
      case 'InvalidStateError':
      case 'UnknownError':
        return 'unavailable';
      case 'AbortError':
        return 'aborted';
      default:
        return 'unavailable';
    }
  }
  if (typeof error === 'object' && error !== null && 'name' in error) {
    const name = String((error as { name: unknown }).name);
    if (name === 'QuotaExceededError' || name === 'NS_ERROR_DOM_QUOTA_REACHED') {
      return 'quota';
    }
    if (name === 'AbortError') {
      return 'aborted';
    }
  }
  return 'unavailable';
}

/** Map a storage failure class to the closed FEAT-003 typed result. */
export function storageFailureToVaultResult(class_: StorageFailureClass): VaultFailure {
  switch (class_) {
    case 'quota':
      return failure('StorageQuotaExceeded');
    case 'generationConflict':
      return failure('GenerationConflict');
    case 'blockedUpgrade':
    case 'unexpectedSchema':
    case 'unavailable':
      return failure('StorageUnavailable');
    case 'aborted':
      return failure('StorageUnavailable');
  }
}

/** Valid storage result codes produced by the browser adapter boundary. */
export const BROWSER_STORAGE_RESULT_CODES: readonly VaultResultCode[] = [
  'StorageUnavailable',
  'StorageQuotaExceeded',
  'GenerationConflict',
  'PersistenceDenied',
] as const;

/**
 * Assert a storage key is allowed for its store. Throws a deterministic
 * Error (never a secret) when the layout is violated; callers convert to
 * `OperationForbidden`/`StorageUnavailable` typed results.
 */
export function assertAllowedStorageKey(store: VaultStoreName, key: string): void {
  if (store === 'vaultSlots' && !(VAULT_SLOT_KEYS as readonly string[]).includes(key)) {
    throw new Error(`disallowed key for vaultSlots: ${key}`);
  }
  if (store === 'vaultJournal' && key !== VAULT_JOURNAL_KEY) {
    throw new Error(`disallowed key for vaultJournal: ${key}`);
  }
  if (store === 'operationalSidecars' && !(ALLOWED_SIDECAR_KEYS as readonly string[]).includes(key)) {
    throw new Error(`disallowed key for operationalSidecars: ${key}`);
  }
}

/** Verify a database layout matches the fixed schema exactly. */
export function verifyDatabaseLayout(stores: readonly string[]): boolean {
  const expected = new Set<string>(VAULT_STORES);
  const actual = new Set<string>(stores);
  return expected.size === actual.size && [...expected].every((name) => actual.has(name));
}
