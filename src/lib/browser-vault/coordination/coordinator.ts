/**
 * FEAT-004 browser coordination — real primitives + tab authority.
 *
 * Authority order: SharedWorker (one shared unlocked authority for every
 * same-origin tab) → dedicated worker + exclusive Web Lock (one authenticated
 * tab) → dedicated worker + generation-checked 15-second IndexedDB lease (one
 * authenticated tab) → fail closed. BroadcastChannel is advisory notification
 * only; correctness comes from the Web Lock or the CAS'd IndexedDB lease.
 * localStorage events/mutexes are prohibited (the lease lives in the
 * allowlisted `operationalSidecars` store, never localStorage).
 *
 * Takeover never steals a live Web Lock or unexpired lease; after proven
 * release or 15-second lease expiry it acquires ownership atomically,
 * increments the epoch, reconciles the encrypted journal, and requires the
 * device password again (starts Locked).
 *
 * Browser primitives are injected so the coordinator is deterministic in tests;
 * the production wiring (`createBrowserCoordinationPrimitives`) resolves real
 * browser globals.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker hierarchy",
 * "Session and Tab Coordination".
 */
import type { VaultStorageSession } from '../storage/wrapper';

/** Closed authority modes (FEAT-004 hierarchy). */
export type AuthorityMode = 'shared' | 'exclusive' | 'lease' | 'blocked';

/** Non-secret lease record stored under the allowlisted `lease` sidecar key. */
export interface LeaseRecord {
  readonly ownerId: string;
  readonly heartbeatMs: number;
  readonly generation: number;
}

export const LEASE_SIDECAR_KEY = 'lease' as const;
export const LEASE_STALENESS_MS = 15_000 as const;
export const HEARTBEAT_INTERVAL_MS = 5_000 as const;

/** Injected browser primitives (deterministic in tests). */
export interface CoordinationPrimitives {
  readonly sharedWorker: {
    readonly supported: boolean;
    readonly connect: () => { readonly send: (payload: unknown) => void } | null;
  };
  readonly webLock: {
    readonly supported: boolean;
    readonly acquire: (name: string, onLost: () => void) => Promise<boolean>;
    readonly release: (name: string) => Promise<void>;
  };
  /** CAS'd non-secret lease over the IndexedDB `operationalSidecars` store. */
  readonly leaseStore: {
    readonly supported: boolean;
    readonly read: (key: string) => Promise<LeaseRecord | null>;
    readonly casAcquire: (key: string, expected: LeaseRecord | null, next: LeaseRecord) => Promise<boolean>;
    readonly clear: (key: string) => Promise<void>;
  };
  /** Advisory notifications only; never correctness. */
  readonly broadcast: {
    readonly supported: boolean;
    readonly post: (payload: unknown) => void;
  };
  readonly now: () => number;
  readonly schedule: (callback: () => void, delayMs: number) => { readonly cancel: () => void };
}

export interface Ownership {
  readonly mode: 'shared' | 'exclusive' | 'lease' | 'blocked';
  readonly ownerId: string | null;
}

/** Build the CAS'd lease store over the vault storage session. */
export function createLeaseStore(session: VaultStorageSession): CoordinationPrimitives['leaseStore'] {
  return {
    supported: true,
    async read(key) {
      const outcome = await session.readRecord('operationalSidecars', key);
      if (!outcome.ok) {
        return null;
      }
      const value = outcome.value.record as LeaseRecord | undefined;
      return value ?? null;
    },
    async casAcquire(key, expected, next) {
      const outcome = await session.casRecord('operationalSidecars', key, expected, next, (a, b) => {
        const missing = (value: unknown) => value === null || value === undefined;
        if (missing(a) && missing(b)) {
          return true; // both absent: first acquisition
        }
        if (missing(a) || missing(b)) {
          return false;
        }
        return (a as LeaseRecord).generation === (b as LeaseRecord).generation;
      });
      return outcome.ok;
    },
    async clear(key) {
      await session.deleteRecord('operationalSidecars', key);
    },
  };
}

/** Select the strongest available mode. */
export function selectMode(primitives: CoordinationPrimitives): AuthorityMode {
  if (primitives.sharedWorker.supported) {
    return 'shared';
  }
  if (primitives.webLock.supported) {
    return 'exclusive';
  }
  if (primitives.leaseStore.supported) {
    return 'lease';
  }
  return 'blocked';
}

/** True when a lease is stale (15 s without a valid heartbeat). */
export function isLeaseStale(lease: LeaseRecord | null, nowMs: number, stalenessMs = LEASE_STALENESS_MS): boolean {
  if (lease === null) {
    return true;
  }
  return nowMs - lease.heartbeatMs > stalenessMs;
}

/**
 * Acquire one authority using the strongest safe mode. Never steals a live
 * Web Lock or unexpired lease; the lease path uses a generation CAS.
 */
export async function acquireTabAuthority(primitives: CoordinationPrimitives): Promise<Ownership> {
  const mode = selectMode(primitives);
  switch (mode) {
    case 'shared': {
      const channel = primitives.sharedWorker.connect();
      return channel ? { mode: 'shared', ownerId: null } : { mode: 'blocked', ownerId: null };
    }
    case 'exclusive': {
      const acquired = await primitives.webLock.acquire('hushvoting-vault-owner', () => undefined);
      return acquired ? { mode: 'exclusive', ownerId: 'web-lock-owner' } : { mode: 'blocked', ownerId: null };
    }
    case 'lease': {
      const ownerId = `lease-${primitives.now()}-${Math.random().toString(36).slice(2, 10)}`;
      const current = await primitives.leaseStore.read(LEASE_SIDECAR_KEY);
      if (current !== null && !isLeaseStale(current, primitives.now())) {
        return { mode: 'blocked', ownerId: null }; // live foreign lease: active elsewhere
      }
      const nextGeneration = (current?.generation ?? 0) + 1;
      // Expected value is the CURRENT record (null when absent, the stale record
      // when expired) so the CAS replaces the stale lease atomically.
      const acquired = await primitives.leaseStore.casAcquire(
        LEASE_SIDECAR_KEY,
        current,
        { ownerId, heartbeatMs: primitives.now(), generation: nextGeneration },
      );
      return acquired ? { mode: 'lease', ownerId } : { mode: 'blocked', ownerId: null };
    }
    case 'blocked':
      return { mode: 'blocked', ownerId: null };
  }
}

/** Renew the lease heartbeat (visible clients: 5-second intervals). */
export async function heartbeatLease(primitives: CoordinationPrimitives, ownerId: string): Promise<void> {
  const current = await primitives.leaseStore.read(LEASE_SIDECAR_KEY);
  if (current === null || current.ownerId !== ownerId) {
    return; // no longer owner; caller must re-acquire or Lock
  }
  await primitives.leaseStore.casAcquire(
    LEASE_SIDECAR_KEY,
    current,
    { ...current, heartbeatMs: primitives.now() },
  );
}

export type TakeoverDecision =
  | { readonly allowed: true; readonly reason: 'authorityLost' | 'ownerStale' }
  | { readonly allowed: false; readonly reason: 'alreadyOwned' | 'notLeaseMode' };

/** Async takeover decision over the real lease store. */
export async function decideLeaseTakeover(primitives: CoordinationPrimitives, expectedOwnerId: string | null): Promise<TakeoverDecision> {
  if (expectedOwnerId === null) {
    return { allowed: false, reason: 'notLeaseMode' };
  }
  const lease = await primitives.leaseStore.read(LEASE_SIDECAR_KEY);
  if (lease === null) {
    return { allowed: true, reason: 'authorityLost' };
  }
  if (lease.ownerId === expectedOwnerId) {
    return isLeaseStale(lease, primitives.now())
      ? { allowed: true, reason: 'ownerStale' }
      : { allowed: false, reason: 'alreadyOwned' };
  }
  return isLeaseStale(lease, primitives.now())
    ? { allowed: true, reason: 'ownerStale' }
    : { allowed: false, reason: 'alreadyOwned' };
}

/** Advisory notification only — never a correctness primitive. */
export function notifyPeers(primitives: CoordinationPrimitives, payload: unknown): void {
  if (primitives.broadcast.supported) {
    primitives.broadcast.post(payload);
  }
}
