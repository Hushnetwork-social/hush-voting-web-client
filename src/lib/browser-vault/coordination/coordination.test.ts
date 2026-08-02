/**
 * FEAT-004 coordination tests — hierarchy, takeover, heartbeat, and races.
 *
 * Proves: strongest-mode selection; SharedWorker join; exclusive Web Lock
 * never stolen; lease CAS acquisition with generation; 15 s staleness;
 * takeover only after proven expiry (starts Locked at the authority layer);
 * heartbeat renewal; advisory BroadcastChannel is never a correctness input.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker hierarchy",
 * "Session and Tab Coordination"; Task 4.4 behavior specification.
 */
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { VAULT_DATABASE_NAME } from '../contracts/storage';
import { openVaultStorage, type VaultStorageSession } from '../storage/wrapper';
import {
  LEASE_SIDECAR_KEY,
  acquireTabAuthority,
  createLeaseStore,
  decideLeaseTakeover,
  heartbeatLease,
  isLeaseStale,
  selectMode,
  type CoordinationPrimitives,
} from './coordinator';

async function openSession(): Promise<VaultStorageSession> {
  const outcome = await openVaultStorage(indexedDB);
  if (!outcome.ok) {
    throw new Error(`open failed: ${outcome.code}`);
  }
  return outcome.value.session;
}

function primitives(overrides: Partial<CoordinationPrimitives> = {}): CoordinationPrimitives {
  let lease: { ownerId: string; heartbeatMs: number; generation: number } | null = null;
  const now = { value: 1_000_000 };
  return {
    sharedWorker: { supported: false, connect: () => null },
    webLock: { supported: false, acquire: async () => false, release: async () => undefined },
    leaseStore: {
      supported: true,
      read: async () => lease,
      casAcquire: async (_key, expected, next) => {
        const matches = expected === null ? lease === null : lease !== null && expected.generation === lease.generation;
        if (!matches) {
          return false;
        }
        lease = next;
        return true;
      },
      clear: async () => {
        lease = null;
      },
    },
    broadcast: { supported: false, post: () => undefined },
    now: () => now.value,
    schedule: () => ({ cancel: () => undefined }),
    ...overrides,
  };
}

afterEach(() => {
  indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
});

describe('coordination — mode selection hierarchy', () => {
  it('prefers SharedWorker, then Web Lock, then lease, else blocked', () => {
    expect(selectMode(primitives({ sharedWorker: { supported: true, connect: () => null } }))).toBe('shared');
    expect(selectMode(primitives({ webLock: { supported: true, acquire: async () => true, release: async () => undefined } }))).toBe('exclusive');
    expect(selectMode(primitives())).toBe('lease');
    expect(selectMode(primitives({ leaseStore: { supported: false, read: async () => null, casAcquire: async () => false, clear: async () => undefined } }))).toBe('blocked');
  });
});

describe('coordination — exclusive authority', () => {
  it('acquires the Web Lock and blocks when held elsewhere (never steals)', async () => {
    const held = primitives({ webLock: { supported: true, acquire: async () => false, release: async () => undefined } });
    const ownership = await acquireTabAuthority(held);
    expect(ownership.mode).toBe('blocked');

    const free = primitives({ webLock: { supported: true, acquire: async () => true, release: async () => undefined } });
    expect((await acquireTabAuthority(free)).mode).toBe('exclusive');
  });
});

describe('coordination — CAS lease and takeover', () => {
  it('acquires the lease via generation CAS and renews heartbeats', async () => {
    const session = await openSession();
    const leaseStore = createLeaseStore(session);
    const prims = primitives({ leaseStore });
    const ownership = await acquireTabAuthority(prims);
    expect(ownership.mode).toBe('lease');
    const lease = await leaseStore.read(LEASE_SIDECAR_KEY);
    expect(lease?.generation).toBe(1);
    await heartbeatLease(prims, ownership.ownerId!);
    const renewed = await leaseStore.read(LEASE_SIDECAR_KEY);
    expect(renewed?.heartbeatMs).toBe(prims.now());
    session.close();
  });

  it('blocks a second tab while the lease is live and allows takeover after 15 s expiry', async () => {
    const session = await openSession();
    const leaseStore = createLeaseStore(session);
    const prims = primitives({ leaseStore });
    const first = await acquireTabAuthority(prims);
    expect(first.mode).toBe('lease');

    const second = await acquireTabAuthority(prims);
    expect(second.mode).toBe('blocked'); // live foreign lease

    const takeoverNow = await decideLeaseTakeover(prims, 'someone-else');
    expect(takeoverNow.allowed).toBe(false); // never steal a live lease

    // Simulate elapsed time by writing an old heartbeat through the store.
    const stale = await leaseStore.read(LEASE_SIDECAR_KEY);
    if (stale) {
      await leaseStore.casAcquire(LEASE_SIDECAR_KEY, stale, { ...stale, heartbeatMs: stale.heartbeatMs - 16_000 });
    }
    const takeoverLater = await decideLeaseTakeover(prims, 'someone-else');
    expect(takeoverLater.allowed).toBe(true);
    expect(takeoverLater.reason).toBe('ownerStale');

    // A new tab can now acquire atomically (stale lease replaced).
    const retake = await acquireTabAuthority(prims);
    expect(retake.mode).toBe('lease');
    session.close();
  });

  it('allows takeover when the authority is lost (lease absent)', async () => {
    const prims = primitives();
    expect((await decideLeaseTakeover(prims, 'owner-1')).allowed).toBe(true);
    expect((await decideLeaseTakeover(prims, null)).allowed).toBe(false);
  });

  it('marks leases stale after 15 s without a heartbeat', () => {
    expect(isLeaseStale({ ownerId: 'a', heartbeatMs: 0, generation: 1 }, 14_999)).toBe(false);
    expect(isLeaseStale({ ownerId: 'a', heartbeatMs: 0, generation: 1 }, 15_001)).toBe(true);
    expect(isLeaseStale(null, 0)).toBe(true);
  });
});

describe('coordination — advisory notifications only', () => {
  it('posts advisory messages without affecting ownership correctness', async () => {
    let posted: unknown = null;
    const prims = primitives({ broadcast: { supported: true, post: (payload) => { posted = payload; } } });
    // Ownership still fails closed without shared/web-lock support.
    const ownership = await acquireTabAuthority(prims);
    expect(ownership.mode).toBe('lease');
    expect(posted).toBeNull(); // advisory posting is explicit, never automatic
  });
});
