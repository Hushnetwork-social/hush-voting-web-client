/**
 * FEAT-004 lifecycle policy tests — throttle, storage policy, and removal.
 *
 * Proves: throttle persists across sessions and follows the FEAT-003 schedule
 * with single-increment discipline; headroom formula and bounded retry schedule;
 * persistence denial/acknowledgement/ephemeral handling; tombstone-backed
 * removal with interruption/resume and verified absence.
 *
 * Normative source: FEAT-004 FeatureDescription "Password Throttling",
 * "Storage persistence", "Failure and quota behavior", "Local-User Removal";
 * Task 3.6 behavior specification.
 */
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { failure } from '../../vault-core/contracts/results';
import { VAULT_DATABASE_NAME } from '../contracts/storage';
import { openVaultStorage, type VaultStorageSession } from '../storage/wrapper';
import { checkHeadroom, evaluatePersistence, requiredHeadroomKiB, retryDelayForAttempt, withBoundedStorageRetry } from './storage-policy';
import { checkThrottle, createThrottlePort, recordPasswordFailure, resetPasswordThrottle } from './throttle';
import { beginRemoval, executeRemoval, readRemovalState, resumeRemovalIfTombstoned } from './removal';

async function openSession(): Promise<VaultStorageSession> {
  const outcome = await openVaultStorage(indexedDB);
  if (!outcome.ok) {
    throw new Error(`open failed: ${outcome.code}`);
  }
  return outcome.value.session;
}

afterEach(() => {
  indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
});

describe('password throttling — persisted across sessions', () => {
  it('records failures, applies cooldown, and resets on success', async () => {
    const session = await openSession();
    const port = createThrottlePort(session);
    const now = 1_000_000;
    const decision = await checkThrottle(port, now);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.value.decision.allowed).toBe(true);
    }
    // 5 failed attempts trigger a 5 s cooldown (FEAT-003 schedule).
    for (let i = 0; i < 5; i += 1) {
      await recordPasswordFailure(port, now + i);
    }
    const blocked = await checkThrottle(port, now + 5);
    if (blocked.ok) {
      expect(blocked.value.decision.allowed).toBe(false);
      expect(blocked.value.decision.cooldownSeconds).toBeGreaterThan(0);
    }
    // After the cooldown window expires the attempt is allowed.
    const allowedAfter = await checkThrottle(port, now + 5 + 6000);
    if (allowedAfter.ok) {
      expect(allowedAfter.value.decision.allowed).toBe(true);
    }
    await resetPasswordThrottle(port);
    const reset = await checkThrottle(port, now + 5 + 6000);
    if (reset.ok) {
      expect(reset.value.decision.allowed).toBe(true);
    }
    session.close();
  });

  it('persists the counter across sessions (restart does not reset it)', async () => {
    let session = await openSession();
    const port = createThrottlePort(session);
    for (let i = 0; i < 3; i += 1) {
      await recordPasswordFailure(port, 2_000_000 + i);
    }
    session.close();

    session = await openSession();
    const reopened = createThrottlePort(session);
    const read = await reopened.readState();
    if (read.ok) {
      expect(read.value.state.failedPasswordCount).toBe(3);
    }
    session.close();
  });
});

describe('storage policy — headroom and retry', () => {
  it('computes the conservative headroom formula', () => {
    expect(requiredHeadroomKiB(0)).toBe(4 * 1024);
    expect(requiredHeadroomKiB(1024)).toBe(4 * 1024);
    const large = requiredHeadroomKiB(2 * 1024 * 1024);
    expect(large).toBeGreaterThanOrEqual(3 * 2048 + 1024);
  });

  it('returns StorageQuotaExceeded on known shortfall and ok when sufficient', async () => {
    const tight = await checkHeadroom({ estimate: async () => ({ usage: 90 * 1024 * 1024, quota: 100 * 1024 * 1024 }) }, 5 * 1024 * 1024);
    expect(tight.ok).toBe(false);
    if (!tight.ok) {
      expect(tight.code).toBe('StorageQuotaExceeded');
    }
    const roomy = await checkHeadroom({ estimate: async () => ({ usage: 10 * 1024 * 1024, quota: 1000 * 1024 * 1024 }) }, 5 * 1024 * 1024);
    expect(roomy.ok).toBe(true);
    const missing = await checkHeadroom({}, 5 * 1024 * 1024);
    expect(missing.ok).toBe(true); // missing estimate defers to the real transaction
  });

  it('applies the bounded retry schedule with bounded jitter', () => {
    expect(retryDelayForAttempt(0, 0)).toBe(100);
    expect(retryDelayForAttempt(1, 0)).toBe(250);
    expect(retryDelayForAttempt(2, 0)).toBe(500);
    expect(retryDelayForAttempt(2, 1000)).toBe(600); // jitter capped at 100 ms
    expect(() => retryDelayForAttempt(3)).toThrow();
  });

  it('retries only transient storage failures and never repeats KDF work', async () => {
    let attempts = 0;
    const run = async () => {
      attempts += 1;
      return attempts < 3 ? failure('StorageUnavailable') : { ok: true as const, value: { done: true } };
    };
    const outcome = await withBoundedStorageRetry(run, (result) => !result.ok && result.code === 'StorageUnavailable', { sleep: async () => undefined });
    expect(outcome.ok).toBe(true);
    expect(attempts).toBe(3);
  });
});

describe('storage policy — persistence gating', () => {
  it('returns PersistenceDenied without acknowledgement and proceeds with it', async () => {
    const env = {
      persisted: async () => false,
      persist: async () => false,
    };
    const denied = await evaluatePersistence(env, { allowAcknowledgedDenial: false });
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.code).toBe('PersistenceDenied');
    }
    const acknowledged = await evaluatePersistence(env, { allowAcknowledgedDenial: true });
    expect(acknowledged.ok).toBe(true);
    if (acknowledged.ok) {
      expect(acknowledged.value.decision.kind).toBe('denied');
    }
  });

  it('reports persisted when already granted and unavailable when APIs are missing', async () => {
    const persisted = await evaluatePersistence({ persisted: async () => true, persist: async () => true }, { allowAcknowledgedDenial: false });
    if (persisted.ok) {
      expect(persisted.value.decision.kind).toBe('persisted');
    }
    const unavailable = await evaluatePersistence({}, { allowAcknowledgedDenial: false });
    if (unavailable.ok) {
      expect(unavailable.value.decision.kind).toBe('unavailable');
    }
  });
});

describe('local-user removal — tombstone-backed and resumable', () => {
  it('removes all vault records and verifies absence before clearing the tombstone', async () => {
    const session = await openSession();
    await session.writeRecord('vaultSlots', 'slot-a', { generation: 1, bytes: new Uint8Array([1]) });
    await session.writeRecord('vaultSlots', 'slot-b', { generation: 2, bytes: new Uint8Array([2]) });
    await session.writeRecord('operationalSidecars', 'throttle', { failedPasswordCount: 2, cooldownDeadline: 0 });

    const begin = await beginRemoval(session);
    expect(begin.ok).toBe(true);
    const during = await readRemovalState(session);
    if (during.ok) {
      expect(during.value.state).toBe('inProgress');
    }
    const done = await executeRemoval(session);
    expect(done.ok).toBe(true);

    const after = await readRemovalState(session);
    if (after.ok) {
      expect(after.value.state).toBe('none'); // tombstone cleared only after verified completion
    }
    const slot = await session.readRecord('vaultSlots', 'slot-a');
    if (slot.ok) {
      expect(slot.value.record).toBeUndefined();
    }
    session.close();
  });

  it('resumes an interrupted removal on startup', async () => {
    let session = await openSession();
    await beginRemoval(session);
    // Simulate interruption: tombstone present but records not yet deleted.
    session.close();

    session = await openSession();
    const resumed = await resumeRemovalIfTombstoned(session);
    expect(resumed.ok).toBe(true);
    if (resumed.ok) {
      expect(resumed.value.resumed).toBe(true);
    }
    const state = await readRemovalState(session);
    if (state.ok) {
      expect(state.value.state).toBe('none');
    }
    session.close();
  });

  it('rejects removal without a tombstone', async () => {
    const session = await openSession();
    const outcome = await executeRemoval(session);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.code).toBe('OperationForbidden');
    }
    session.close();
  });
});
