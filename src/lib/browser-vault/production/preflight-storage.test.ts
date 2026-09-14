import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openVaultStorage, type VaultStorageSession } from '../storage/wrapper';

// EPIC-001 -> FEAT-004 capability preflight / Phase 2 Tasks 2.3/2.4;
// FEAT-007 AC-007-002 -> Phase 6 Tasks 6.1/6.2. Isolated FEAT evidence only.
const sessions: VaultStorageSession[] = [];
async function storage() {
  const opened = await openVaultStorage(new IDBFactory());
  if (!opened.ok) throw new Error('Isolated storage unavailable');
  sessions.push(opened.value.session);
  return opened.value.session;
}
afterEach(() => { vi.restoreAllMocks(); sessions.splice(0).forEach(session => session.close()); });

describe('HushVotingApp TwinTests — non-secret storage preflight', () => {
  it('does not expose a storage session when opening succeeds but writing is denied', async () => {
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(() => { throw new DOMException('Controlled denial', 'QuotaExceededError'); });
    const opened = await openVaultStorage(new IDBFactory());
    // Close even a wrongly accepted connection so the red test leaves no owner.
    if (opened.ok) sessions.push(opened.value.session);
    expect(opened.ok).toBe(false);
  });
  it.each([false, true])('verifies write/read/delete while preserving prior acknowledgement: %s', async existing => {
    const session = await storage();
    const ack = { acknowledged: true, policyVersion: 1 };
    if (existing) await session.writeRecord('operationalSidecars', 'persistenceAck', ack);
    await session.writeRecord('vaultSlots', 'slot-a', { opaque: 'retained-slot' });
    await session.writeRecord('operationalSidecars', 'lease', { opaque: 'retained-lease' });
    expect(await session.probeStorage!()).toEqual({ ok: true, value: { ok: true } });
    expect(await session.readRecord('operationalSidecars', 'persistenceAck')).toEqual({ ok: true, value: { record: existing ? ack : undefined } });
    expect(await session.readRecord('vaultSlots', 'slot-a')).toEqual({ ok: true, value: { record: { opaque: 'retained-slot' } } });
    expect(await session.readRecord('operationalSidecars', 'lease')).toEqual({ ok: true, value: { record: { opaque: 'retained-lease' } } });
  });

  it.each([1, 2])('fails closed and rolls back all probe writes when write %s is denied', async failingWrite => {
    const session = await storage();
    const ack = { acknowledged: true };
    await session.writeRecord('operationalSidecars', 'persistenceAck', ack);
    const put = IDBObjectStore.prototype.put;
    let writes = 0;
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function(this: IDBObjectStore, ...args) {
      if (++writes === failingWrite) throw new DOMException('Controlled denial', 'QuotaExceededError');
      return Reflect.apply(put, this, args);
    });
    expect((await session.probeStorage!()).ok).toBe(false);
    vi.restoreAllMocks();
    expect(await session.readRecord('operationalSidecars', 'persistenceAck')).toEqual({ ok: true, value: { record: ack } });
  });

  it.each(['read', 'delete'])('rejects a successful-looking request that fails the %s verification', async fault => {
    const session = await storage();
    const ack = { acknowledged: true };
    await session.writeRecord('operationalSidecars', 'persistenceAck', ack);
    const get = IDBObjectStore.prototype.get;
    if (fault === 'read') {
      let reads = 0;
      vi.spyOn(IDBObjectStore.prototype, 'get').mockImplementation(function(this: IDBObjectStore, key) {
        return Reflect.apply(get, this, [++reads === 2 ? 'throttle' : key]);
      });
    } else {
      vi.spyOn(IDBObjectStore.prototype, 'delete').mockImplementation(function(this: IDBObjectStore, key) {
        return Reflect.apply(get, this, [key]);
      });
    }
    expect((await session.probeStorage!()).ok).toBe(false);
    vi.restoreAllMocks();
    expect(await session.readRecord('operationalSidecars', 'persistenceAck')).toEqual({ ok: true, value: { record: ack } });
  });
});
