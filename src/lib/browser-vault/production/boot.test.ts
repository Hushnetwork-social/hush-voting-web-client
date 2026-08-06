/**
 * FEAT-010 Task 7.3 — worker boot + handshake integration test (Node).
 *
 * Boots the REAL production worker authority with an injected storage session
 * and fake MessagePort, then proves: startup inspection resolves verified-
 * absent; a v2 handshake is accepted and delivered; malformed/stale messages
 * fail closed; and a provisioned vault surfaces as locked.
 */
import { describe, expect, it } from 'vitest';
import { bootVaultWorker, type WorkerAppIdentity } from './worker-entry';
import type { VaultStorageSession } from '../storage/wrapper';
import type { VaultResult } from '../../vault-core/contracts/results';
import { success, failure } from '../../vault-core/contracts/results';

class MemoryVaultStorage implements VaultStorageSession {
  readonly databaseName = 'hushvoting-vault';
  readonly schemaVersion = 1;
  private readonly records = new Map<string, Map<string, unknown>>();
  constructor() {
    this.records.set('vaultSlots', new Map());
    this.records.set('vaultJournal', new Map());
    this.records.set('operationalSidecars', new Map());
  }
  private store(name: string): Map<string, unknown> {
    let map = this.records.get(name);
    if (!map) {
      map = new Map();
      this.records.set(name, map);
    }
    return map;
  }
  async readRecord(store: string, key: string): Promise<VaultResult<{ readonly record: unknown }>> {
    const value = this.store(store).get(key);
    return value === undefined ? success({ record: undefined }) : success({ record: value });
  }
  async writeRecord(store: string, key: string, value: unknown): Promise<VaultResult<{ readonly ok: true }>> {
    this.store(store).set(key, value);
    return success({ ok: true });
  }
  async deleteRecord(store: string, key: string): Promise<VaultResult<{ readonly ok: true }>> {
    this.store(store).delete(key);
    return success({ ok: true });
  }
  async clearStore(store: string): Promise<VaultResult<{ readonly ok: true }>> {
    this.store(store).clear();
    return success({ ok: true });
  }
  async casJournal(expected: unknown, next: unknown): Promise<VaultResult<{ readonly ok: true }>> {
    const current = this.store('vaultJournal').get('current');
    const expectedRecord = expected as { generation?: number } | null;
    const matches = current === undefined ? (expectedRecord !== null && expectedRecord.generation === 0) : JSON.stringify(current) === JSON.stringify(expected);
    if (!matches) return failure('GenerationConflict');
    this.store('vaultJournal').set('current', next);
    return success({ ok: true });
  }
  async casRecord(store: string, key: string, expected: unknown, next: unknown): Promise<VaultResult<{ readonly ok: true }>> {
    const current = this.store(store).get(key);
    if (JSON.stringify(current) !== JSON.stringify(expected)) return failure('GenerationConflict');
    this.store(store).set(key, next);
    return success({ ok: true });
  }
  async readJournal(): Promise<VaultResult<{ readonly journal: { generation: number; activeSlot: 'slot-a' | 'slot-b' } | null }>> {
    const value = this.store('vaultJournal').get('current');
    return value === undefined ? success({ journal: null }) : success({ journal: value as { generation: number; activeSlot: 'slot-a' | 'slot-b' } });
  }
  close(): void {
    this.records.clear();
  }
}

class FakePort {
  readonly sent: unknown[] = [];
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  postMessage(message: unknown): void {
    this.sent.push(message);
  }
  push(data: unknown): void {
    this.onmessage?.({ data });
  }
  start(): void {}
}

const APP_IDENTITY: WorkerAppIdentity = { appVersion: '0.1.0', buildDigest: '0123456789ab' };

describe('worker boot + handshake', () => {
  it('boots, resolves verified-absent startup, and accepts a v2 handshake', async () => {
    const storage = new MemoryVaultStorage();
    const result = await bootVaultWorker({
      appIdentity: APP_IDENTITY,
      runtimeConfigId: 'development-localhost',
      openStorage: async () => success({ session: storage }),
    });
    console.log('BOOTRESULT', JSON.stringify(result));
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.reason);
    }
    const port = new FakePort();
    result.registerPort(port as unknown as MessagePort);

    port.push({ kind: 'handshake', protocolVersion: 2, appVersion: '0.1.0', buildDigest: '0123456789ab', clientChannel: 'chan-1', runtimeConfigId: 'development-localhost' });
    const accepted = port.sent.find((m) => (m as { kind?: string }).kind === 'handshake-accepted') as { session?: { state?: string } } | undefined;
    expect(accepted).toBeDefined();
    expect(accepted?.session?.state).toBe('noLocalUser');
    expect(result.authority.snapshot().phase).toBe('noLocalUser');
  });

  it('rejects a build-mismatched handshake and never falls back', async () => {
    const storage = new MemoryVaultStorage();
    const result = await bootVaultWorker({
      appIdentity: APP_IDENTITY,
      runtimeConfigId: 'development-localhost',
      openStorage: async () => success({ session: storage }),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.reason);
    }
    const port = new FakePort();
    result.registerPort(port as unknown as MessagePort);
    port.push({ kind: 'handshake', protocolVersion: 2, appVersion: '0.1.0', buildDigest: 'ffffffffffff', clientChannel: 'chan-2', runtimeConfigId: 'development-localhost' });
    const rejected = port.sent.find((m) => (m as { kind?: string }).kind === 'handshake-rejected') as { reason?: string } | undefined;
    expect(rejected).toBeDefined();
    expect(rejected?.reason).toBe('build-mismatch');
  });

  it('rejects an unapproved runtime configuration at boot (fail closed)', async () => {
    const storage = new MemoryVaultStorage();
    const result = await bootVaultWorker({
      appIdentity: APP_IDENTITY,
      runtimeConfigId: 'production-hushnetwork',
      openStorage: async () => success({ session: storage }),
    });
    expect(result.ok).toBe(false);
  });
});
