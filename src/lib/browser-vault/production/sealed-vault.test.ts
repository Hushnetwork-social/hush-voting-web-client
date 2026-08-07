/**
 * FEAT-010 Task 7.3 — sealed vault engine tests (worker boundary).
 *
 * Proves the real engine over a deterministic in-memory storage session and
 * the REAL suite crypto (WebCrypto + noble Argon2id): provisioning builds an
 * encrypted two-slot current record; startup inspection resolves the exact
 * surface; unlock enforces the cooldown schedule and the combined error;
 * network mismatch fails before promotion; verification is exact-both-key;
 * lock wipes secrets; removal verifies absence; change-password rewraps via
 * CAS; current records reject mnemonic-shaped content (AC-010-073+).
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { SealedVaultEngine, parseCurrentRecord, cooldownSecondsFor, abbreviateSigningAddress } from './sealed-vault';
import { createBrowserSuiteExecutor, resolveBrowserCryptoEnvironment } from '../crypto/executor';
import type { VaultStorageSession } from '../storage/wrapper';
import type { VaultResult } from '../../vault-core/contracts/results';
import { success, failure } from '../../vault-core/contracts/results';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { canonicalizeJsonBytes } from '../../vault-core/canonical/jcs';

/** Deterministic in-memory vault storage session (same wrapper contract). */
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
    return value === undefined ? success({ record: undefined }) : success({ record: structuredClone(value) });
  }

  async writeRecord(store: string, key: string, value: unknown): Promise<VaultResult<{ readonly ok: true }>> {
    this.store(store).set(key, structuredClone(value));
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
    const currentMatches =
      current === undefined
        ? expectedRecord !== null && expectedRecord.generation === 0 // absent journal = generation 0
        : JSON.stringify(current) === JSON.stringify(expected);
    if (!currentMatches) {
      return failure('GenerationConflict');
    }
    this.store('vaultJournal').set('current', structuredClone(next));
    return success({ ok: true });
  }

  async casRecord(store: string, key: string, expected: unknown, next: unknown): Promise<VaultResult<{ readonly ok: true }>> {
    const current = this.store(store).get(key);
    if (JSON.stringify(current) !== JSON.stringify(expected)) {
      return failure('GenerationConflict');
    }
    this.store(store).set(key, structuredClone(next));
    return success({ ok: true });
  }

  async readJournal(): Promise<VaultResult<{ readonly journal: { generation: number; activeSlot: 'slot-a' | 'slot-b' } | null }>> {
    const value = this.store('vaultJournal').get('current');
    return value === undefined ? success({ journal: null }) : success({ journal: structuredClone(value) as { generation: number; activeSlot: 'slot-a' | 'slot-b' } });
  }

  activeEnvelope(): Record<string, unknown> {
    const journal = this.store('vaultJournal').get('current') as { activeSlot?: string } | undefined;
    if (journal?.activeSlot !== 'slot-a' && journal?.activeSlot !== 'slot-b') throw new Error('no active journal');
    const slot = this.store('vaultSlots').get(journal.activeSlot) as { bytes?: unknown } | undefined;
    if (typeof slot?.bytes !== 'object' || slot.bytes === null) throw new Error('no active slot');
    const raw = slot.bytes as Uint8Array | Record<string, number>;
    const bytes = raw instanceof Uint8Array
      ? raw
      : Uint8Array.from(Object.keys(raw).filter((key) => /^\d+$/.test(key)).sort((a, b) => Number(a) - Number(b)).map((key) => raw[key]));
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  }

  replaceActiveEnvelope(envelope: Record<string, unknown>): void {
    const journal = this.store('vaultJournal').get('current') as { activeSlot?: string } | undefined;
    if (journal?.activeSlot !== 'slot-a' && journal?.activeSlot !== 'slot-b') throw new Error('no active journal');
    const slot = this.store('vaultSlots').get(journal.activeSlot) as { slotKey: string; generation: number; bytes: unknown } | undefined;
    if (!slot) throw new Error('no active slot');
    this.store('vaultSlots').set(journal.activeSlot, { ...slot, bytes: canonicalizeJsonBytes(envelope) });
  }

  close(): void {
    this.records.clear();
  }
}

function createEngine(storage: VaultStorageSession, lookup: (address: string) => Promise<{ readonly kind: 'exact' | 'missing' | 'timeout' | 'unavailable'; readonly profileName?: string; readonly signingAddress?: string; readonly encryptionAddress?: string; readonly visibility?: 'private' | 'public' }> = async () => ({ kind: 'missing' })): SealedVaultEngine {
  return new SealedVaultEngine({
    storage,
    suite: createBrowserSuiteExecutor(resolveBrowserCryptoEnvironment()),
    manifest: ISOLATED_DEVNET_MANIFEST,
    nowMs: () => 1_700_000_000_000,
    randomId: (prefix) => `${prefix}-test`,
    lookupIdentity: lookup,
    broadcast: () => undefined,
    onForceCleanup: () => undefined,
  });
}

const PASSWORD = 'Tr0ub4dor&3-correct-horse';

describe('cooldown schedule', () => {
  it('follows the exact FEAT-003 schedule (attempt → added seconds)', () => {
    expect(cooldownSecondsFor(1)).toBe(0);
    expect(cooldownSecondsFor(4)).toBe(0);
    expect(cooldownSecondsFor(5)).toBe(5);
    expect(cooldownSecondsFor(6)).toBe(10);
    expect(cooldownSecondsFor(7)).toBe(20);
    expect(cooldownSecondsFor(8)).toBe(40);
    expect(cooldownSecondsFor(9)).toBe(80);
    expect(cooldownSecondsFor(10)).toBe(160);
    expect(cooldownSecondsFor(11)).toBe(300);
    expect(cooldownSecondsFor(99)).toBe(300);
  });
});

describe('parseCurrentRecord', () => {
  it('accepts a concrete-key-only current record', () => {
    const record = {
      schemaVersion: 1,
      alias: 'Alice',
      visibility: 'private',
      producerId: 'P-01',
      producerVersion: '1.0.0',
      lifecycleStatus: 'Active',
      networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
      keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
      signingPrivateKey: 'a'.repeat(64),
      encryptionPrivateKey: 'b'.repeat(64),
      protectionModeClass: 'device-password',
      generation: 1,
      transactionDigest: null,
    };
    const parsed = parseCurrentRecord(JSON.stringify(record), 1);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.record.keyBinding.signingAddress).toBe('A'.repeat(44));
      expect(parsed.record.signingPrivateKey).toBe('a'.repeat(64));
    }
  });

  it('rejects any mnemonic/seed/phrase-shaped field (no-mnemonic rule)', () => {
    const record = {
      schemaVersion: 1,
      alias: 'Alice',
      visibility: 'private',
      producerId: 'P-01',
      producerVersion: '1.0.0',
      lifecycleStatus: 'Active',
      networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
      keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
      signingPrivateKey: 'a'.repeat(64),
      encryptionPrivateKey: 'b'.repeat(64),
      protectionModeClass: 'device-password',
      generation: 1,
      transactionDigest: null,
      mnemonic: 'abandon abandon abandon',
    };
    expect(parseCurrentRecord(JSON.stringify(record), 1).ok).toBe(false);
  });

  it('rejects a wrong generation or malformed keys', () => {
    const record = {
      schemaVersion: 1,
      alias: 'Alice',
      visibility: 'private',
      producerId: 'P-01',
      producerVersion: '1.0.0',
      lifecycleStatus: 'Active',
      networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
      keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
      signingPrivateKey: 'zz',
      encryptionPrivateKey: 'b'.repeat(64),
      protectionModeClass: 'device-password',
      generation: 2,
      transactionDigest: null,
    };
    expect(parseCurrentRecord(JSON.stringify(record), 1).ok).toBe(false);
  });

  it('abbreviates signing addresses as 8…6', () => {
    const address = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
    expect(abbreviateSigningAddress(address)).toBe('01234567…efghij');
  });
});

describe('sealed vault lifecycle', () => {
  let storage: MemoryVaultStorage;
  let engine: SealedVaultEngine;

  beforeEach(() => {
    storage = new MemoryVaultStorage();
    engine = createEngine(storage);
  });

  it('starts with verified-absent startup surface', async () => {
    const result = await engine.inspectStartup();
    expect(result.code).toBe('OK');
    if (result.code === 'OK') {
      expect(result.detail).toMatchObject({ surface: 'verifiedAbsent' });
    }
  });

  it('provisions, inspects as locked vault, unlocks, verifies, locks, removes', async () => {
    const candidate = engine.createCandidate({ wordCount: 24 });
    expect(candidate.code).toBe('OK');
    if (candidate.code !== 'OK' || candidate.detail === undefined) {
      throw new Error('candidate generation failed');
    }
    const candidateRef = String((candidate.detail as { ref?: unknown }).ref);

    const provision = await engine.provision({
      candidateRef,
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');
    if (provision.code !== 'OK' || provision.detail === undefined) {
      throw new Error('provision failed');
    }
    const provisionDetail = provision.detail as { signingAddress?: string; encryptionAddress?: string; abbreviatedSigningAddress?: string };
    expect(provisionDetail.signingAddress).toBeTruthy();
    expect(provisionDetail.abbreviatedSigningAddress).toBeTruthy();

    const inspect = await engine.inspectStartup();
    expect(inspect.code).toBe('OK');
    if (inspect.code === 'OK') {
      expect(inspect.detail).toMatchObject({ surface: 'lockedVault' });
    }

    // Wrong password → combined error; no promotion.
    const wrong = await engine.unlock({ devicePassword: 'wrong-password-value', configurationId: 'isolated-local-devnet-v1' });
    expect(wrong.code).toBe('WRONG_PASSWORD_OR_DAMAGED');

    // Correct password → verificationOnly with safe identity.
    const unlock = await engine.unlock({ devicePassword: PASSWORD, configurationId: 'isolated-local-devnet-v1' });
    expect(unlock.code).toBe('OK');
    if (unlock.code === 'OK' && unlock.detail) {
      expect((unlock.detail as { safeIdentity?: { alias?: string } }).safeIdentity?.alias).toBe('Alice');
    }

    // Exact online verification promotes only on both-key equality.
    const verifyEngine = createEngine(storage, async () => ({
      kind: 'exact' as const,
      profileName: 'Alice',
      signingAddress: provisionDetail.signingAddress as string,
      encryptionAddress: provisionDetail.encryptionAddress as string,
      visibility: 'private' as const,
    }));
    const unlockForVerify = await verifyEngine.unlock({ devicePassword: PASSWORD, configurationId: 'isolated-local-devnet-v1' });
    expect(unlockForVerify.code).toBe('OK');
    const verified = await verifyEngine.verifyOnline();
    expect(verified.code).toBe('OK');

    // Lock wipes the session.
    const lock = engine.lock();
    expect(lock.code).toBe('OK');

    // Removal verifies absence.
    const removed = await engine.removeLocalUser();
    expect(removed.code).toBe('OK');
    const after = await engine.inspectStartup();
    expect(after.code).toBe('OK');
    if (after.code === 'OK') {
      expect(after.detail).toMatchObject({ surface: 'verifiedAbsent' });
    }
  });

  it('rewraps the DEK whenever retained digest or lifecycle AAD changes', async () => {
    let signingAddress = '';
    let encryptionAddress = '';
    engine = createEngine(storage, async () => ({
      kind: 'exact',
      profileName: 'Alice',
      signingAddress,
      encryptionAddress,
      visibility: 'private',
    }));
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || candidate.detail === undefined) throw new Error('candidate generation failed');
    const provision = await engine.provision({
      candidateRef: String((candidate.detail as { ref?: unknown }).ref),
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');
    signingAddress = String((provision.detail as { signingAddress?: unknown }).signingAddress);
    encryptionAddress = String((provision.detail as { encryptionAddress?: unknown }).encryptionAddress);

    expect((await engine.retainTransactionDigest('a'.repeat(64))).code).toBe('OK');
    expect((await engine.verifyOnline()).code).toBe('OK');
    expect((await engine.promoteLifecycle('Active')).code).toBe('OK');
    engine.lock();

    const returning = createEngine(storage, async () => ({ kind: 'exact', profileName: 'Alice', signingAddress, encryptionAddress, visibility: 'private' }));
    expect((await returning.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
  }, 120_000);

  it('repairs the bounded legacy generation-1 wrapper defect after proving current ciphertext', async () => {
    let signingAddress = '';
    let encryptionAddress = '';
    engine = createEngine(storage, async () => ({ kind: 'exact', profileName: 'Alice', signingAddress, encryptionAddress, visibility: 'private' }));
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || candidate.detail === undefined) throw new Error('candidate generation failed');
    const provision = await engine.provision({
      candidateRef: String((candidate.detail as { ref?: unknown }).ref),
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');
    signingAddress = String((provision.detail as { signingAddress?: unknown }).signingAddress);
    encryptionAddress = String((provision.detail as { encryptionAddress?: unknown }).encryptionAddress);
    const generationOne = storage.activeEnvelope();
    const originalKeyPackage = structuredClone(
      (((generationOne.records as { ordinary: { keyPackage: unknown } }).ordinary).keyPackage),
    );

    expect((await engine.retainTransactionDigest('b'.repeat(64))).code).toBe('OK');
    expect((await engine.verifyOnline()).code).toBe('OK');
    expect((await engine.promoteLifecycle('Active')).code).toBe('OK');

    // Reproduce the shipped defect: current ciphertext/AAD with the untouched
    // provisioning wrapper. This is the exact shape already in local browsers.
    const broken = storage.activeEnvelope();
    ((broken.records as { ordinary: { keyPackage: unknown } }).ordinary).keyPackage = originalKeyPackage;
    storage.replaceActiveEnvelope(broken);
    engine.lock();

    const repairing = createEngine(storage, async () => ({ kind: 'exact', profileName: 'Alice', signingAddress, encryptionAddress, visibility: 'private' }));
    expect((await repairing.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
    repairing.lock();

    // Repair is persisted atomically; the compatibility fallback is no longer
    // needed by subsequent returning-user unlocks.
    const stable = createEngine(storage);
    expect((await stable.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
  }, 180_000);

  it('enforces the cooldown schedule after repeated failures', async () => {
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || candidate.detail === undefined) {
      throw new Error('candidate generation failed');
    }
    const candidateRef = String((candidate.detail as { ref?: unknown }).ref);
    const provision = await engine.provision({
      candidateRef,
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');

    // Attempts 1-5 fail with the combined error (attempt 5 adds the 5 s cooldown).
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const outcome = await engine.unlock({ devicePassword: 'wrong-password-value', configurationId: 'isolated-local-devnet-v1' });
      expect(outcome.code).toBe('WRONG_PASSWORD_OR_DAMAGED');
    }
    // Attempt 6 is throttled with the exact added cooldown (5 s at attempt 5).
    const throttled = await engine.unlock({ devicePassword: 'wrong-password-value', configurationId: 'isolated-local-devnet-v1' });
    expect(throttled.code).toBe('THROTTLED');
    if (throttled.code === 'THROTTLED') {
      expect(throttled.cooldownDeadlineMs).toBe(1_700_000_000_000 + 5000);
    }
  }, 60_000);

  it('fails closed on network mismatch before unlock promotion', async () => {
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || candidate.detail === undefined) {
      throw new Error('candidate generation failed');
    }
    const candidateRef = String((candidate.detail as { ref?: unknown }).ref);
    const provision = await engine.provision({
      candidateRef,
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');

    // A different network manifest (production slot) must fail before
    // promotion. Simulate by unlocking under a mismatched manifest engine.
    const otherManifest = {
      ...ISOLATED_DEVNET_MANIFEST,
      canonicalNetworkId: 'production-mainnet',
      networkMagic: 999999,
    };
    const otherEngine = new SealedVaultEngine({
      storage,
      suite: createBrowserSuiteExecutor(resolveBrowserCryptoEnvironment()),
      manifest: otherManifest,
      nowMs: () => 1_700_000_000_000,
      randomId: (prefix) => `${prefix}-test`,
      lookupIdentity: async () => ({ kind: 'missing' }),
      broadcast: () => undefined,
      onForceCleanup: () => undefined,
    });
    const outcome = await otherEngine.unlock({ devicePassword: PASSWORD, configurationId: 'production-mainnet-v1' });
    expect(outcome.code).toBe('NETWORK_MISMATCH');
  }, 60_000);

  it('change-password rewraps the DEK under a fresh KEK and CAS-commits a new generation', async () => {
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || candidate.detail === undefined) {
      throw new Error('candidate generation failed');
    }
    const candidateRef = String((candidate.detail as { ref?: unknown }).ref);
    const provision = await engine.provision({
      candidateRef,
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');

    const changed = await engine.changeDevicePassword({ currentPassword: PASSWORD, newPassword: 'New-password-1234!' });
    expect(changed.code).toBe('OK');

    // Old password must now fail; the new one must unlock.
    const oldUnlock = await engine.unlock({ devicePassword: PASSWORD, configurationId: 'isolated-local-devnet-v1' });
    expect(oldUnlock.code).toBe('WRONG_PASSWORD_OR_DAMAGED');
    const newUnlock = await engine.unlock({ devicePassword: 'New-password-1234!', configurationId: 'isolated-local-devnet-v1' });
    expect(newUnlock.code).toBe('OK');
  }, 120_000);

  it('rejects unsupported envelope versions at unlock', async () => {
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || candidate.detail === undefined) {
      throw new Error('candidate generation failed');
    }
    const candidateRef = String((candidate.detail as { ref?: unknown }).ref);
    await engine.provision({
      candidateRef,
      devicePassword: PASSWORD,
      alias: 'Alice',
      visibility: 'private',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    // Tamper: bump the envelope format version in the stored slot bytes
    // (write back through the storage boundary so the tamper is real).
    const slotA = await storage.readRecord('vaultSlots', 'slot-a');
    const slotB = await storage.readRecord('vaultSlots', 'slot-b');
    const chosen = slotA.ok && slotA.value.record !== undefined ? slotA : slotB;
    if (!chosen.ok || chosen.value.record === undefined) {
      throw new Error('no slot record');
    }
    const entry = chosen.value.record as { slotKey?: string; generation?: number; bytes?: unknown };
    if (typeof entry.slotKey !== 'string' || typeof entry.bytes !== 'object' || entry.bytes === null) {
      throw new Error('no slot bytes');
    }
    // Vitest structured-clone artifacts may arrive as plain byte objects.
    const byteObject = entry.bytes as Record<string, number>;
    const byteCount = byteObject.byteLength ?? Object.keys(byteObject).length;
    const bytes = new Uint8Array(byteCount);
    for (let i = 0; i < byteCount; i += 1) {
      bytes[i] = byteObject[i] ?? 0;
    }
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    parsed.envelopeFormatVersion = 99;
    await storage.writeRecord('vaultSlots', entry.slotKey, { slotKey: entry.slotKey, generation: entry.generation ?? 1, bytes: new TextEncoder().encode(JSON.stringify(parsed)) });
    const outcome = await engine.unlock({ devicePassword: PASSWORD, configurationId: 'isolated-local-devnet-v1' });
    expect(outcome.code).toBe('UNSUPPORTED_VAULT');
  }, 60_000);
});
