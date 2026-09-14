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
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { SealedVaultEngine, parseCurrentRecord, cooldownSecondsFor, abbreviateSigningAddress } from './sealed-vault';
import { createBrowserSuiteExecutor, resolveBrowserCryptoEnvironment } from '../crypto/executor';
import type { VaultStorageSession } from '../storage/wrapper';
import type { VaultResult } from '../../vault-core/contracts/results';
import { success, failure } from '../../vault-core/contracts/results';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import datVectors from '../../../../conformance/identity/v1/vectors/dat-vectors.json';
import { canonicalizeJsonBytes } from '../../vault-core/canonical/jcs';
import { createProductionWorkerEnvironment } from './worker-env';
import * as workerDerivation from './bip39-worker';

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

function createEngine(storage: VaultStorageSession, lookup: (address: string) => Promise<{ readonly kind: 'exact' | 'missing' | 'timeout' | 'unavailable'; readonly profileName?: string; readonly signingAddress?: string; readonly encryptionAddress?: string; readonly visibility?: 'private' | 'public' }> = async () => ({ kind: 'missing' }), nowMs: () => number = () => 1_700_000_000_000): SealedVaultEngine {
  let sequence = 0;
  return new SealedVaultEngine({
    storage,
    suite: createBrowserSuiteExecutor(resolveBrowserCryptoEnvironment()),
    manifest: ISOLATED_DEVNET_MANIFEST,
    nowMs,
    randomId: (prefix) => `${prefix}-test-${++sequence}`,
    lookupIdentity: lookup,
    broadcast: () => undefined,
    onForceCleanup: () => undefined,
  });
}

const PASSWORD = 'Tr0ub4dor&3-correct-horse';

// EPIC-001 -> FEAT-008 AC-008-041 -> Phase 3 Tasks 3.5/3.6;
// FEAT-003 Device-Password Contract -> Phase 3 Tasks 3.3/3.4.
describe('HushVotingApp TwinTests — recovered password normalization', () => {
  // FEAT-003 Phase 3 Tasks 3.3/3.4; FEAT-010 change-password authority.
  async function provisionCreated(engine: SealedVaultEngine, password: string) {
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || !candidate.detail) throw new Error('Candidate unavailable');
    const outcome = await engine.provision({ candidateRef: candidate.detail.ref, devicePassword: password,
      alias: 'Normalization test', visibility: 'private', producerId: 'P-01',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
        networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } });
    expect(outcome.code).toBe('OK');
  }

  it.each(['NFC', 'NFD'] as const)('unlocks a recovered %s password using its canonically equivalent spelling', async form => {
    const storage = new MemoryVaultStorage();
    const initial = createEngine(storage);
    const restarted = createEngine(storage);
    const chosen = 'Café-vault-Protection-42!'.normalize(form);
    const equivalent = 'Café-vault-Protection-42!'.normalize(form === 'NFC' ? 'NFD' : 'NFC');
    try {
      const derived = initial.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
      const selected = derived.detail?.candidates[0];
      if (derived.code !== 'OK' || !selected) throw new Error('Recovery candidate unavailable');
      for (const candidate of derived.detail!.candidates.slice(1)) initial.destroyCandidate(candidate.ref);
      const provisioned = await initial.provision({ candidateRef: selected.ref, devicePassword: chosen,
        alias: 'Selected recovery', visibility: 'private', producerId: selected.producerIds[0],
        configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
        networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
          networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } });
      expect(provisioned.code).toBe('OK');
      expect(provisioned.detail?.signingAddress === selected.signingAddress && provisioned.detail?.encryptionAddress === selected.encryptionAddress).toBe(true);
      initial.wipeSecrets();
      // Exact-input positive control proves the stored encrypted record is valid.
      expect((await restarted.unlock({ devicePassword: chosen, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
      restarted.wipeSecrets();
      expect((await restarted.unlock({ devicePassword: equivalent, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
    } finally { initial.wipeSecrets(); restarted.wipeSecrets(); }
  });

  it('changes a password using canonical-equivalent current input and reopens with canonical-equivalent new input', async () => {
    const storage = new MemoryVaultStorage();
    const engine = createEngine(storage);
    const reopened = createEngine(storage);
    const current = 'Café-current-Protection-42!';
    const next = 'Café-new-Protection-73!';
    try {
      await provisionCreated(engine, current);
      const before = storage.activeEnvelope();
      expect((await engine.changeDevicePassword({ currentPassword: current.normalize('NFD'), newPassword: next.normalize('NFD') })).code).toBe('OK');
      const after = storage.activeEnvelope();
      expect(after.preview).toEqual(before.preview);
      engine.wipeSecrets();
      expect((await reopened.unlock({ devicePassword: current, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('WRONG_PASSWORD_OR_DAMAGED');
      expect((await reopened.unlock({ devicePassword: next, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
    } finally { engine.wipeSecrets(); reopened.wipeSecrets(); }
  }, 60_000);

  it('preserves case, surrounding spaces and compatibility characters in device-password KDF input', async () => {
    const storage = new MemoryVaultStorage();
    const engine = createEngine(storage);
    const password = ' Café-Ａccess-Protection-42! ';
    try {
      await provisionCreated(engine, password.normalize('NFD'));
      engine.wipeSecrets();
      for (const changed of [password.trim(), password.toLowerCase(), password.normalize('NFKC')]) {
        const rejected = createEngine(storage);
        try {
          expect((await rejected.unlock({ devicePassword: changed, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('WRONG_PASSWORD_OR_DAMAGED');
        } finally { rejected.wipeSecrets(); }
      }
      const accepted = createEngine(storage);
      try {
        expect((await accepted.unlock({ devicePassword: password, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
      } finally { accepted.wipeSecrets(); }
    } finally { engine.wipeSecrets(); }
  }, 60_000);
});

// EPIC-001 -> FEAT-007 AC-007-052 / FEAT-010 AC-010-025.
// FEAT-007 Phase 3 Tasks 3.3/3.4; FEAT-010 Phase 3 Tasks 3.1/3.2.
// Pending presentation contract is tracked in submitted FEAT-030.
describe('HushVotingApp TwinTests — staged startup distinction', () => {
  it('does not classify a restarted provisional creation as an ordinary locked vault', async () => {
    const storage = new MemoryVaultStorage();
    const initial = createEngine(storage);
    const restarted = createEngine(storage);
    try {
      const candidate = initial.createCandidate({ wordCount: 24 });
      if (!candidate.detail) throw new Error('Fixture candidate unavailable');
      expect((await initial.provision({
        candidateRef: candidate.detail.ref, devicePassword: PASSWORD,
        alias: 'Alice', visibility: 'private', configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
        networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
          networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
        producerId: 'P-01',
      })).code).toBe('OK');
      expect(storage.activeEnvelope().preview).toHaveProperty('lifecycleStatus', 'PendingRegistration');
      initial.wipeSecrets();
      const inspected = await restarted.inspectStartup();
      expect(inspected.code).toBe('OK');
      expect(restarted.snapshot().hasSession).toBe(false);
      // Assert the forbidden existing classification without inventing the
      // future persisted origin field or closed worker/root response schema.
      expect(inspected.detail?.surface).not.toBe('lockedVault');
      expect(inspected.detail?.surface).toBe('staged');
    } finally { initial.wipeSecrets(); restarted.wipeSecrets(); }
  });
});

// EPIC-001 -> FEAT-008 AC-008-052 -> Phase 2 Tasks 2.3/2.4,
// Phase 3 Tasks 3.5/3.6. Fault occurs AFTER genuine cryptographic decryption.
describe('HushVotingApp TwinTests — closed recovered protection metadata', () => {
  it.each(['unknown', 'none', 'session-only', 'webauthn-prf', 'ubuntu-secret-service', 'android-keystore', 'version', 'unwrapped'])
  ('rejects %s metadata without a session or network fallback', async mode => {
    const storage = new MemoryVaultStorage();
    const lookup = vi.fn(async () => ({ kind: 'missing' as const }));
    const engine = createEngine(storage, lookup);
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK') throw new Error('Fixture candidate unavailable');
    const provision = await engine.provision({
      candidateRef: String((candidate.detail as { ref: string }).ref), devicePassword: PASSWORD,
      alias: 'Alice', visibility: 'private', configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
        networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
      producerId: 'P-01',
    });
    expect(provision.code).toBe('OK');
    engine.wipeSecrets();
    const original = JSON.stringify(storage.activeEnvelope());
    const cryptoApi = globalThis.crypto.subtle;
    const decrypt = cryptoApi.decrypt.bind(cryptoApi);
    let injected = 0;
    const spy = vi.spyOn(cryptoApi, 'decrypt').mockImplementation(async (...args) => {
      const result = await decrypt(...args);
      const bytes = new Uint8Array(result);
      // DEK unwrapping is untouched; only the authenticated ordinary record
      // receives this controlled metadata fault before the production parser.
      if (bytes.byteLength > 32 && bytes[0] === 123) {
        const record = JSON.parse(new TextDecoder().decode(bytes));
        if (Object.hasOwn(record, 'protectionModeClass')) {
          injected++;
          if (mode === 'version') record.schemaVersion = 999;
          else if (mode === 'unwrapped') record.unwrappedDataKey = 'forbidden-mode-override';
          else record.protectionModeClass = mode;
          bytes.fill(0);
          return new TextEncoder().encode(JSON.stringify(record)).buffer;
        }
      }
      return result;
    });
    try {
      expect((await engine.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('CORRUPT_VAULT');
      expect(injected).toBe(1);
      expect(engine.snapshot().hasSession).toBe(false);
      expect(lookup).not.toHaveBeenCalled();
      expect(JSON.stringify(storage.activeEnvelope()) === original).toBe(true);
    } finally { spy.mockRestore(); engine.wipeSecrets(); }
    try {
      expect((await engine.unlock({ devicePassword: '', configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).not.toBe('OK');
      expect(engine.snapshot().hasSession).toBe(false);
      expect((await engine.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
      expect(JSON.stringify(storage.activeEnvelope()) === original).toBe(true);
      expect(lookup).not.toHaveBeenCalled();
    } finally { engine.wipeSecrets(); }
  });
});

// EPIC-001 -> FEAT-007 AC-007-007 -> Phase 3 Tasks 3.1/3.2.
describe('HushVotingApp TwinTests — hidden invalid creation candidates', () => {
  afterEach(() => vi.restoreAllMocks());

  it.each(['invalid scalar', 'derivation exception'])('regenerates the whole hidden candidate after %s', mode => {
    const derive = vi.spyOn(workerDerivation, 'deriveP01KeysWorker');
    if (mode === 'invalid scalar') derive.mockReturnValueOnce(null);
    else derive.mockImplementationOnce(() => { throw new Error('Controlled derivation failure'); });
    const engine = createEngine(new MemoryVaultStorage());
    try {
      const candidate = engine.createCandidate({ wordCount: 24 });
      expect(candidate.code).toBe('OK');
      expect(derive).toHaveBeenCalledTimes(2);
      // Boolean comparison prevents rejected secret material in diagnostics.
      expect(derive.mock.calls[0][0] !== derive.mock.calls[1][0]).toBe(true);
      const reveal = engine.revealWords(candidate.detail!.ref);
      expect(reveal.code).toBe('OK');
      expect(reveal.detail!.words.join(' ') === derive.mock.calls[1][0]).toBe(true);
    } finally { engine.wipeSecrets(); }
  });

  it('exhausts three hidden attempts without publishing a candidate', () => {
    const derive = vi.spyOn(workerDerivation, 'deriveP01KeysWorker').mockReturnValue(null);
    const engine = createEngine(new MemoryVaultStorage());
    try {
      const candidate = engine.createCandidate({ wordCount: 24 });
      expect(candidate.code).toBe('UNKNOWN_FAILURE');
      expect(candidate.detail).toBeUndefined();
      expect(derive).toHaveBeenCalledTimes(3);
      expect(new Set(derive.mock.calls.map(([words]) => words)).size).toBe(3);
      expect(engine.snapshot().hasCandidate).toBe(false);
    } finally { engine.wipeSecrets(); }
  });
});

// EPIC-001 -> FEAT-010 AC-010-074/077 -> Phase 3 Tasks 3.7/3.8;
// consumed by FEAT-009 AC-009-072. Storage failures are not verified absence.
describe('HushVotingApp TwinTests — verified local removal', () => {
  afterEach(() => vi.restoreAllMocks());
  const records = [
    ['vaultSlots', 'slot-a'], ['vaultSlots', 'slot-b'], ['vaultJournal', 'current'],
    ['licenceJournal', 'slot-a'], ['licenceJournal', 'slot-b'], ['licenceJournal', 'pointer'],
    ['operationalSidecars', 'throttle'], ['operationalSidecars', 'lease'],
    ['operationalSidecars', 'persistenceAck'], ['operationalSidecars', 'epoch'],
  ] as const;
  async function arranged() {
    const storage = new MemoryVaultStorage();
    for (const [store, key] of records) await storage.writeRecord(store, key, { opaqueRemovalFixture: true });
    return { storage, engine: createEngine(storage) };
  }

  // FEAT-008 AC-008-068 -> Phase 3 Tasks 3.9/3.10. A completed
  // delete is insufficient until the final actual absence read resolves.
  it('withholds removal success until the last absence verification acknowledges', async () => {
    const { storage, engine } = await arranged();
    const read = storage.readRecord.bind(storage);
    let release: (() => void) | undefined;
    const held = new Promise<void>(resolve => { release = resolve; });
    let observed = false;
    const fault = vi.spyOn(storage, 'readRecord').mockImplementation(async (store, key) => {
      const actual = await read(store, key);
      if (store === 'operationalSidecars' && key === 'removalTombstone' && actual.ok && actual.value.record === undefined) {
        observed = true;
        await held;
      }
      return actual;
    });
    let completed = false;
    const removal = engine.removeLocalUser().then(result => { completed = true; return result; });
    try {
      await vi.waitFor(() => expect(observed).toBe(true));
      expect(completed).toBe(false);
      expect(engine.snapshot()).toMatchObject({ phase: 'locked', hasSession: false, hasCandidate: false });
      for (const [store, key] of records) expect(await read(store, key)).toEqual(success({ record: undefined }));
    } finally { release?.(); fault.mockRestore(); }
    expect((await removal).code).toBe('OK');
    expect((await engine.inspectStartup()).detail).toMatchObject({ surface: 'verifiedAbsent' });
  });

  it('stops before deleting durable records when the removal marker cannot be written', async () => {
    const { storage, engine } = await arranged();
    vi.spyOn(storage, 'writeRecord').mockResolvedValue(failure('StorageUnavailable'));
    const deleting = vi.spyOn(storage, 'deleteRecord');
    expect((await engine.removeLocalUser()).code).toBe('UNKNOWN_FAILURE');
    expect(deleting).not.toHaveBeenCalled();
    expect((await storage.readRecord('vaultSlots', 'slot-b')).ok).toBe(true);
    expect(await storage.readRecord('vaultSlots', 'slot-b')).toEqual(success({ record: { opaqueRemovalFixture: true } }));
  });

  it.each(records)('retains the removal marker when verifying %s/%s fails, then completes on retry', async (failedStore, failedKey) => {
    const { storage, engine } = await arranged();
    const read = storage.readRecord.bind(storage);
    const fault = vi.spyOn(storage, 'readRecord').mockImplementation((store, key) =>
      store === failedStore && key === failedKey ? Promise.resolve(failure('StorageUnavailable')) : read(store, key));
    expect((await engine.removeLocalUser()).code).toBe('UNKNOWN_FAILURE');
    expect((await engine.inspectStartup()).detail).toMatchObject({ surface: 'removalTombstone' });
    fault.mockRestore();
    expect((await engine.removeLocalUser()).code).toBe('OK');
    for (const [store, key] of records) expect(await storage.readRecord(store, key)).toEqual(success({ record: undefined }));
    expect(await storage.readRecord('operationalSidecars', 'removalTombstone')).toEqual(success({ record: undefined }));
  });

  it.each([
    ['vaultSlots', 'slot-b'], ['licenceJournal', 'pointer'], ['operationalSidecars', 'removalTombstone'],
  ])('rejects a successful-looking deletion that leaves %s/%s behind', async (failedStore, failedKey) => {
    const { storage, engine } = await arranged();
    const remove = storage.deleteRecord.bind(storage);
    vi.spyOn(storage, 'deleteRecord').mockImplementation((store, key) =>
      store === failedStore && key === failedKey ? Promise.resolve(success({ ok: true })) : remove(store, key));
    expect((await engine.removeLocalUser()).code).toBe('UNKNOWN_FAILURE');
    expect((await engine.inspectStartup()).detail).toMatchObject({ surface: 'removalTombstone' });
  });

  it.each(['slot-b', 'removalTombstone'])('keeps removal resumable when deleting %s fails', async failedKey => {
    const { storage, engine } = await arranged();
    const remove = storage.deleteRecord.bind(storage);
    const fault = vi.spyOn(storage, 'deleteRecord').mockImplementation((store, key) =>
      key === failedKey ? Promise.resolve(failure('StorageUnavailable')) : remove(store, key));
    expect((await engine.removeLocalUser()).code).toBe('UNKNOWN_FAILURE');
    expect((await engine.inspectStartup()).detail).toMatchObject({ surface: 'removalTombstone' });
    fault.mockRestore();
    expect((await engine.removeLocalUser()).code).toBe('OK');
  });

  it('does not claim success when final marker absence cannot be read', async () => {
    const { storage, engine } = await arranged();
    const read = storage.readRecord.bind(storage);
    vi.spyOn(storage, 'readRecord').mockImplementation((store, key) =>
      key === 'removalTombstone' ? Promise.resolve(failure('StorageUnavailable')) : read(store, key));
    expect((await engine.removeLocalUser()).code).toBe('UNKNOWN_FAILURE');
    expect((await engine.inspectStartup()).code).toBe('UNKNOWN_FAILURE');
  });
});

describe('HushVotingApp TwinTests — durable exact identity transaction', () => {
  // EPIC-001 -> FEAT-007 AC-007-035 -> Phase 3 Tasks 3.5/3.6.
  it.each([
    ...['ACCEPTED', 'PENDING', 'ALREADY_EXISTS'].flatMap(status => [
      { status, successfull: false }, { status },
      { status, successfull: true, validationCode: 'FULL_IDENTITY_INVALID_SIGNATURE' },
    ]),
    { status: 'REJECTED', successfull: true, validationCode: 'FULL_IDENTITY_INVALID_SIGNATURE' },
    { status: 'UNSPECIFIED', successfull: true }, { status: 'FUTURE_STATUS', successfull: true },
  ])('does not accept incompatible identity submission fields %j', async reply => {
    const storage = new MemoryVaultStorage();
    const engine = createEngine(storage);
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (!candidate.detail) throw new Error('Candidate unavailable');
    await engine.provision({ candidateRef: candidate.detail.ref, devicePassword: PASSWORD,
      alias: 'Alice', visibility: 'private', producerId: 'P-01', configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic,
        configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } });
    try {
      const submit = vi.fn(async () => ({ ok: true as const, reply }));
      expect(await engine.submitIdentityTransaction({ alias: 'Alice', visibility: 'private', submit }))
        .toEqual({ code: 'OK', detail: { status: 'compatibilityError' } });
      expect(submit).toHaveBeenCalledOnce();
    } finally { engine.lock(); }
  });

  // FEAT-007 AC-007-045 -> Phase 3 Tasks 3.5/3.6, Phase 7 Tasks 7.1/7.2.
  it.each(['same authority', 'fresh authority'])('seals before submission and reuses identical bytes with %s', async (mode) => {
    const storage = new MemoryVaultStorage();
    const engine = createEngine(storage, async () => ({ kind: 'missing' }));
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (candidate.code !== 'OK' || !candidate.detail) throw new Error('Candidate unavailable');
    expect((await engine.provision({ candidateRef: candidate.detail.ref, devicePassword: PASSWORD,
      alias: 'Alice', visibility: 'private', producerId: 'P-01',
      configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic,
        configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } })).code).toBe('OK');
    const submitted: string[] = [];
    const submit = async (json: string) => {
      expect(storage.activeEnvelope().recordSchemaVersion).toBe(2);
      expect(JSON.stringify(storage.activeEnvelope()).includes(json)).toBe(false);
      submitted.push(json);
      return { ok: false as const, failure: 'unavailable' };
    };
    expect((await engine.submitIdentityTransaction({ alias: 'Alice', visibility: 'private', submit })).code).toBe('OK');
    let restarted = engine;
    if (mode === 'fresh authority') {
      engine.lock();
      restarted = createEngine(storage, async () => ({ kind: 'missing' }));
      expect((await restarted.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
    }
    expect((await restarted.submitIdentityTransaction({ alias: 'Alice', visibility: 'private', submit })).code).toBe('OK');
    expect(submitted).toHaveLength(2);
    expect(submitted[1] === submitted[0]).toBe(true);
    restarted.lock();
  }, 120_000);
});

describe('credential import cancellation', () => {
  // EPIC-001 -> FEAT-009 AC-009-057 -> Phase 3 Tasks 3.7/3.8;
  // FEAT-004 atomic journal Task 3.6. Corruption occurs in persisted bytes.
  it.each(['ciphertext', 'preview'] as const)('rejects changed %s at imported-stage read-back before committing or publishing a session', async mode => {
    const vector = datVectors.vectors.find(vector => vector.id === 'D-001');
    if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Missing approved import fixture');
    const storage = new MemoryVaultStorage(), lookup = vi.fn(async () => ({ kind: 'unavailable' as const }));
    const engine = createEngine(storage, lookup);
    const source = new Uint8Array(Buffer.from(vector.envelopeHex, 'hex'));
    const write = storage.writeRecord.bind(storage);
    const cas = vi.spyOn(storage, 'casJournal');
    let changed = false;
    vi.spyOn(storage, 'writeRecord').mockImplementation(async (store, key, value) => {
      if (store === 'vaultSlots' && !changed) {
        const slot = structuredClone(value) as { bytes: Uint8Array };
        const envelope = JSON.parse(new TextDecoder().decode(slot.bytes));
        if (mode === 'preview') envelope.preview.alias = 'Changed during persistence';
        else {
          const ordinary = envelope.records.ordinary;
          ordinary.ciphertext = (ordinary.ciphertext[0] === 'A' ? 'B' : 'A') + ordinary.ciphertext.slice(1);
        }
        slot.bytes = canonicalizeJsonBytes(envelope);
        changed = true;
        return write(store, key, slot);
      }
      return write(store, key, value);
    });
    try {
      const imported = await engine.importFileCandidate({ fileBytes: source, filePassword: vector.password });
      if (imported.code !== 'OK' || !imported.detail) throw new Error('Approved fixture did not import');
      const outcome = await engine.provision({ candidateRef: imported.detail.ref, devicePassword: PASSWORD,
        alias: 'Imported fixture', visibility: 'private', producerId: 'P-01', configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
        networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
          networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } });
      expect(changed).toBe(true);
      expect(outcome.code).toBe('UNKNOWN_FAILURE');
      expect(cas).not.toHaveBeenCalled();
      expect(await storage.readJournal()).toEqual(success({ journal: null }));
      expect(engine.snapshot().hasSession).toBe(false);
      expect(lookup).not.toHaveBeenCalled();
    } finally { source.fill(0); engine.wipeSecrets(); }
  });

  // EPIC-001 -> FEAT-009 AC-009-062/063 -> Phase 3 Tasks 3.7/3.8; FEAT evidence only.
  it.each(['exact', 'unavailable', 'key mismatch', 'ciphertext', 'version'] as const)('resumes imported keys without source and handles %s in a fresh authority', async mode => {
    const vector = datVectors.vectors.find(vector => vector.id === 'D-001');
    if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Missing approved import fixture');
    const storage = new MemoryVaultStorage(), original = createEngine(storage);
    const source = new Uint8Array(Buffer.from(vector.envelopeHex, 'hex'));
    let resumed: SealedVaultEngine | undefined;
    try {
      const imported = await original.importFileCandidate({ fileBytes: source, filePassword: vector.password });
      if (imported.code !== 'OK' || !imported.detail) throw new Error('Approved fixture did not import');
      const candidate = imported.detail;
      expect((await original.provision({ candidateRef: candidate.ref, devicePassword: PASSWORD, alias: 'Imported fixture', visibility: 'private',
        producerId: 'P-01', configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
        networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic,
          configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } })).code).toBe('OK');
      original.wipeSecrets();
      source.fill(0);
      if (mode === 'ciphertext' || mode === 'version') {
        const envelope = storage.activeEnvelope();
        if (mode === 'version') envelope.envelopeFormatVersion = 999;
        else {
          const ordinary = (envelope.records as { ordinary: { ciphertext: string } }).ordinary;
          ordinary.ciphertext = (ordinary.ciphertext[0] === 'A' ? 'B' : 'A') + ordinary.ciphertext.slice(1);
        }
        storage.replaceActiveEnvelope(envelope);
      }
      const lookup = vi.fn(async () => ({ kind: mode === 'unavailable' ? 'unavailable' as const : 'exact' as const,
        profileName: 'Current chain profile', visibility: 'private' as const,
        signingAddress: candidate.signingAddress, encryptionAddress: mode === 'key mismatch' ? 'different-encryption-key' : candidate.encryptionAddress }));
      resumed = createEngine(storage, lookup);
      const importing = vi.spyOn(resumed, 'importFileCandidate');
      const unlocked = await resumed.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId });
      expect(lookup).not.toHaveBeenCalled();
      expect(resumed.snapshot().hasCandidate).toBe(false);
      expect(resumed.revealWords(candidate.ref).code).toBe('INVALID_INPUT');
      expect(importing).not.toHaveBeenCalled();
      expect(source.every(byte => byte === 0)).toBe(true);
      if (mode === 'ciphertext' || mode === 'version') {
        expect(unlocked.code).toBe(mode === 'ciphertext' ? 'WRONG_PASSWORD_OR_DAMAGED' : 'UNSUPPORTED_VAULT');
        expect(resumed.snapshot().hasSession).toBe(false);
        return;
      }
      expect(unlocked.code).toBe('OK');
      if (mode === 'unavailable' || mode === 'key mismatch') {
        expect((await resumed.verifyOnline()).code).toBe(mode === 'unavailable' ? 'NETWORK_UNAVAILABLE' : 'ENCRYPTION_KEY_MISMATCH');
        expect((await resumed.promoteLifecycle('Active')).code).toBe('UNKNOWN_FAILURE');
        expect(storage.activeEnvelope().preview).toMatchObject({ lifecycleStatus: 'PendingRegistration' });
        return;
      }
      expect((await resumed.verifyOnline()).detail).toMatchObject({ requiresPromotion: true });
      expect(lookup).toHaveBeenCalledExactlyOnceWith(candidate.signingAddress);
      expect((await resumed.promoteLifecycle('Active')).code).toBe('OK');
      expect(storage.activeEnvelope().preview).toMatchObject({ lifecycleStatus: 'Active', alias: 'Current chain profile' });
      expect(importing).not.toHaveBeenCalled();
      expect(source.every(byte => byte === 0)).toBe(true);
    } finally { source.fill(0); original.wipeSecrets(); resumed?.wipeSecrets(); }
  });

  it('enforces one authority-wide import backoff across ciphertext changes and resets only after valid credentials', async () => {
    const vector = datVectors.vectors.find(vector => vector.id === 'D-001');
    if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Missing approved import fixture');
    let now = 1_700_000_000_000;
    const engine = createEngine(new MemoryVaultStorage(), async () => ({ kind: 'missing' }), () => now);
    const good = new Uint8Array(Buffer.from(vector.envelopeHex, 'hex'));
    for (const seconds of [0, 0, 2, 4, 8, 16, 30]) {
      const changed = good.slice(); changed[changed.length - 1] ^= 1;
      const failed = await engine.importFileCandidate({ fileBytes: changed, filePassword: vector.password });
      expect(failed).toMatchObject({ code: 'WRONG_PASSWORD_OR_DAMAGED', cooldownDeadlineMs: now + seconds * 1000 });
      if (seconds > 0) {
        const blocked = await engine.importFileCandidate({ fileBytes: good, filePassword: vector.password });
        expect(blocked).toMatchObject({ code: 'THROTTLED', cooldownDeadlineMs: now + seconds * 1000 });
        now += seconds * 1000;
      }
    }
    expect((await engine.importFileCandidate({ fileBytes: good, filePassword: vector.password })).code).toBe('OK');
    expect(await engine.importFileCandidate({ fileBytes: good, filePassword: 'incorrect' })).toMatchObject({ code: 'WRONG_PASSWORD_OR_DAMAGED', cooldownDeadlineMs: now });
    engine.wipeSecrets();
  });

  it('cannot publish a decrypted candidate after its authority is wiped', async () => {
    const vector = datVectors.vectors.find(vector => vector.id === 'D-001');
    if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Missing approved import fixture');
    const engine = createEngine(new MemoryVaultStorage());
    const importing = engine.importFileCandidate({ fileBytes: new Uint8Array(Buffer.from(vector.envelopeHex, 'hex')), filePassword: vector.password });
    engine.wipeSecrets();
    const result = await importing;
    expect(result.code).toBe('INVALID_INPUT');
    expect(engine.snapshot().hasCandidate).toBe(false);
    expect(engine.snapshot().hasSession).toBe(false);
  });
});

describe('HushVotingApp TwinTests — failed credential attempt cleanup', () => {
  // EPIC-001 / FEAT-009 AC-009-022 / Phase 3 Tasks 3.3–3.4.
  afterEach(() => vi.restoreAllMocks());

  function observeCryptoBuffers() {
    const passwordViews: Uint8Array[] = [], plaintextViews: Uint8Array[] = [];
    const keyPolicies: boolean[] = [];
    const cryptoApi = globalThis.crypto.subtle;
    const importKey = cryptoApi.importKey.bind(cryptoApi);
    const deriveKey = cryptoApi.deriveKey.bind(cryptoApi);
    const decrypt = cryptoApi.decrypt.bind(cryptoApi);
    vi.spyOn(cryptoApi, 'importKey').mockImplementation(async (...args) => {
      const [format, data, algorithm] = args;
      if (format === 'raw' && algorithm === 'PBKDF2') {
        if (ArrayBuffer.isView(data)) passwordViews.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        else if (data instanceof ArrayBuffer) passwordViews.push(new Uint8Array(data));
      }
      return Reflect.apply(importKey, cryptoApi, args);
    });
    vi.spyOn(cryptoApi, 'deriveKey').mockImplementation(async (...args) => {
      const key = await deriveKey(...args);
      keyPolicies.push(!key.extractable && key.usages.length === 1 && key.usages[0] === 'decrypt');
      return key;
    });
    vi.spyOn(cryptoApi, 'decrypt').mockImplementation(async (...args) => {
      const plaintext = await decrypt(...args);
      plaintextViews.push(new Uint8Array(plaintext));
      return plaintext;
    });
    return { passwordViews, plaintextViews, keyPolicies };
  }

  it('releases successful import transfers and actual crypto buffers before returning the candidate for online work (AC-009-035)', async () => {
    const vector = datVectors.vectors.find(vector => vector.id === 'D-001');
    if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Missing approved import vector');
    const storage = new MemoryVaultStorage(), fetchImpl = vi.fn<typeof fetch>();
    const { env, engine, secrets } = createProductionWorkerEnvironment({
      storage, suite: createBrowserSuiteExecutor(resolveBrowserCryptoEnvironment()),
      appIdentity: { appVersion: '0.1.0', buildDigest: '0123456789ab' }, runtimeConfigId: 'development-localhost',
      deliver: () => undefined, broadcast: () => undefined, onForceCleanup: () => undefined, fetchImpl,
    });
    const observed = observeCryptoBuffers();
    let sourceBytes: Uint8Array | undefined;
    const importFile = engine.importFileCandidate.bind(engine);
    vi.spyOn(engine, 'importFileCandidate').mockImplementation(input => {
      sourceBytes = input.fileBytes;
      return importFile(input);
    });
    const operationId = 'successful-import-cleanup';
    secrets.store({ operationId, kind: 'fileBytes', value: Buffer.from(vector.envelopeHex, 'hex').toString('base64url'), consumed: false });
    secrets.store({ operationId, kind: 'filePassword', value: vector.password, consumed: false });
    try {
      const outcome = await env.executeOperation({ kind: 'operation', operation: 'importFileCandidate', operationVersion: 1,
        clientChannel: 'app-twin', authorityEpoch: 1, operationId }, 1);
      expect(outcome.outcome).toBe('OK');
      expect(secrets.take(operationId, 'fileBytes')).toBeNull();
      expect(secrets.take(operationId, 'filePassword')).toBeNull();
      expect(sourceBytes?.byteLength).toBeGreaterThan(0);
      expect(sourceBytes?.every(byte => byte === 0)).toBe(true);
      expect(observed.passwordViews).toHaveLength(1);
      expect(observed.plaintextViews).toHaveLength(1);
      expect([...observed.passwordViews, ...observed.plaintextViews].every(view => view.every(byte => byte === 0))).toBe(true);
      expect(observed.keyPolicies).toEqual([true]);
      expect(engine.snapshot().hasCandidate).toBe(true);
      expect(engine.snapshot().hasSession).toBe(false);
      expect(await storage.readJournal()).toEqual(success({ journal: null }));
      expect(fetchImpl).not.toHaveBeenCalled();
    } finally { engine.wipeSecrets(); }
  });

  it.each(['D-002', 'D-005', 'D-008'])('clears password bytes after authentication failure %s without publishing credentials', async id => {
    const vector = datVectors.vectors.find(vector => vector.id === id);
    if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Missing approved negative import vector');
    const storage = new MemoryVaultStorage(), lookup = vi.fn(async () => ({ kind: 'missing' as const }));
    const engine = createEngine(storage, lookup);
    const observed = observeCryptoBuffers();
    try {
      const outcome = await engine.importFileCandidate({ fileBytes: new Uint8Array(Buffer.from(vector.envelopeHex, 'hex')), filePassword: vector.password });
      expect(outcome.code).toBe('WRONG_PASSWORD_OR_DAMAGED');
      expect(observed.passwordViews).toHaveLength(1);
      expect(observed.passwordViews.every(view => view.every(byte => byte === 0))).toBe(true);
      expect(observed.keyPolicies).toEqual([true]);
      expect(observed.plaintextViews).toHaveLength(0);
      expect(engine.snapshot().hasCandidate).toBe(false);
      expect(engine.snapshot().hasSession).toBe(false);
      expect(await storage.readJournal()).toEqual(success({ journal: null }));
      expect(lookup).not.toHaveBeenCalled();
    } finally { engine.wipeSecrets(); }
  });

  it('clears authenticated plaintext bytes even when strict parsing rejects the credential record', async () => {
    const vector = datVectors.vectors.find(vector => vector.id === 'D-009');
    if (!vector?.payloadJson) throw new Error('Missing approved malformed payload');
    const salt = crypto.getRandomValues(new Uint8Array(16)), nonce = crypto.getRandomValues(new Uint8Array(12));
    const passwordBytes = new TextEncoder().encode('cleanup-test-password');
    const plaintext = new TextEncoder().encode(vector.payloadJson);
    let envelope: Uint8Array;
    try {
      const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, material,
        { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, plaintext));
      envelope = new Uint8Array(36 + ciphertext.length);
      envelope.set(new TextEncoder().encode('HUSH')); new DataView(envelope.buffer).setInt32(4, 1, true);
      envelope.set(salt, 8); envelope.set(nonce, 24); envelope.set(ciphertext, 36);
    } finally { passwordBytes.fill(0); plaintext.fill(0); }
    const storage = new MemoryVaultStorage(), lookup = vi.fn(async () => ({ kind: 'missing' as const }));
    const engine = createEngine(storage, lookup), observed = observeCryptoBuffers();
    try {
      const outcome = await engine.importFileCandidate({ fileBytes: envelope, filePassword: 'cleanup-test-password' });
      expect(outcome.code).toBe('INVALID_INPUT');
      expect(observed.passwordViews).toHaveLength(1);
      expect(observed.plaintextViews).toHaveLength(1);
      expect([...observed.passwordViews, ...observed.plaintextViews].every(view => view.every(byte => byte === 0))).toBe(true);
      expect(observed.keyPolicies).toEqual([true]);
      expect(engine.snapshot().hasCandidate).toBe(false);
      expect(engine.snapshot().hasSession).toBe(false);
      expect(await storage.readJournal()).toEqual(success({ journal: null }));
      expect(lookup).not.toHaveBeenCalled();
    } finally { engine.wipeSecrets(); envelope.fill(0); }
  });
});

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
  afterEach(() => { engine.wipeSecrets(); vi.useRealTimers(); });

  // EPIC-001 -> FEAT-008 AC-008-053 -> Phase 3 Tasks 3.5/3.6.
  it.each([[0, false], [1, false], [0, true], [1, true]] as const)(
    'publishes selected recovery candidate %s only after journal commit (abort=%s)', async (selectedIndex, abort) => {
      const derived = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
      if (derived.code !== 'OK' || derived.detail?.candidates.length !== 2) throw new Error('Recovery candidate set unavailable');
      const selected = derived.detail.candidates[selectedIndex], discarded = derived.detail.candidates[1 - selectedIndex];
      expect(engine.destroyCandidate(discarded.ref).code).toBe('OK');
      const commit = storage.casJournal.bind(storage);
      let entered!: () => void, release!: () => void;
      const enteredCommit = new Promise<void>(resolve => { entered = resolve; });
      const released = new Promise<void>(resolve => { release = resolve; });
      vi.spyOn(storage, 'casJournal').mockImplementation(async (expected, next) => {
        entered(); await released;
        return abort ? failure('StorageUnavailable') : commit(expected, next);
      });
      let completed = false;
      const provisioning = engine.provision({ candidateRef: selected.ref, devicePassword: PASSWORD,
        alias: 'Selected recovery', visibility: 'private', producerId: selected.producerIds[0],
        configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
        networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
          networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } })
        .then(result => { completed = true; return result; });
      try {
        await enteredCommit;
        expect(completed).toBe(false);
        expect(engine.snapshot().hasSession).toBe(false);
        expect(await storage.readJournal()).toEqual(success({ journal: null }));
        release();
        const result = await provisioning;
        if (abort) {
          expect(result.code).toBe('UNKNOWN_FAILURE');
          expect(engine.snapshot().hasSession).toBe(false);
          expect(await storage.readJournal()).toEqual(success({ journal: null }));
          return;
        }
        expect(result.code).toBe('OK');
        expect(result.detail?.signingAddress === selected.signingAddress && result.detail?.encryptionAddress === selected.encryptionAddress).toBe(true);
        expect(engine.snapshot()).toMatchObject({ phase: 'verificationOnly', hasCandidate: false, hasSession: true });
        expect(storage.activeEnvelope().preview).toMatchObject({ lifecycleStatus: 'PendingRegistration', alias: 'Selected recovery' });
        engine.lock();
        expect((await engine.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
        const lookup = vi.fn(async () => ({ kind: 'exact' as const, profileName: 'Selected recovery', visibility: 'private' as const,
          signingAddress: selected.signingAddress, encryptionAddress: selected.encryptionAddress }));
        const restarted = createEngine(storage, lookup);
        try {
          expect((await restarted.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId })).code).toBe('OK');
          expect((await restarted.verifyOnline()).code).toBe('OK');
          expect(lookup).toHaveBeenCalledExactlyOnceWith(selected.signingAddress);
        } finally { restarted.wipeSecrets(); }
      } finally { release(); await provisioning; }
    });

  // EPIC-001 -> FEAT-008 AC-008-021 -> Phase 3 Tasks 3.5/3.6.
  it.each([0, 1])('cannot provision a discarded recovery candidate when candidate %s is selected', async selectedIndex => {
    const derived = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
    if (derived.code !== 'OK' || derived.detail?.candidates.length !== 2) throw new Error('Recovery candidate set unavailable');
    const selected = derived.detail.candidates[selectedIndex];
    const discarded = derived.detail.candidates[1 - selectedIndex];
    expect(engine.destroyCandidate(discarded.ref).code).toBe('OK');
    const write = vi.spyOn(storage, 'writeRecord');
    const input = { candidateRef: discarded.ref, devicePassword: PASSWORD, alias: 'Selected recovery', visibility: 'private' as const,
      producerId: selected.producerIds[0], configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
      networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic,
        configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } };
    expect(await engine.provision(input)).toEqual({ code: 'INVALID_INPUT', reason: 'unknown-candidate' });
    expect(write).not.toHaveBeenCalled();
    expect(engine.snapshot().hasSession).toBe(false);
    const provisioned = await engine.provision({ ...input, candidateRef: selected.ref });
    expect(provisioned.code).toBe('OK');
    expect(provisioned.detail?.signingAddress === selected.signingAddress && provisioned.detail?.encryptionAddress === selected.encryptionAddress).toBe(true);
    engine.lock();
    const unlocked = await engine.unlock({ devicePassword: PASSWORD, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId });
    expect(unlocked.code).toBe('OK');
    expect(engine.snapshot().hasSession).toBe(true);
  });

  it('destroys unprovisioned recovery candidates at the ten-minute authority deadline', async () => {
    vi.useFakeTimers();
    const result = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
    expect(result.code).toBe('OK');
    await vi.advanceTimersByTimeAsync(599_999);
    expect(engine.snapshot().hasCandidate).toBe(true);
    await vi.advanceTimersByTimeAsync(1);
    expect(engine.snapshot().hasCandidate).toBe(false);
    for (const candidate of result.detail?.candidates ?? []) expect(engine.destroyCandidate(candidate.ref).code).toBe('INVALID_INPUT');
  });

  it('distinguishes correction errors using only closed codes and numbered word positions', () => {
    const words = Array<string>(12).fill('abandon');
    words[2] = 'notabipword';
    expect(engine.deriveWordsCandidate({ mnemonic: words.join(' '), producerId: 'P-01', wordCount: 12 })).toEqual({
      code: 'INVALID_INPUT', reason: 'UNKNOWN_WORD', invalidPositions: [3],
    });
    words[2] = 'abandon';
    expect(engine.deriveWordsCandidate({ mnemonic: words.join(' '), producerId: 'P-01', wordCount: 12 })).toEqual({
      code: 'INVALID_INPUT', reason: 'INVALID_CHECKSUM', invalidPositions: [],
    });
    words[11] = 'about';
    const ordinary = engine.deriveWordsCandidate({ mnemonic: words.join(' '), producerId: 'P-01', wordCount: 12 });
    const normalized = engine.deriveWordsCandidate({ mnemonic: `  ${words.join('\t\n').toUpperCase()}  `, producerId: 'P-01', wordCount: 12 });
    expect(ordinary.code).toBe('OK');
    expect(normalized.code).toBe('OK');
    expect(normalized.detail?.signingAddress === ordinary.detail?.signingAddress).toBe(true);
    expect(normalized.detail?.encryptionAddress === ordinary.detail?.encryptionAddress).toBe(true);
  });

  it('derives every approved recovery format and deduplicates the historical address pair with provenance', () => {
    const phrase = [...Array<string>(23).fill('abandon'), 'art'].join(' ');
    const result = engine.deriveRecoveryCandidates({ mnemonic: phrase, wordCount: 24 });
    expect(result.code).toBe('OK');
    const candidates = result.detail?.candidates;
    expect(candidates).toHaveLength(2);
    expect(candidates?.map(candidate => candidate.producerIds)).toEqual([['P-01'], ['P-02', 'P-03']]);
    expect(candidates?.map(candidate => candidate.signingAddress.length)).toEqual([66, 130]);
    expect(candidates?.map(candidate => candidate.encryptionAddress.length)).toEqual([66, 130]);
    for (const candidate of candidates ?? []) {
      expect(engine.revealWords(candidate.ref).code).toBe('INVALID_INPUT');
      expect(engine.destroyCandidate(candidate.ref).code).toBe('OK');
      expect(engine.revealWords(candidate.ref).code).toBe('INVALID_INPUT');
    }
    const twelve = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(11).fill('abandon'), 'about'].join(' '), wordCount: 12 });
    expect(twelve.detail?.candidates.map(candidate => candidate.producerIds)).toEqual([['P-01']]);
  });

  it('destroys every partial candidate when an applicable producer fails', () => {
    const original = engine.deriveWordsCandidate.bind(engine);
    const derive = vi.spyOn(engine, 'deriveWordsCandidate');
    derive.mockImplementationOnce(original).mockReturnValueOnce({ code: 'UNKNOWN_FAILURE', supportCode: 'TEST_PRODUCER_FAILURE' });
    const result = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
    expect(result.code).toBe('UNKNOWN_FAILURE');
    expect(result.detail).toBeUndefined();
    expect(engine.snapshot().hasCandidate).toBe(false);
  });

  // EPIC-001 -> FEAT-008 AC-008-020 -> Phase 3 Tasks 3.1/3.2.
  it.each(['P-02', 'P-03'])('revokes all earlier candidates when %s throws during recovery derivation', async failedProducer => {
    const original = engine.deriveWordsCandidate.bind(engine);
    const refs: string[] = [];
    vi.spyOn(engine, 'deriveWordsCandidate').mockImplementation(input => {
      if (input.producerId === failedProducer) throw new Error('Controlled producer encoding failure');
      const result = original(input);
      if (result.detail) refs.push(result.detail.ref);
      return result;
    });
    const result = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
    expect(refs).toHaveLength(failedProducer === 'P-02' ? 1 : 2);
    expect(result).toEqual({ code: 'UNKNOWN_FAILURE', supportCode: 'RECOVERY_DERIVATION_FAILED' });
    expect(engine.snapshot().hasCandidate).toBe(false);
    for (const ref of refs) expect(engine.destroyCandidate(ref)).toEqual({ code: 'INVALID_INPUT', reason: 'unknown-candidate' });
    expect(await engine.inspectStartup()).toMatchObject({ code: 'OK', detail: { surface: 'verifiedAbsent' } });
  });

  it('grants a new bounded explicit reveal without expiring or regenerating the candidate', () => {
    let now = 1_700_000_000_000;
    const authority = createEngine(storage, undefined, () => now);
    const candidate = authority.createCandidate({ wordCount: 24 });
    const ref = String((candidate.detail as { ref: string }).ref);
    const first = authority.revealWords(ref);
    now += 60_001;
    const second = authority.revealWords(ref);
    expect(second.code).toBe('OK');
    expect(second.detail).toMatchObject({ expiresAtMs: now + 60_000 });
    expect(first.detail?.words.join(' ') === second.detail?.words.join(' ')).toBe(true);
    authority.destroyCandidate(ref);
    expect(authority.revealWords(ref).code).toBe('INVALID_INPUT');
  });

  it('does not declare empty authority while a candidate exists only in worker memory', async () => {
    const candidate = engine.createCandidate({ wordCount: 24 });
    if (!candidate.detail) throw new Error('Expected candidate');
    const result = await engine.inspectStartup();
    expect(result.code).not.toBe('OK');
    expect(result.detail).toBeUndefined();
    expect(engine.snapshot().hasCandidate).toBe(true);
    expect(engine.destroyCandidate(candidate.detail.ref).code).toBe('OK');
    expect((await engine.inspectStartup()).detail).toMatchObject({ surface: 'verifiedAbsent' });
  });

  it('starts with verified-absent startup surface', async () => {
    const result = await engine.inspectStartup();
    expect(result.code).toBe('OK');
    if (result.code === 'OK') {
      expect(result.detail).toMatchObject({ surface: 'verifiedAbsent' });
    }
  });

  // FEAT-009 AC-009-001 / Phase 3 Tasks 3.1–3.2: unreadable is not absent.
  it.each([
    ['operationalSidecars', 'removalTombstone'], ['vaultSlots', 'slot-a'], ['vaultSlots', 'slot-b'],
  ])('never reports empty custody when startup cannot read %s/%s', async (failedStore, failedKey) => {
    const read = storage.readRecord.bind(storage);
    vi.spyOn(storage, 'readRecord').mockImplementation((store, key) =>
      store === failedStore && key === failedKey ? Promise.resolve(failure('StorageUnavailable')) : read(store, key));
    const result = await engine.inspectStartup();
    expect(result.code).toBe('UNKNOWN_FAILURE');
    expect(result.detail).toBeUndefined();
    expect(engine.snapshot().hasCandidate).toBe(false);
    expect(engine.snapshot().hasSession).toBe(false);
  });

  it('provisions, inspects as staged, unlocks, verifies, locks, removes', async () => {
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
      // PendingRegistration takes precedence over an ordinary Active locked vault.
      expect(inspect.detail).toMatchObject({ surface: 'staged' });
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
    // FEAT-008 resume must finish the durable transition before root access.
    expect(verified.detail).toMatchObject({ requiresPromotion: true });
    expect((await verifyEngine.promoteLifecycle('Active')).code).toBe('OK');
    expect((await verifyEngine.verifyOnline()).detail).toMatchObject({ requiresPromotion: false });

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

// EPIC-001 -> FEAT-008 AC-008-051 / FEAT-009 AC-009-054;
// Phase 3 Tasks 3.5/3.6 and 3.7/3.8, respectively; FEAT-033 integration repair.
describe('HushVotingApp TwinTests — real volatile recovered authority', () => {
  it.each(['words', 'file'] as const)('verifies and locks a %s session without any persistent write', async source => {
    const storage = new MemoryVaultStorage();
    const writes = [vi.spyOn(storage, 'writeRecord'), vi.spyOn(storage, 'deleteRecord'),
      vi.spyOn(storage, 'clearStore'), vi.spyOn(storage, 'casRecord'), vi.spyOn(storage, 'casJournal')];
    let profile: { signingAddress: string; encryptionAddress: string } | null = null;
    const engine = createEngine(storage, async () => profile
      ? { kind: 'exact', ...profile, profileName: 'Recovered', visibility: 'private' }
      : { kind: 'missing' });
    try {
      let ref: string;
      if (source === 'words') {
        const derived = engine.deriveRecoveryCandidates({ mnemonic: [...Array<string>(23).fill('abandon'), 'art'].join(' '), wordCount: 24 });
        if (derived.code !== 'OK' || !derived.detail) throw new Error('Public recovery fixture unavailable');
        ref = derived.detail.candidates[0].ref; profile = derived.detail.candidates[0];
      } else {
        const vector = datVectors.vectors.find(item => item.id === 'D-001');
        if (!vector?.envelopeHex || vector.password === undefined) throw new Error('Public file fixture unavailable');
        const imported = await engine.importFileCandidate({ fileBytes: new Uint8Array(Buffer.from(vector.envelopeHex, 'hex')), filePassword: vector.password });
        if (imported.code !== 'OK' || !imported.detail) throw new Error('Public import failed');
        ref = imported.detail.ref; profile = imported.detail;
      }
      expect((await engine.provisionSessionOnly({ candidateRef: ref, alias: 'Recovered', visibility: 'private',
        configurationId: ISOLATED_DEVNET_MANIFEST.configurationId, producerId: 'P-01',
        networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId,
          networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId } })).code).toBe('OK');
      expect(engine.snapshot()).toMatchObject({ hasCandidate: false, hasSession: true, phase: 'verificationOnly' });
      expect(engine.licenceActor()).toBeNull();
      expect((await engine.verifyOnline()).code).toBe('OK');
      expect((await engine.promoteLifecycle('Active')).code).toBe('OK');
      expect(engine.licenceActor()?.signingAddress === profile.signingAddress).toBe(true);
      await engine.licenceJournalWrite('{"publicTestMarker":true}');
      expect(await engine.licenceJournalRead()).toEqual({ ok: true, recordJson: '{"publicTestMarker":true}' });
      await engine.licenceJournalClear();
      expect(await engine.licenceJournalRead()).toEqual({ ok: true, recordJson: null });
      expect((await engine.inspectStartup()).detail?.surface).not.toBe('verifiedAbsent');
      engine.lock();
      expect(engine.snapshot()).toMatchObject({ hasCandidate: false, hasSession: false });
      expect(engine.licenceActor()).toBeNull();
      expect((await engine.inspectStartup()).detail?.surface).toBe('verifiedAbsent');
      expect((await createEngine(storage).inspectStartup()).detail?.surface).toBe('verifiedAbsent');
      for (const write of writes) expect(write).not.toHaveBeenCalled();
    } finally { engine.wipeSecrets(); for (const write of writes) write.mockRestore(); }
  });
});
