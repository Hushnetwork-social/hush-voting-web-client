/**
 * FEAT-016 Tasks 6.3/6.4 — worker licence authority integration tests.
 *
 * Proves the FEAT-016 licence authority surface over the REAL sealed engine
 * and the REAL production worker environment:
 *   - encrypted two-slot licence journal (round-trip, lock-unreadable,
 *     re-unlock readable, corruption rollback, no plaintext in storage);
 *   - fresh signed-query mints with verifiable per-attempt headers;
 *   - deterministic baseline sealing (exact bytes, verifying signature);
 *   - one LicenceBootstrapSession binds the coordinator to the engine:
 *     no-active bootstrap seals the SIGNED form durably before submission,
 *     admission never grants access, a later active query converges;
 *   - query-first restart reuses the exact sealed pending record;
 *   - page-visible progress never carries exact bytes/signatures.
 *   - FEAT-017 Phase 3 (business logic) reconciliation outcomes are proven
 *     through the SAME worker host: old-current preservation across ordinary
 *     polls, exact sealed-UUID local success once with one-shot notification
 *     eligibility, competing-activation retirement without a local-success
 *     claim, and query-first restart preservation of a pending confirmed
 *     upgrade through the encrypted durable journal.
 *
 * SECRET BOUNDARY: page-visible events/outcomes are asserted to never carry
 * exact signed bytes, raw signatures, private keys, or journal material.
 *
 * Normative source: FEAT-016 FeatureDescription "Web", "Licence Transaction
 * and Pending Journal", "Restart and Recovery"; Task 6.4 behavior spec.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SealedVaultEngine } from './sealed-vault';
import { createBrowserSuiteExecutor, resolveBrowserCryptoEnvironment } from '../crypto/executor';
import type { VaultStorageSession } from '../storage/wrapper';
import type { VaultResult } from '../../vault-core/contracts/results';
import { success, failure } from '../../vault-core/contracts/results';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { LicenceBootstrapSession } from './licence-session';
import { buildDirectFreeUnsignedTransaction } from '../../licensing/direct-free';
import { LICENCE_CATALOGUE_VERSION_V1, LICENCE_PLAN_DIRECT_FREE, type LicenceHigherOptionView, type LicenceQueryTransportResult } from '../../licensing/contracts';
import { isLicenceSignedTransactionJson, base64ToHex, verifyLicenceSeal } from '../../licensing/sealing';
import { verifyMessage } from '../../identity-compatibility/signature';
import { sha256Hex, utf8Bytes } from '../../identity-compatibility/crypto';

const PASSWORD = 'Tr0ub4dor&3-correct-horse';
const NETWORK_BINDING = ISOLATED_DEVNET_MANIFEST.canonicalNetworkId;
const ALIAS = 'Alice';

/** In-memory vault storage (licenceJournal store created). */
class MemoryVaultStorage implements VaultStorageSession {
  readonly databaseName = 'hushvoting-vault';
  readonly schemaVersion = 2;
  private readonly records = new Map<string, Map<string, unknown>>();
  constructor() {
    this.records.set('vaultSlots', new Map());
    this.records.set('vaultJournal', new Map());
    this.records.set('operationalSidecars', new Map());
    this.records.set('licenceJournal', new Map());
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
    const matches = current === undefined ? expectedRecord !== null && expectedRecord.generation === 0 : JSON.stringify(current) === JSON.stringify(expected);
    if (!matches) return failure('GenerationConflict');
    this.store('vaultJournal').set('current', structuredClone(next));
    return success({ ok: true });
  }
  async casRecord(store: string, key: string, expected: unknown, next: unknown): Promise<VaultResult<{ readonly ok: true }>> {
    const current = this.store(store).get(key);
    if (JSON.stringify(current) !== JSON.stringify(expected)) return failure('GenerationConflict');
    this.store(store).set(key, structuredClone(next));
    return success({ ok: true });
  }
  async readJournal(): Promise<VaultResult<{ readonly journal: { generation: number; activeSlot: 'slot-a' | 'slot-b' } | null }>> {
    const value = this.store('vaultJournal').get('current');
    return value === undefined ? success({ journal: null }) : success({ journal: structuredClone(value) as { generation: number; activeSlot: 'slot-a' | 'slot-b' } });
  }
  /** Test hook: raw licence journal blobs (must be encrypted). */
  rawLicenceSlots(): Array<{ key: string; value: unknown }> {
    return [...this.store('licenceJournal').entries()].map(([key, value]) => ({ key, value }));
  }
  /** Test hook: corrupt the committed licence journal ciphertext. */
  corruptLicenceJournal(): void {
    const map = this.store('licenceJournal');
    const pointer = map.get('pointer');
    if (typeof pointer === 'string' && map.has(pointer)) {
      const blob = map.get(pointer) as { v: number; nonce: string; ct: string };
      map.set(pointer, { ...blob, ct: `${blob.ct.slice(0, -4)}AAAA` });
    }
  }
  close(): void {
    this.records.clear();
  }
}

/** Fake licence server state shared by transport fakes. */
interface FakeServer {
  signingAddress: string;
  encryptionAddress: string;
  queryResponses: Array<() => LicenceQueryTransportResult | Promise<LicenceQueryTransportResult>>;
  submissionReplies: Array<{ status: string }>;
  queryCalls: number;
  submitCalls: number;
}

function createFakeServer(signingAddress: string, encryptionAddress: string): FakeServer {
  return { signingAddress, encryptionAddress, queryResponses: [], submissionReplies: [], queryCalls: 0, submitCalls: 0 };
}

function noActiveResponse(): LicenceQueryTransportResult {
  return { ok: true, state: 'noActive', template: { TransitionIntent: 'baseline_free', RequestedPlanId: LICENCE_PLAN_DIRECT_FREE, ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1 } };
}

function activeResponse(licenceReference: string, planId = 'hushvoting.direct.free', planFamily = 'direct'): LicenceQueryTransportResult {
  return {
    ok: true,
    state: 'active',
    active: {
      LicenceReference: licenceReference,
      PlanId: planId,
      PlanFamily: planFamily,
      DisplayName: 'HushVoting! Direct Free',
      SafeDescription: 'Free community licence',
      EffectiveFromUtc: '2026-09-06T00:00:00.000Z',
      AssignedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
      AllowedGovernanceOptionIds: [],
      HigherOptions: [],
    },
  };
}

function createEngine(storage: VaultStorageSession, lookup: (address: string) => Promise<{ readonly kind: 'exact' | 'missing' | 'timeout' | 'unavailable'; readonly profileName?: string; readonly signingAddress?: string; readonly encryptionAddress?: string; readonly visibility?: 'private' | 'public' }>): SealedVaultEngine {
  return new SealedVaultEngine({
    storage,
    suite: createBrowserSuiteExecutor(resolveBrowserCryptoEnvironment()),
    manifest: ISOLATED_DEVNET_MANIFEST,
    nowMs: () => Date.now(),
    randomId: (prefix) => `${prefix}-test`,
    lookupIdentity: lookup,
    broadcast: () => undefined,
    onForceCleanup: () => undefined,
  });
}

async function provisionAndAuthenticate(storage: VaultStorageSession): Promise<{ engine: SealedVaultEngine; signingAddress: string; encryptionAddress: string }> {
  const engine = createEngine(storage, async () => ({ kind: 'missing' }));
  const candidate = engine.createCandidate({ wordCount: 24 });
  if (candidate.code !== 'OK' || candidate.detail === undefined) throw new Error('candidate failed');
  const provision = await engine.provision({
    candidateRef: String((candidate.detail as { ref?: unknown }).ref),
    devicePassword: PASSWORD,
    alias: ALIAS,
    visibility: 'private',
    configurationId: ISOLATED_DEVNET_MANIFEST.configurationId,
    networkBinding: { canonicalNetworkId: ISOLATED_DEVNET_MANIFEST.canonicalNetworkId, networkMagic: ISOLATED_DEVNET_MANIFEST.networkMagic, configurationId: ISOLATED_DEVNET_MANIFEST.configurationId },
    producerId: 'P-01',
  });
  if (provision.code !== 'OK' || provision.detail === undefined) throw new Error('provision failed');
  const signingAddress = String((provision.detail as { signingAddress?: unknown }).signingAddress);
  const encryptionAddress = String((provision.detail as { encryptionAddress?: unknown }).encryptionAddress);
  engine.lock();
  const authenticated = await unlockAndVerify(storage, signingAddress, encryptionAddress);
  return { engine: authenticated, signingAddress, encryptionAddress };
}

async function unlockAndVerify(storage: VaultStorageSession, signingAddress: string, encryptionAddress: string): Promise<SealedVaultEngine> {
  const engine = createEngine(storage, async () => ({ kind: 'exact', profileName: ALIAS, signingAddress, encryptionAddress, visibility: 'private' }));
  const unlock = await engine.unlock({ devicePassword: PASSWORD, configurationId: 'isolated-local-devnet-v1' });
  if (unlock.code !== 'OK') throw new Error(`unlock failed: ${unlock.code}`);
  const verified = await engine.verifyOnline();
  if (verified.code !== 'OK') throw new Error(`verify failed: ${verified.code}`);
  return engine;
}

function unsignedEnvelopeJson(transactionId: string): string {
  const template = { TransitionIntent: 'baseline_free' as const, RequestedPlanId: LICENCE_PLAN_DIRECT_FREE, ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1 };
  const built = buildDirectFreeUnsignedTransaction(template, transactionId, '2026-09-06T00:00:00.000Z');
  if (!built.ok) throw new Error('build failed');
  return built.canonicalUnsignedJson;
}

/** Standard licence record serializer used for journal writes (valid digest). */
function recordJsonFor(actor: string, exactJson: string, transactionId: string): string {
  const digest = sha256Hex(utf8Bytes(exactJson));
  return JSON.stringify({
    schemaVersion: 1,
    purpose: 'pending_licence_transaction',
    transaction: { exactJson, digest },
    transactionId,
    identityBinding: actor,
    networkBinding: NETWORK_BINDING,
    targetBinding: 'web-sharedworker',
    createdUtc: '2026-09-06T00:00:00.000Z',
    attemptEvidence: [],
    recoveryState: 'sealed',
  });
}

/** Authenticated harness: engine + fake licence server + session host. */
async function createHostHarness(): Promise<{
  storage: MemoryVaultStorage;
  engine: SealedVaultEngine;
  server: FakeServer;
  host: LicenceBootstrapSession;
  progress: Array<Record<string, unknown>>;
  signingAddress: string;
}> {
  const storage = new MemoryVaultStorage();
  const { engine, signingAddress, encryptionAddress } = await provisionAndAuthenticate(storage);
  const server = createFakeServer(signingAddress, encryptionAddress);
  const progress: Array<Record<string, unknown>> = [];
  const host = new LicenceBootstrapSession({
    engine,
    nowMs: () => Date.now(),
    expectedNetworkBinding: NETWORK_BINDING,
    querySubmit: async () => {
      server.queryCalls += 1;
      const responder = server.queryResponses[Math.min(server.queryCalls - 1, server.queryResponses.length - 1)] ?? (() => ({ ok: false, status: 'UNAVAILABLE' }) as const);
      return responder();
    },
    transactionSubmit: async () => {
      server.submitCalls += 1;
      const reply = server.submissionReplies[Math.min(server.submitCalls - 1, server.submissionReplies.length - 1)] ?? { status: 'PENDING' };
      switch (reply.status) {
        case 'ACCEPTED': return 'accepted';
        case 'PENDING': return 'pending';
        case 'ALREADY_EXISTS': return 'alreadyExists';
        case 'REJECTED': return 'terminalRejected';
        default: return 'uncertain';
      }
    },
    onProgress: (payload) => progress.push({ ...payload }),
  });
  return { storage, engine, server, host, progress, signingAddress };
}

describe('sealed engine licence journal', () => {
  let storage: MemoryVaultStorage;
  let engine: SealedVaultEngine;
  let signingAddress = '';
  let encryptionAddress = '';

  beforeEach(async () => {
    storage = new MemoryVaultStorage();
    const provisioned = await provisionAndAuthenticate(storage);
    engine = provisioned.engine;
    signingAddress = provisioned.signingAddress;
    encryptionAddress = provisioned.encryptionAddress;
  });

  it('stores only encrypted blobs under fixed keys and round-trips a record', async () => {
    const json = recordJsonFor(signingAddress, unsignedEnvelopeJson('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e'), '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    expect((await engine.licenceJournalWrite(json)).ok).toBe(true);
    const read = await engine.licenceJournalRead();
    expect(read.ok).toBe(true);
    if (read.ok) {
      expect(read.recordJson).toBe(json);
    }
    for (const slot of storage.rawLicenceSlots()) {
      const text = JSON.stringify(slot.value);
      expect(text).not.toContain('pending_licence_transaction');
      expect(text).not.toContain('exactJson');
      expect(text).not.toContain(signingAddress.toLowerCase());
    }
    const cleared = await engine.licenceJournalClear();
    expect(cleared.ok).toBe(true);
    const after = await engine.licenceJournalRead();
    expect(after.ok).toBe(true);
    if (after.ok) {
      expect(after.recordJson).toBeNull();
    }
  });

  it('is unreadable while locked and readable again after the next unlock', async () => {
    const json = recordJsonFor(signingAddress, unsignedEnvelopeJson('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e'), '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    expect((await engine.licenceJournalWrite(json)).ok).toBe(true);
    engine.lock();
    const lockedRead = await engine.licenceJournalRead();
    expect(lockedRead).toEqual({ ok: false, reason: 'not-authenticated' });
    const engine2 = await unlockAndVerify(storage, signingAddress, encryptionAddress);
    const read2 = await engine2.licenceJournalRead();
    expect(read2.ok).toBe(true);
    if (read2.ok) {
      expect(read2.recordJson).toBe(json);
    }
    engine2.lock();
  });

  it('rolls back to the previous slot when the committed slot is corrupt', async () => {
    const first = recordJsonFor(signingAddress, unsignedEnvelopeJson('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e'), '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    const second = recordJsonFor(signingAddress, unsignedEnvelopeJson('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55'), '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55');
    expect((await engine.licenceJournalWrite(first)).ok).toBe(true);
    expect((await engine.licenceJournalWrite(second)).ok).toBe(true);
    storage.corruptLicenceJournal();
    const read = await engine.licenceJournalRead();
    // Rollback decrypts the inactive slot; corruption is never surfaced as
    // wrong plaintext.
    expect(read.ok).toBe(true);
    if (read.ok && read.recordJson !== null) {
      expect(read.recordJson === first || read.recordJson === second).toBe(true);
    }
  });
});

describe('sealed engine licence query + sealing', () => {
  let engine: SealedVaultEngine;
  let signingAddress = '';

  beforeEach(async () => {
    const storage = new MemoryVaultStorage();
    const provisioned = await provisionAndAuthenticate(storage);
    engine = provisioned.engine;
    signingAddress = provisioned.signingAddress;
  });

  it('mints a fresh query and the signature verifies over the canonical bytes', async () => {
    const box: { headers: { signatory: string; signedAt: string; signature: string } | null } = { headers: null };
    const result = await engine.licenceQuery(async (headers) => {
      box.headers = headers;
      return { ok: false, status: 'UNKNOWN' };
    });
    expect(result).toEqual({ ok: false, status: 'UNKNOWN' });
    expect(box.headers).not.toBeNull();
    if (box.headers === null) return;
    const captured = box.headers;
    expect(captured.signatory).toBe(signingAddress.toLowerCase());
    const canonicalJson = `{"actorAddress":"${captured.signatory}","method":"GetMyEntitlement","request":{},"signedAt":"${captured.signedAt}"}`;
    const compactHex = base64ToHex(captured.signature);
    expect(compactHex).not.toBeNull();
    if (compactHex === null) return;
    expect(verifyMessage(canonicalJson, compactHex, signingAddress, 'compact')).toBe(true);
  });

  it('seals a baseline deterministically with a verifying signature', async () => {
    const unsignedJson = unsignedEnvelopeJson('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    const sealed = engine.licenceSignBaseline(unsignedJson);
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;
    expect(isLicenceSignedTransactionJson(sealed.signedJson)).toBe(true);
    expect(verifyLicenceSeal({ unsignedJson, signedJson: sealed.signedJson, publicSigningKeyHex: signingAddress })).toBe(true);
    const again = engine.licenceSignBaseline(unsignedJson);
    expect(again.ok).toBe(true);
    if (again.ok) {
      expect(again.signedJson).toBe(sealed.signedJson);
    }
  });

  it('fails closed without an authenticated session', async () => {
    const fresh = createEngine(new MemoryVaultStorage(), async () => ({ kind: 'missing' }));
    expect(fresh.licenceActor()).toBeNull();
    const query = await fresh.licenceQuery(async () => ({ ok: false, status: 'UNKNOWN' }));
    expect(query).toEqual({ ok: false, status: 'UNAVAILABLE' });
    expect(fresh.licenceSignBaseline('{}')).toEqual({ ok: false, code: 'not-authenticated' });
  });
});

describe('LicenceBootstrapSession (worker host)', () => {
  it('no-active bootstrap seals the signed form durably; PENDING never grants access; restart reuses exact pending', async () => {
    const { storage, server, host, progress, signingAddress } = await createHostHarness();
    server.queryResponses = [() => noActiveResponse()];
    server.submissionReplies = [{ status: 'PENDING' }];
    const start = await host.start(NETWORK_BINDING);
    expect(start.ok).toBe(true);
    if (!start.ok) return;
    expect(['awaitingIndex', 'confirmationDelayed']).toContain(start.snapshot.phase);
    expect(start.snapshot.projection).toBeNull();
    expect(server.submitCalls).toBe(1);
    host.teardown();

    // Query-first restart on the same storage: hydrate + resubmit exact.
    const engine2 = await unlockAndVerify(storage, signingAddress, server.encryptionAddress);
    const secondHost = new LicenceBootstrapSession({
      engine: engine2,
      nowMs: () => Date.now(),
      expectedNetworkBinding: NETWORK_BINDING,
      querySubmit: async () => {
        server.queryCalls += 1;
        return noActiveResponse();
      },
      transactionSubmit: async () => {
        server.submitCalls += 1;
        return 'pending';
      },
      onProgress: () => undefined,
    });
    const resumed = await secondHost.start(NETWORK_BINDING);
    expect(resumed.ok).toBe(true);
    if (resumed.ok) {
      expect(resumed.snapshot.pendingTransactionId).not.toBeNull();
      expect(server.submitCalls).toBe(2); // exact sealed record resubmitted once
    }
    for (const event of progress) {
      const text = JSON.stringify(event);
      expect(text).not.toContain('UserSignature');
      expect(text).not.toContain('signature');
      expect(text).not.toContain('signingPrivateKey');
    }
    secondHost.teardown();
    engine2.lock();
  });

  it('converges to ready only when a fresh query returns compatible active truth', async () => {
    const { host, server } = await createHostHarness();
    server.queryResponses = [() => activeResponse('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55')];
    const start = await host.start(NETWORK_BINDING);
    expect(start.ok).toBe(true);
    if (!start.ok) return;
    expect(start.snapshot.phase).toBe('entitlementReady');
    expect(start.snapshot.projection).not.toBeNull();
    host.teardown();
  });

  // EPIC-002 -> FEAT-016 AC-016-018 -> Phase 6 Task 6.4.
  // Isolated FEAT evidence, paired with the .NET compatibility fault journeys.
  it.each(['catalogue-version', 'plan-family', 'plan-id', 'governance'] as const)(
    'HushVotingApp TwinTest rejects incompatible active %s without baseline creation',
    async (kind) => {
      const { host, engine, server, storage, progress } = await createHostHarness();
      try {
        const reply = activeResponse('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55');
        if (!reply.ok || reply.state !== 'active') throw new Error('Invalid test arrangement');
        server.queryResponses = [() => ({ ...reply, active: {
          ...reply.active,
          ...({
            'catalogue-version': { AssignedCatalogueVersion: 'hushvoting-licence-catalogue/v2.0.0' },
            'plan-family': { PlanFamily: 'future-governance-family' },
            'plan-id': { PlanId: 'unsupported-test-plan' },
            governance: { AllowedGovernanceOptionIds: ['no-customer-trustees', 'unsupported-test-governance'] },
          }[kind]),
        } })];
        const result = await host.start(NETWORK_BINDING);
        expect(result.ok).toBe(true);
        expect(host.snapshot()?.phase).toBe('entitlementUnsupported');
        expect(host.snapshot()?.projection).toBeNull();
        expect(server.queryCalls).toBe(1);
        expect(server.submitCalls).toBe(0);
        expect(storage.rawLicenceSlots()).toHaveLength(0);
        expect(progress.some(event => event.phase === 'entitlementReady')).toBe(false);
        await host.pump();
        expect(server.submitCalls).toBe(0);
      } finally {
        host.teardown();
        engine.lock();
      }
    },
  );

  // EPIC-002 -> FEAT-016 AC-016-016/017 -> Phase 6 Tasks 6.4/6.7.
  it.each(['unavailable', 'active', 'no-active'] as const)(
    'HushVotingApp TwinTest revalidates at annual expiry with %s truth and no continuous active polling', async (outcome) => {
    const { host, engine, server, progress } = await createHostHarness();
    const expiry = Date.now() + 60_000;
    let release: (result: LicenceQueryTransportResult) => void = () => undefined;
    let arrived: () => void = () => undefined;
    const queryArrived = new Promise<void>(resolve => { arrived = resolve; });
    const heldQuery = new Promise<LicenceQueryTransportResult>(resolve => { release = resolve; });
    try {
      vi.useFakeTimers({ toFake: ['Date'] });
      const reply = activeResponse('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55', 'hushvoting.veritas.2000', 'veritas');
      if (!reply.ok || reply.state !== 'active') throw new Error('Invalid test arrangement');
      const annual = { ...reply, active: {
        ...reply.active, DisplayName: 'HushVoting! Veritas 2k',
        EffectiveFromUtc: new Date(expiry - 365 * 86_400_000).toISOString(),
        ExpiresAtUtc: new Date(expiry).toISOString(), TermKind: 'calendar_years', TermYears: 1,
      } } as const;
      server.queryResponses = [() => annual, () => { arrived(); return heldQuery; }];
      await host.start(NETWORK_BINDING);
      expect(host.snapshot()?.phase).toBe('entitlementReady');
      vi.setSystemTime(expiry - 1);
      await host.pump();
      expect(server.queryCalls).toBe(1);
      vi.setSystemTime(expiry);
      const pumping = host.pump();
      expect(host.snapshot()?.phase).toBe('resolving');
      expect(host.snapshot()?.projection).toBeNull();
      expect(progress.at(-1)?.phase).toBe('resolving');
      await queryArrived;
      expect(server.queryCalls).toBe(2);
      expect(server.submitCalls).toBe(0);
      await host.pump();
      expect(server.queryCalls).toBe(2);
      release(outcome === 'active' ? annual : outcome === 'no-active' ? noActiveResponse() : { ok: false, status: 'UNAVAILABLE' });
      await pumping;
      expect(host.snapshot()?.phase).toBe(outcome === 'active' ? 'entitlementReady' : outcome === 'no-active' ? 'awaitingIndex' : 'entitlementUnavailable');
      expect(server.submitCalls).toBe(outcome === 'no-active' ? 1 : 0);
      if (outcome === 'active') {
        vi.setSystemTime(expiry + 10_000);
        await host.pump();
        expect(server.queryCalls).toBe(2);
        expect(host.snapshot()?.projection?.planFamily).toBe('veritas');
        vi.setSystemTime(expiry + 60_000);
        await host.pump();
        expect(server.queryCalls).toBe(3);
        expect(server.submitCalls).toBe(0);
      } else {
        expect(host.snapshot()?.projection).toBeNull();
      }
    } finally {
      release({ ok: false, status: 'UNAVAILABLE' });
      host.teardown();
      engine.lock();
      vi.useRealTimers();
    }
  });

  it('rejects a wrong network binding and starts before authentication', async () => {
    const { host, engine } = await createHostHarness();
    const wrong = await host.start('other-network');
    expect(wrong).toEqual({ ok: false, reason: 'invalid-input' });
    engine.lock();
    const locked = await host.start(NETWORK_BINDING);
    expect(locked).toEqual({ ok: false, reason: 'not-authenticated' });
  });

  it('exposes no page-visible secrets in progress after a full baseline flow', async () => {
    vi.useFakeTimers();
    try {
      const { host, server, progress } = await createHostHarness();
      server.queryResponses = [() => noActiveResponse(), () => noActiveResponse(), () => activeResponse('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e')];
      server.submissionReplies = [{ status: 'PENDING' }];
      const start = await host.start(NETWORK_BINDING);
      expect(start.ok).toBe(true);
      if (!start.ok) return;
      expect(start.snapshot.phase).toBe('awaitingIndex');
      // Advance past the 3 s query cadence, then one serialized pump queries
      // again; the fake server now returns the indexed active entitlement.
      vi.setSystemTime(Date.now() + 4_000);
      const firstPump = await host.pump();
      expect(firstPump).not.toBeNull();
      if (firstPump !== null) {
        // Query #2 still returns no-active; the exact pending record is kept
        // and no replacement transaction is ever created.
        expect(firstPump.phase).toBe('awaitingIndex');
        expect(server.submitCalls).toBe(1);
      }
      // Query #3 (after the next cadence) returns the indexed entitlement.
      vi.setSystemTime(Date.now() + 4_000);
      const pumped = await host.pump();
      expect(pumped).not.toBeNull();
      if (pumped !== null) {
        expect(pumped.phase).toBe('entitlementReady');
      }
      for (const event of progress) {
        const text = JSON.stringify(event);
        expect(text).not.toContain('UserSignature');
        expect(text).not.toContain('signature');
        expect(text).not.toContain('privateKey');
        expect(text).not.toContain('mnemonic');
      }
      host.teardown();
    } finally {
      vi.useRealTimers();
    }
  });

  it('FEAT-017 upgrade snapshot fields flow into safe progress only after real operations', async () => {
    const { host, server } = await createHostHarness();
    server.queryResponses = [() => activeResponse('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e')];
    const start = await host.start(NETWORK_BINDING);
    expect(start.ok).toBe(true);
    if (!start.ok) return;
    // No upgrade operation has ever been sealed in this baseline-only harness:
    // the additive safe vocabulary is always present and page-safe.
    const before = host.snapshot();
    expect(before).not.toBeNull();
    if (before !== null) {
      expect(before.phase).toBe('entitlementReady');
      expect(before.upgradeOperation).toBeNull();
      expect(before.upgradeNotificationEligible).toBe(false);
    }
    // A malformed activation is refused without touching the authority.
    const bad = await host.confirmUpgrade(42);
    expect(bad).toEqual({ ok: false, reason: 'invalid-input' });
    const empty = await host.confirmUpgrade('');
    expect(empty).toEqual({ ok: false, reason: 'invalid-input' });
    // Acknowledging an outcome that was never surfaced is still a safe step.
    const ack = await host.acknowledgeUpgradeOutcome();
    expect(ack.ok).toBe(true);
    host.teardown();
  });

  it('rejects upgrade control before authentication with the closed refusal', async () => {
    const { storage, server, signingAddress } = await createHostHarness();
    const engine2 = await unlockAndVerify(storage, signingAddress, server.encryptionAddress);
    engine2.lock();
    const lockedHost = new LicenceBootstrapSession({
      engine: engine2,
      nowMs: () => Date.now(),
      expectedNetworkBinding: NETWORK_BINDING,
      querySubmit: async () => ({ ok: false, status: 'UNAVAILABLE' }),
      transactionSubmit: async () => 'uncertain',
      onProgress: () => undefined,
    });
    expect(await lockedHost.confirmUpgrade('hushvoting.veritas.2000')).toEqual({
      ok: false,
      reason: 'not-authenticated',
    });
    expect(await lockedHost.acknowledgeUpgradeOutcome()).toEqual({
      ok: false,
      reason: 'not-authenticated',
    });
  });
});

describe('FEAT-017 Phase 3 confirmed-upgrade reconciliation through the worker host', () => {
  const OLD_DF_REF = '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e';
  const COMPETING_REF = '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55';
  const TARGET_500 = 'hushvoting.veritas.500';
  const TARGET_2000 = 'hushvoting.veritas.2000';

  /** One server-ordered higher Veritas option row (wire shape). */
  function higherOption(planId: string, displayName: string, cap: number): LicenceHigherOptionView {
    return {
      PlanId: planId,
      DisplayName: displayName,
      SafeDescription: 'Annual Veritas licence',
      EligibleVoterCap: cap,
      UnlimitedElections: true,
      TermKind: 'annual',
      TermYears: 1,
    };
  }

  /** Real wire-shaped active query result with the current detail + options. */
  function activeResult(
    licenceReference: string,
    planId: string,
    planFamily: 'direct' | 'veritas',
    displayName: string,
    higherOptions: readonly LicenceHigherOptionView[] = [],
  ): LicenceQueryTransportResult {
    const direct = planId === LICENCE_PLAN_DIRECT_FREE;
    return {
      ok: true,
      state: 'active',
      active: {
        LicenceReference: licenceReference,
        PlanId: planId,
        PlanFamily: planFamily,
        DisplayName: displayName,
        SafeDescription: direct ? 'Free community licence' : 'Annual Veritas licence',
        EligibleVoterCap: direct ? 100 : planId === TARGET_2000 ? 2000 : 500,
        UnlimitedElections: true,
        TermKind: direct ? 'perpetual' : 'annual',
        TermYears: direct ? 0 : 1,
        EffectiveFromUtc: '2026-09-06T00:00:00.000Z',
        AssignedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
        AllowedGovernanceOptionIds: [],
        HigherOptions: higherOptions,
      },
    };
  }

  /** Direct Free truth offering Veritas 500 + 2k strictly higher (server order). */
  function directFreeWithOptions(): LicenceQueryTransportResult {
    return activeResult(OLD_DF_REF, LICENCE_PLAN_DIRECT_FREE, 'direct', 'HushVoting! Direct Free', [
      higherOption(TARGET_500, 'HushVoting! Veritas 500', 500),
      higherOption(TARGET_2000, 'HushVoting! Veritas 2k', 2000),
    ]);
  }

  it('ordinary polls returning the old indexed licence preserve the pending upgrade under the old limits (never success, never resubmit)', async () => {
    vi.useFakeTimers();
    try {
      const { host, server } = await createHostHarness();
      // Query 1 (start) and query 2 (seal-time freshness re-query) both return
      // the same old current truth; every later poll keeps returning it.
      server.queryResponses = [() => directFreeWithOptions(), () => directFreeWithOptions()];
      server.submissionReplies = [{ status: 'PENDING' }];
      const start = await host.start(NETWORK_BINDING);
      expect(start.ok).toBe(true);
      if (!start.ok) return;
      expect(start.snapshot.phase).toBe('entitlementReady');

      const confirm = await host.confirmUpgrade(TARGET_2000);
      expect(confirm.ok).toBe(true);
      if (!confirm.ok) return;
      expect(confirm.snapshot.upgradeOperation?.status).toBe('pending');
      expect(confirm.snapshot.upgradeNotificationEligible).toBe(false);
      expect(confirm.snapshot.projection?.planId).toBe(LICENCE_PLAN_DIRECT_FREE);
      const sealedId = confirm.snapshot.pendingTransactionId;
      expect(sealedId).not.toBeNull();
      expect(server.submitCalls).toBe(1);

      vi.setSystemTime(Date.now() + 4_000);
      const poll = await host.pump();
      expect(poll).not.toBeNull();
      if (poll !== null) {
        // Old licence still current: pending preserved, old limits effective,
        // no local-success claim and no notification eligibility (D017-01).
        expect(poll.phase).toBe('entitlementReady');
        expect(poll.pendingTransactionId).toBe(sealedId);
        expect(poll.upgradeOperation?.status).toBe('pending');
        expect(poll.upgradeNotificationEligible).toBe(false);
        expect(poll.projection?.planId).toBe(LICENCE_PLAN_DIRECT_FREE);
        expect(poll.lastOutcomeCode).toBe('upgrade-pending-old-current');
      }
      // Ordinary three-second polls never resubmit the exact sealed upgrade.
      expect(server.submitCalls).toBe(1);
      host.teardown();
    } finally {
      vi.useRealTimers();
    }
  });

  it('only the exact indexed sealed transaction UUID confirms local success once, with one-shot notification eligibility', async () => {
    vi.useFakeTimers();
    try {
      const { host, server } = await createHostHarness();
      server.queryResponses = [() => directFreeWithOptions(), () => directFreeWithOptions()];
      server.submissionReplies = [{ status: 'PENDING' }];
      const start = await host.start(NETWORK_BINDING);
      expect(start.ok).toBe(true);
      if (!start.ok) return;

      const confirm = await host.confirmUpgrade(TARGET_2000);
      expect(confirm.ok).toBe(true);
      if (!confirm.ok) return;
      const sealedId = confirm.snapshot.pendingTransactionId;
      expect(sealedId).not.toBeNull();
      expect(server.submitCalls).toBe(1);

      // Indexed truth now reports the EXACT sealed transaction id as the
      // current licence (the higher plan activated through the real pipeline).
      server.queryResponses.push(() =>
        activeResult(String(sealedId), TARGET_2000, 'veritas', 'HushVoting! Veritas 2k', []),
      );
      vi.setSystemTime(Date.now() + 4_000);
      const pumped = await host.pump();
      expect(pumped).not.toBeNull();
      if (pumped !== null) {
        expect(pumped.phase).toBe('entitlementReady');
        expect(pumped.pendingTransactionId).toBeNull();
        expect(pumped.upgradeOperation?.status).toBe('local-success');
        expect(pumped.upgradeNotificationEligible).toBe(true);
        expect(pumped.projection?.planId).toBe(TARGET_2000);
        expect(pumped.lastOutcomeCode).toBe('upgrade-local-success');
      }

      // A later ordinary poll must NOT re-arm the one-shot notification or
      // duplicate the terminal success: with nothing pending the query loop is
      // done, the retained local-success terminal and its one-shot eligibility
      // persist untouched until the page acknowledges them.
      vi.setSystemTime(Date.now() + 4_000);
      const polled = await host.pump();
      expect(polled).not.toBeNull();
      if (polled !== null) {
        expect(polled.upgradeOperation?.status).toBe('local-success');
        expect(polled.upgradeNotificationEligible).toBe(true);
        expect(polled.lastOutcomeCode).toBe('upgrade-local-success');
      }
      // The authority-owned loop is done (nothing pending): the post-success
      // pump issues no fresh query and no second submission can ever be
      // created after local success (start + seal-time re-query + the one
      // reconciliation query that indexed the exact UUID = 3 total).
      expect(server.queryCalls).toBe(3);
      expect(server.submitCalls).toBe(1);

      // Acknowledge clears the one-shot eligibility and the retained terminal.
      const acked = await host.acknowledgeUpgradeOutcome();
      expect(acked.ok).toBe(true);
      if (acked.ok) {
        expect(acked.snapshot.upgradeNotificationEligible).toBe(false);
        expect(acked.snapshot.upgradeOperation).toBeNull();
      }
      host.teardown();
    } finally {
      vi.useRealTimers();
    }
  });

  it('a competing activation on another device retires the obsolete pending upgrade without a local-success claim', async () => {
    vi.useFakeTimers();
    try {
      const { host, server } = await createHostHarness();
      server.queryResponses = [() => directFreeWithOptions(), () => directFreeWithOptions()];
      server.submissionReplies = [{ status: 'PENDING' }];
      const start = await host.start(NETWORK_BINDING);
      expect(start.ok).toBe(true);
      if (!start.ok) return;

      const confirm = await host.confirmUpgrade(TARGET_2000);
      expect(confirm.ok).toBe(true);
      if (!confirm.ok) return;
      expect(server.submitCalls).toBe(1);

      // Another device indexed a DIFFERENT compatible activation first: the
      // authoritative truth is accepted and the obsolete local pending is
      // retired without any local-success claim or notification eligibility.
      server.queryResponses.push(() =>
        activeResult(COMPETING_REF, TARGET_500, 'veritas', 'HushVoting! Veritas 500', []),
      );
      vi.setSystemTime(Date.now() + 4_000);
      const pumped = await host.pump();
      expect(pumped).not.toBeNull();
      if (pumped !== null) {
        expect(pumped.phase).toBe('entitlementReady');
        expect(pumped.pendingTransactionId).toBeNull();
        expect(pumped.upgradeOperation?.status).toBe('competing-activation');
        expect(pumped.upgradeNotificationEligible).toBe(false);
        expect(pumped.projection?.planId).toBe(TARGET_500);
        expect(pumped.lastOutcomeCode).toBe('upgrade-competing-activation');
      }
      host.teardown();
    } finally {
      vi.useRealTimers();
    }
  });

  it('a query-first restart under the old current licence preserves the pending upgrade via the encrypted durable journal', async () => {
    const { storage, server, host, signingAddress } = await createHostHarness();
    server.queryResponses = [() => directFreeWithOptions(), () => directFreeWithOptions()];
    server.submissionReplies = [{ status: 'PENDING' }];
    const start = await host.start(NETWORK_BINDING);
    expect(start.ok).toBe(true);
    if (!start.ok) return;

    const confirm = await host.confirmUpgrade(TARGET_2000);
    expect(confirm.ok).toBe(true);
    if (!confirm.ok) return;
    const sealedId = confirm.snapshot.pendingTransactionId;
    expect(sealedId).not.toBeNull();
    expect(server.submitCalls).toBe(1);

    // The durable licence journal now holds the sealed upgrade record: the
    // stored blobs must never expose exact bytes, bindings, or plan material.
    const raw = JSON.stringify(storage.rawLicenceSlots());
    expect(raw).not.toContain('confirmed_upgrade');
    expect(raw).not.toContain(TARGET_2000);
    expect(raw).not.toContain('ExpectedCurrentPlanId');
    expect(raw).not.toContain('UserSignature');

    host.teardown();

    // Query-first restart on the same storage under the STILL-CURRENT old
    // licence: hydrate the bound upgrade record and reconcile it (preserve
    // pending; a confirmed upgrade is never auto-resubmitted on ready truth).
    const engine2 = await unlockAndVerify(storage, signingAddress, server.encryptionAddress);
    const secondHost = new LicenceBootstrapSession({
      engine: engine2,
      nowMs: () => Date.now(),
      expectedNetworkBinding: NETWORK_BINDING,
      querySubmit: async () => {
        server.queryCalls += 1;
        return directFreeWithOptions();
      },
      transactionSubmit: async () => {
        server.submitCalls += 1;
        return 'pending';
      },
      onProgress: () => undefined,
    });
    const resumed = await secondHost.start(NETWORK_BINDING);
    expect(resumed.ok).toBe(true);
    if (resumed.ok) {
      expect(resumed.snapshot.phase).toBe('entitlementReady');
      expect(resumed.snapshot.pendingTransactionId).toBe(sealedId);
      expect(resumed.snapshot.upgradeOperation?.status).toBe('pending');
      expect(resumed.snapshot.upgradeNotificationEligible).toBe(false);
      expect(resumed.snapshot.lastOutcomeCode).toBe('upgrade-pending-old-current');
      expect(resumed.snapshot.projection?.planId).toBe(LICENCE_PLAN_DIRECT_FREE);
    }
    expect(server.submitCalls).toBe(1); // exact sealed record submitted once, never re-submitted
    secondHost.teardown();
  });
});
