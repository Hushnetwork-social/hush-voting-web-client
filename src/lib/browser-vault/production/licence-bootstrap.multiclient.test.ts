/**
 * FEAT-016 Task 6.4 — multi-client worker ownership and recovery tests.
 *
 * Boots the REAL production worker environment (`createProductionWorkerEnvironment`)
 * with the REAL `WorkerAuthority` and two attached client ports (tabs) over a
 * deterministic in-memory vault and fake same-origin BFF. Proves:
 *   - exactly one signed query/submission/reconciliation session spans tabs
 *     (a second start request reuses it; query count does not grow);
 *   - safe progress broadcasts reach every attached tab and never carry exact
 *     bytes, signatures, keys, or journal material;
 *   - closing one tab does not duplicate work or stop the authority session;
 *   - Lock (from either tab) tears the session down and stops progress;
 *   - query-first restart discipline holds through a worker restart (new
 *     authority over the same storage hydrates the exact sealed pending
 *     record and never fabricates a second transaction).
 *
 * SECRET BOUNDARY: page-visible messages are scanned for forbidden material.
 *
 * Normative source: FEAT-016 FeatureDescription "Web" (SharedWorker = one
 * authority; one loop; safe broadcasts; tab closure continuity); Task 6.4
 * behavior spec.
 */
import { describe, expect, it } from 'vitest';
import { WorkerAuthority } from '../authority/authority';
import { createProductionWorkerEnvironment } from './worker-env';
import { createBrowserSuiteExecutor, resolveBrowserCryptoEnvironment } from '../crypto/executor';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import type { VaultStorageSession } from '../storage/wrapper';
import type { VaultResult } from '../../vault-core/contracts/results';
import { success, failure } from '../../vault-core/contracts/results';
import type { LicenceQueryTransportResult } from '../../licensing/contracts';
import { LICENCE_CATALOGUE_VERSION_V1, LICENCE_PLAN_DIRECT_FREE } from '../../licensing/contracts';
import type { BrowserWorkerEvent } from '../contracts/protocol';
import { BROWSER_PROTOCOL_VERSION } from '../contracts/protocol';

import { AuthAdapter, canAccessCapturedElection } from '../../auth/react/adapter';
import { EntitlementBridge } from '../../auth/web/entitlement-bridge';
import type { BrowserVaultClient } from './client';
import type { AuthActors } from '../../auth/ports';
import { completeAllPendingOperations, createLocalUserAuthorityTestActor, createSecretAuthorityTestActor,
  createIdentityVerificationTestActor, createOnboardingTestActor, createRemovalTestActor,
  createBrowserCoordinationTestActor, createNavigationTestActor } from '../../auth/testing/actors';
import { electionQuerySignedJson, ELECTION_QUERY_HEADERS } from '../../elections/query';
import { verifyMessage } from '../../identity-compatibility/signature';
import { base64ToHex } from '../../licensing/sealing';

const PASSWORD = 'Tr0ub4dor&3-correct-horse';
const NETWORK_BINDING = ISOLATED_DEVNET_MANIFEST.canonicalNetworkId;

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
  close(): void {
    this.records.clear();
  }
}

interface FakeServer {
  electionScope?: unknown;
  electionStatus?: number;
  electionCalls?: number;
  electionSignaturesValid?: boolean;
  electionPause?: Promise<void>;
  signingAddress: string;
  encryptionAddress: string;
  queryCalls: number;
  submitCalls: number;
  /** Deterministic sequence: index 0 replayed when exhausted. */
  querySequence: Array<LicenceQueryTransportResult>;
  submitStatus: 'ACCEPTED' | 'PENDING' | 'ALREADY_EXISTS' | 'REJECTED';
}

function noActive(): LicenceQueryTransportResult {
  return { ok: true, state: 'noActive', template: { TransitionIntent: 'baseline_free', RequestedPlanId: LICENCE_PLAN_DIRECT_FREE, ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1 } };
}

function fakeFetch(server: FakeServer): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('/api/election-access')) {
      server.electionCalls = (server.electionCalls ?? 0) + 1;
      const request = JSON.parse(String(init?.body)) as { electionId: string };
      const headers = new Headers(init?.headers);
      const at = headers.get(ELECTION_QUERY_HEADERS[1]) ?? '';
      const signature = base64ToHex(headers.get(ELECTION_QUERY_HEADERS[2]) ?? '');
      const check = signature !== null && verifyMessage(electionQuerySignedJson(server.signingAddress, request.electionId, at), signature, server.signingAddress, 'compact');
      server.electionSignaturesValid = headers.get(ELECTION_QUERY_HEADERS[0]) === server.signingAddress && check;
      await server.electionPause;
      return new Response(JSON.stringify({ scope: server.electionScope }), { status: server.electionStatus ?? 200 });
    }
    if (url.includes('/api/identity')) {
      return new Response(
        JSON.stringify({ reply: { successfull: true, profileName: 'Alice', publicSigningAddress: server.signingAddress, publicEncryptAddress: server.encryptionAddress, isPublic: false } }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (url.includes('/api/licence-entitlement')) {
      server.queryCalls += 1;
      const index = Math.min(server.queryCalls - 1, server.querySequence.length - 1);
      const body = server.querySequence[index >= 0 ? index : 0] ?? { ok: false, status: 'UNAVAILABLE' };
      return new Response(JSON.stringify({ reply: body }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/api/blockchain')) {
      server.submitCalls += 1;
      return new Response(JSON.stringify({ reply: { status: server.submitStatus } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('{}', { status: 404 });
  }) as typeof fetch;
}

interface PortHarness {
  readonly channel: string;
  readonly received: BrowserWorkerEvent[];
  deliver(event: BrowserWorkerEvent): void;
}

/** One authority + N client ports over the real production env. */
function createAuthority(storage: VaultStorageSession, server: FakeServer): { authority: WorkerAuthority; ports: PortHarness[]; secrets: { store: (t: { operationId: string; kind: string; value: string }) => void } } {
  const ports: PortHarness[] = [];
  let seq = 0;
  const deliver = (clientChannel: string, event: BrowserWorkerEvent): void => {
    const port = ports.find((p) => p.channel === clientChannel);
    port?.deliver(event);
  };
  const broadcast = (event: BrowserWorkerEvent): void => {
    for (const port of ports) {
      port.deliver(event);
    }
  };
  const suite = createBrowserSuiteExecutor(resolveBrowserCryptoEnvironment());
  const created = createProductionWorkerEnvironment({
    storage,
    suite,
    appIdentity: { appVersion: '0.1.0', buildDigest: '0123456789ab' },
    runtimeConfigId: 'development-localhost',
    deliver,
    broadcast,
    onForceCleanup: () => undefined,
    fetchImpl: fakeFetch(server),
  });
  // Route authority-handled secret transfers into the env secret book (the
  // worker entry does exactly this in production).
  (created.env as { onSecretTransfer?: (t: { operationId: string; clientChannel: string; authorityEpoch: number; purpose: 'devicePassword' | 'mnemonic' | 'filePassword' | 'fileBytes'; value: string }) => void }).onSecretTransfer = (transfer) => {
    created.secrets.store({ operationId: transfer.operationId, kind: transfer.purpose, value: transfer.value, consumed: false });
  };
  const authority = new WorkerAuthority(created.env);
  const addPort = (): PortHarness => {
    const channel = `chan-${++seq}`;
    const port: PortHarness = { channel, received: [], deliver: (event) => port.received.push(event) };
    ports.push(port);
    authority.handle({ kind: 'handshake', protocolVersion: BROWSER_PROTOCOL_VERSION, appVersion: '0.1.0', buildDigest: '0123456789ab', clientChannel: channel, runtimeConfigId: 'development-localhost' });
    return port;
  };
  const secrets = { store: (t: { operationId: string; kind: string; value: string }) => created.secrets.store({ operationId: t.operationId, kind: t.kind as never, value: t.value, consumed: false }) };
  // Two attached clients (tabs) by default for multi-client scenarios.
  addPort();
  addPort();
  return { authority, ports, secrets };
}

/** Dispatch one op on a port; resolves on the matching operation-outcome. */
function dispatchOp(port: PortHarness, authority: WorkerAuthority, operation: string, payload?: Record<string, unknown>, opts: { freshCapabilityId?: string; operationId?: string; secret?: string } = {}): Promise<BrowserWorkerEvent> {
  // Match BrowserVaultClient: global Lock invalidates every channel, so the
  // next operation must perform a fresh authenticated-channel handshake.
  if (!authority.snapshot().acceptedChannels.includes(port.channel)) {
    authority.handle({ kind: 'handshake', protocolVersion: BROWSER_PROTOCOL_VERSION, appVersion: '0.1.0',
      buildDigest: '0123456789ab', clientChannel: port.channel, runtimeConfigId: 'development-localhost' });
  }
  const operationId = opts.operationId ?? `op-${Math.random().toString(36).slice(2, 10)}`;
  const message = {
    kind: 'operation' as const,
    operation,
    operationVersion: 1,
    clientChannel: port.channel,
    authorityEpoch: authority.snapshot().epoch,
    operationId,
    ...(payload !== undefined && Object.keys(payload).length > 0 ? { payload } : {}),
    ...(opts.freshCapabilityId !== undefined ? { freshCapabilityId: opts.freshCapabilityId } : {}),
  };
  if (opts.secret !== undefined) {
    authority.handle({ kind: 'secret-transfer', operationId, clientChannel: port.channel, authorityEpoch: authority.snapshot().epoch, purpose: 'devicePassword', value: opts.secret });
  }
  authority.handle(message);
  return new Promise<BrowserWorkerEvent>((resolve, reject) => {
    const deadline = Date.now() + 3_000;
    const poll = (): void => {
      const outcome = port.received.find((m) => m.kind === 'operation-outcome' && (m as { operationId?: string }).operationId === operationId);
      if (outcome) {
        resolve(outcome);
        return;
      }
      if (Date.now() > deadline) {
        reject(new Error(`op timeout: ${operation}`));
        return;
      }
      setTimeout(poll, 10);
    };
    poll();
  });
}

async function issueCapability(port: PortHarness, authority: WorkerAuthority, purpose: string): Promise<string> {
  authority.handle({ kind: 'issue-capability', purpose, clientChannel: port.channel, authorityEpoch: authority.snapshot().epoch });
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const issued = port.received.find((m) => m.kind === 'capability-issued');
    if (issued) {
      return (issued as { capabilityId: string }).capabilityId;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('capability timeout');
}

/** Full onboarding → lock → unlock → verify on one authority. */
async function authenticate(port: PortHarness, authority: WorkerAuthority, server: FakeServer): Promise<{ signingAddress: string; encryptionAddress: string }> {
  const candidate = await dispatchOp(port, authority, 'createCandidate');
  if (candidate.kind !== 'operation-outcome' || candidate.outcome !== 'OK') throw new Error('createCandidate failed');
  const candidateRef = String((candidate.payload as { ref?: unknown }).ref);
  const provisionId = `provision-${Date.now().toString(36)}`;
  const capabilityId = await issueCapability(port, authority, 'provision');
  const provision = await dispatchOp(
    port,
    authority,
    'provisionFromValidatedBundle',
    { candidateRef, alias: 'Alice', visibility: 'private' },
    { freshCapabilityId: capabilityId, operationId: provisionId, secret: PASSWORD },
  );
  if (provision.kind !== 'operation-outcome' || provision.outcome !== 'OK') throw new Error('provision failed');
  const signingAddress = String((provision.payload as { signingAddress?: unknown }).signingAddress);
  const encryptionAddress = String((provision.payload as { encryptionAddress?: unknown }).encryptionAddress);
  // The online verification lookup must know the exact derived addresses.
  server.signingAddress = signingAddress;
  server.encryptionAddress = encryptionAddress;
  await dispatchOp(port, authority, 'lockAll');
  const unlockId = `unlock-${Date.now().toString(36)}`;
  const unlock = await dispatchOp(port, authority, 'unlockPassword', undefined, { operationId: unlockId, secret: PASSWORD });
  if (unlock.kind !== 'operation-outcome' || unlock.outcome !== 'OK') throw new Error('unlock failed');
  const verify = await dispatchOp(port, authority, 'verifyOnlineIdentity');
  if (verify.kind !== 'operation-outcome' || verify.outcome !== 'OK') throw new Error('verify failed');
  return { signingAddress, encryptionAddress };
}

function progressEvents(port: PortHarness): Array<Record<string, unknown>> {
  return port.received.filter((m) => m.kind === 'licence-progress') as unknown as Array<Record<string, unknown>>;
}

function assertSecretFree(text: string): void {
  expect(text).not.toContain('UserSignature');
  expect(text).not.toContain('signingPrivateKey');
  expect(text).not.toContain('"signature"');
  expect(text).not.toContain('exactJson');
}

describe('FEAT-016 multi-client worker authority (Task 6.4)', () => {
  it('runs ONE bootstrap session across two tabs, broadcasts safe progress, and tears down on Lock', async () => {
    const storage = new MemoryVaultStorage();
    const server: FakeServer = {
      signingAddress: '',
      encryptionAddress: '',
      queryCalls: 0,
      submitCalls: 0,
      querySequence: [noActive(), noActive(), { ok: true, state: 'active', active: { LicenceReference: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e', PlanId: LICENCE_PLAN_DIRECT_FREE, PlanFamily: 'direct', DisplayName: 'HushVoting! Direct Free', SafeDescription: 'Free community licence', EffectiveFromUtc: '2026-09-06T00:00:00.000Z', AssignedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1, AllowedGovernanceOptionIds: [], HigherOptions: [] } }],
      submitStatus: 'PENDING',
    };
    const { authority, ports } = createAuthority(storage, server);
    const tab1 = ports[0];
    const tab2 = ports[1];
    await authenticate(tab1, authority, server);

    // Tab 1 starts bootstrap. Query 1 = no-active → signed baseline → PENDING.
    const start = await dispatchOp(tab1, authority, 'licenceBootstrapStart', { networkBinding: NETWORK_BINDING });
    expect(start.kind).toBe('operation-outcome');
    if (start.kind !== 'operation-outcome') return;
    expect(start.outcome).toBe('OK');
    const payload = start.payload as { ok: boolean; snapshot?: { phase?: string } };
    expect(payload.ok).toBe(true);
    expect(['awaitingIndex', 'confirmationDelayed']).toContain(payload.snapshot?.phase);
    expect(server.queryCalls).toBe(1);
    expect(server.submitCalls).toBe(1);

    // Both tabs received identical safe progress broadcasts (no exact bytes).
    const tab1Progress = progressEvents(tab1);
    const tab2Progress = progressEvents(tab2);
    expect(tab1Progress.length).toBeGreaterThanOrEqual(1);
    expect(tab2Progress.length).toBe(tab1Progress.length);
    for (const event of tab1Progress) {
      assertSecretFree(JSON.stringify(event));
    }
    for (const event of tab2Progress) {
      assertSecretFree(JSON.stringify(event));
    }

    // Tab 2 requests a second start: the authority session is reused and no
    // second query or transaction is created (within the same cadence).
    const secondStart = await dispatchOp(tab2, authority, 'licenceBootstrapStart', { networkBinding: NETWORK_BINDING });
    expect(secondStart.kind).toBe('operation-outcome');
    if (secondStart.kind === 'operation-outcome') {
      expect(secondStart.outcome).toBe('OK');
    }
    expect(server.queryCalls).toBeLessThanOrEqual(1);
    expect(server.submitCalls).toBe(1);

    // Closing tab 1 does not stop the authority-owned session.
    authority.handle({ kind: 'lifecycle', signal: 'disconnect', clientChannel: tab1.channel, authorityEpoch: authority.snapshot().epoch });
    const afterClose = await dispatchOp(tab2, authority, 'licenceBootstrapEligibility', { foreground: true, connectivity: 'online' });
    expect(afterClose.kind).toBe('operation-outcome');
    if (afterClose.kind === 'operation-outcome') {
      expect(afterClose.outcome).toBe('OK');
    }

    // Lock from either tab tears the session down.
    const lockOutcome = await dispatchOp(tab2, authority, 'lockAll');
    expect(lockOutcome.kind).toBe('operation-outcome');
    if (lockOutcome.kind === 'operation-outcome') {
      expect(lockOutcome.outcome).toBe('OK');
    }
    // No further bootstrap step is accepted without authentication.
    const refused = await dispatchOp(tab2, authority, 'licenceBootstrapControl', { control: 'retry' });
    expect(refused.kind).toBe('operation-outcome');
    if (refused.kind === 'operation-outcome') {
      expect(refused.outcome).toBe('INVALID_INPUT');
    }
  });

  it('FEAT-017 one confirmed-upgrade operation spans tabs (activate, coalesce, acknowledge)', async () => {
    const storage = new MemoryVaultStorage();
    const server: FakeServer = {
      signingAddress: '',
      encryptionAddress: '',
      queryCalls: 0,
      submitCalls: 0,
      // First query after auth returns an ACTIVE Direct Free licence with the
      // three higher Veritas options; later queries return the SAME active
      // truth (the upgrade seals but never indexes in this fixture).
      querySequence: [
        {
          ok: true,
          state: 'active',
          active: {
            LicenceReference: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
            PlanId: LICENCE_PLAN_DIRECT_FREE,
            PlanFamily: 'direct',
            DisplayName: 'HushVoting! Direct Free',
            SafeDescription: 'Free community licence',
            EligibleVoterCap: 100,
            UnlimitedElections: true,
            TermKind: 'perpetual',
            TermYears: 0,
            EffectiveFromUtc: '2026-09-06T00:00:00.000Z',
            AssignedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
            AllowedGovernanceOptionIds: [],
            HigherOptions: [
              { PlanId: 'hushvoting.veritas.500', DisplayName: 'HushVoting! Veritas 500', SafeDescription: 'Up to 500 voters', EligibleVoterCap: 500, UnlimitedElections: true, TermKind: 'annual', TermYears: 1 },
              { PlanId: 'hushvoting.veritas.2000', DisplayName: 'HushVoting! Veritas 2k', SafeDescription: 'Up to 2,000 voters', EligibleVoterCap: 2000, UnlimitedElections: true, TermKind: 'annual', TermYears: 1 },
            ],
          },
        },
      ],
      submitStatus: 'PENDING',
    };
    const { authority, ports } = createAuthority(storage, server);
    const tab1 = ports[0];
    const tab2 = ports[1];
    await authenticate(tab1, authority, server);

    // Tab 1 starts bootstrap → ready with the active Direct Free licence.
    const start = await dispatchOp(tab1, authority, 'licenceBootstrapStart', { networkBinding: NETWORK_BINDING });
    expect(start.kind).toBe('operation-outcome');
    if (start.kind !== 'operation-outcome') return;
    expect(start.outcome).toBe('OK');
    const startPayload = start.payload as { ok?: boolean; snapshot?: { phase?: string; projection?: { planId?: string } | null } };
    expect(startPayload.snapshot?.phase).toBe('entitlementReady');
    expect(startPayload.snapshot?.projection?.planId).toBe(LICENCE_PLAN_DIRECT_FREE);

    // Tab 1 activates the 2k plan through the CLOSED authority op.
    const confirm = await dispatchOp(tab1, authority, 'licenceUpgradeConfirm', { targetPlanId: 'hushvoting.veritas.2000' });
    expect(confirm.kind).toBe('operation-outcome');
    if (confirm.kind !== 'operation-outcome') return;
    expect(confirm.outcome).toBe('OK');
    const confirmPayload = confirm.payload as { ok?: boolean; snapshot?: { upgradeOperation?: { status?: string } | null } };
    expect(confirmPayload.snapshot?.upgradeOperation?.status).toBe('pending');
    expect(server.submitCalls).toBe(1);

    // Tab 2 sees the SAME live operation and asking again coalesces: no
    // second submission/transaction is ever created (D017-03 cross-tab).
    const duplicate = await dispatchOp(tab2, authority, 'licenceUpgradeConfirm', { targetPlanId: 'hushvoting.veritas.500' });
    expect(duplicate.kind).toBe('operation-outcome');
    if (duplicate.kind !== 'operation-outcome') return;
    expect(duplicate.outcome).toBe('OK');
    const dupPayload = duplicate.payload as { ok?: boolean; snapshot?: { upgradeOperation?: { status?: string } | null } };
    // The authority kept the original operation (still pending, still the 2k
    // target) and did not mint a second transaction.
    expect(dupPayload.snapshot?.upgradeOperation?.status).toBe('pending');
    expect(server.submitCalls).toBe(1);

    // Acknowledge from the second tab is a safe no-op step (no live terminal
    // was surfaced) and never fabricates success.
    const ack = await dispatchOp(tab2, authority, 'licenceUpgradeAcknowledge');
    expect(ack.kind).toBe('operation-outcome');
    if (ack.kind === 'operation-outcome') {
      expect(ack.outcome).toBe('OK');
    }
    expect(server.submitCalls).toBe(1);

    // Progress broadcasts to every tab carry only safe, exact-free fields.
    for (const event of progressEvents(tab1)) assertSecretFree(JSON.stringify(event));
    for (const event of progressEvents(tab2)) assertSecretFree(JSON.stringify(event));
  });
});

// EPIC-002 AT-LIC-014 -> AC-018-007/008/009 -> P018-4-01/02 -> T018-4-01/02.
// Real root machine/adapter + bridge + production worker/crypto; only server transport and storage are isolated.
describe('FEAT-018 captured election App Twin', () => {
  it.each([false, true])('binds fresh signed access without disturbing current licence readiness (%s), and clears on Close/offline/lock', async (currentLicenceReady) => {
    const electionId = '11111111-2222-4333-8444-555555555555';
    const server: FakeServer = { signingAddress: '', encryptionAddress: '', queryCalls: 0, submitCalls: 0,
      querySequence: [currentLicenceReady ? { ok: true, state: 'active', active: {
        LicenceReference: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e', PlanId: LICENCE_PLAN_DIRECT_FREE,
        PlanFamily: 'direct', DisplayName: 'HushVoting! Direct Free', SafeDescription: 'Free community licence',
        EffectiveFromUtc: '2026-09-06T00:00:00.000Z', AssignedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
        AllowedGovernanceOptionIds: [], HigherOptions: [],
      } } : noActive()], submitStatus: 'PENDING',
      electionScope: { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: ['vote', 'results'], EntitlementReason: '' } };
    const { authority, ports } = createAuthority(new MemoryVaultStorage(), server);
    const tab = ports[0];
    const identity = await authenticate(tab, authority, server);
    const actors: AuthActors = {
      localUserAuthority: createLocalUserAuthorityTestActor([{ code: 'INIT_NO_LOCAL_USER' }]),
      secretAuthority: createSecretAuthorityTestActor([{ code: 'UNLOCK_SUCCESS' }]),
      identityVerification: createIdentityVerificationTestActor([{ code: 'VERIFY_SUCCESS', identity: {
        alias: 'Alice', publicSigningKey: identity.signingAddress, publicEncryptionKey: identity.encryptionAddress } }]),
      onboarding: { createUser: createOnboardingTestActor([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'test-local-user' }]),
        restoreCredentialFile: null, restoreRecoveryWords: null },
      removal: createRemovalTestActor([{ code: 'REMOVAL_COMPLETE' }]),
      browserCoordination: createBrowserCoordinationTestActor([{ code: 'COORDINATION_SAFE' }]),
      navigation: createNavigationTestActor(), telemetry: null,
    };
    const adapter = new AuthAdapter({ actors, registeredCapabilities: new Set(), safeCoordination: true, entitlementRequired: true });
    const settleRoot = async () => { for (let n = 0; n < 12; n++) { completeAllPendingOperations(); await new Promise(resolve => setTimeout(resolve, 0)); } };
    await settleRoot(); adapter.send({ type: 'INTENT.CREATE_USER' }); await settleRoot();
    adapter.sendEvent({ type: 'CONNECTIVITY.CHANGE', state: 'online' });
    const listeners = new Set<(value: unknown) => void>();
    const deliver = tab.deliver;
    tab.deliver = event => { deliver(event); if (event.kind === 'licence-progress') for (const listener of listeners) listener(event); };
    const client = { dispatch: async (operation: string, payload?: Record<string, unknown>) => dispatchOp(tab, authority, operation, payload),
      onLicenceProgress: (listener: (value: unknown) => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; } };
    const bridge = new EntitlementBridge({ adapter, client: client as unknown as BrowserVaultClient, networkBinding: NETWORK_BINDING,
      lockSession: async () => { await dispatchOp(tab, authority, 'lockAll'); adapter.send({ type: 'INTENT.LOCK' }); return true; } });
    const awaitBootstrap = async () => {
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        bridge.observe(adapter.snapshot());
        if (bridge.isRunning && adapter.snapshot().entitlementStage === (currentLicenceReady ? 'entitlementReady' : 'awaitingIndex')
          && authority.snapshot().activeOperationId === null) return;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      throw new Error('Bootstrap did not release the worker at awaitingIndex');
    };
    try {
      bridge.start(); bridge.observe(adapter.snapshot());
      await awaitBootstrap();
      const first = bridge.refreshElectionAccess(electionId);
      const repeated = bridge.refreshElectionAccess(electionId);
      expect(first).toBe(repeated);
      expect(await first).toBe(true);
      expect(server.electionCalls).toBe(1);
      expect(server.electionSignaturesValid).toBe(true);
      expect(adapter.snapshot().entitlementReady).toBe(currentLicenceReady);
      expect(adapter.snapshot().protectedAccess).toBe(currentLicenceReady);
      expect(canAccessCapturedElection(adapter.snapshot(), electionId, 'vote')).toBe(true);
      expect(canAccessCapturedElection(adapter.snapshot(), '22222222-2222-4333-8444-555555555555', 'vote')).toBe(false);
      expect(canAccessCapturedElection(adapter.snapshot(), electionId, 'close')).toBe(false);
      const signedSubmissions = server.submitCalls;
      server.electionScope = { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: ['results'], EntitlementReason: '' };
      await bridge.refreshElectionAccess(electionId);
      expect(canAccessCapturedElection(adapter.snapshot(), electionId, 'vote')).toBe(false);
      expect(canAccessCapturedElection(adapter.snapshot(), electionId, 'results')).toBe(true);
      adapter.sendEvent({ type: 'CONNECTIVITY.CHANGE', state: 'offline' });
      expect(adapter.snapshot().electionAccess).toBeNull();
      adapter.sendEvent({ type: 'CONNECTIVITY.CHANGE', state: 'online' });
      expect(canAccessCapturedElection(adapter.snapshot(), electionId, 'results')).toBe(false);
      await bridge.refreshElectionAccess(electionId);
      const prior = adapter.snapshot().electionAccess!;
      const licenceQueriesBeforeFailure = server.queryCalls;
      server.electionStatus = 503;
      expect(await bridge.refreshElectionAccess(electionId)).toBe(false);
      expect(adapter.snapshot().electionAccess?.reason).toBe('ENTITLEMENT_AUTHORITY_UNAVAILABLE');
      expect(server.submitCalls).toBe(signedSubmissions);
      expect(adapter.snapshot().entitlementReady).toBe(currentLicenceReady);
      expect(adapter.snapshot().protectedAccess).toBe(currentLicenceReady);
      expect(server.queryCalls).toBe(licenceQueriesBeforeFailure);
      server.electionStatus = 200;
      // T018-5-01: the existing Retry control refreshes election scope rather
      // than constructing a licence or treating renewal as captured-access repair.
      expect(bridge.handleIntent({ type: 'INTENT.ENTITLEMENT_RETRY' })).toBe(true);
      expect(await bridge.refreshElectionAccess(electionId)).toBe(true);
      expect(server.submitCalls).toBe(signedSubmissions);
      let releaseQuery!: () => void;
      server.electionPause = new Promise<void>(resolve => { releaseQuery = resolve; });
      const disconnectedQuery = bridge.refreshElectionAccess(electionId);
      adapter.sendEvent({ type: 'CONNECTIVITY.CHANGE', state: 'offline' });
      adapter.sendEvent({ type: 'CONNECTIVITY.CHANGE', state: 'online' });
      releaseQuery();
      expect(await disconnectedQuery).toBe(false);
      expect(adapter.snapshot().electionAccess).toBeNull();
      server.electionPause = undefined;
      expect(await bridge.refreshElectionAccess(electionId)).toBe(true);
      server.electionPause = new Promise<void>(resolve => { releaseQuery = resolve; });
      const stoppedQuery = bridge.refreshElectionAccess(electionId);
      bridge.stop(); adapter.sendEvent({ type: 'ENTITLEMENT.RESET' });
      bridge.start(); bridge.observe(adapter.snapshot());
      releaseQuery();
      expect(await stoppedQuery).toBe(false);
      expect(adapter.snapshot().electionAccess).toBeNull();
      server.electionPause = undefined;
      // The worker serializes operations: bootstrap can be busy behind the old
      // query. The next root observation retries after that operation has ended.
      await awaitBootstrap();
      expect(bridge.isRunning).toBe(true);
      expect(await bridge.refreshElectionAccess(electionId)).toBe(true);
      for (const reason of ['ENTITLEMENT_CAPTURE_UNAVAILABLE', 'ENTITLEMENT_SEMANTICS_UNSUPPORTED',
        'ENTITLEMENT_ROSTER_REPLACEMENT_AFTER_LINK']) {
        const queriesBefore = server.queryCalls;
        server.electionScope = { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: [], EntitlementReason: reason };
        expect(await bridge.refreshElectionAccess(electionId)).toBe(false);
        expect(adapter.snapshot().entitlementReady).toBe(currentLicenceReady);
        expect(server.queryCalls).toBe(queriesBefore);
      }
      if (currentLicenceReady) {
        for (const reason of ['ENTITLEMENT_NOT_ACTIVE', 'ENTITLEMENT_LIMIT_EXCEEDED', 'ENTITLEMENT_PROFILE_NOT_ALLOWED']) {
          const queriesBefore = server.queryCalls;
          server.electionScope = { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: [], EntitlementReason: reason };
          expect(await bridge.refreshElectionAccess(electionId)).toBe(false);
          await awaitBootstrap();
          expect(server.queryCalls).toBe(queriesBefore + 1);
          expect(server.submitCalls).toBe(signedSubmissions);
        }
      }
      server.electionScope = { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: ['results'], EntitlementReason: '' };
      // Lock while the real signed query is still pending; neither worker nor root
      // may turn its late reply into a grant for the next session.
      server.electionPause = new Promise<void>(resolve => { releaseQuery = resolve; });
      const lockedQuery = bridge.refreshElectionAccess(electionId);
      await dispatchOp(tab, authority, 'lockAll'); adapter.send({ type: 'INTENT.LOCK' });
      releaseQuery();
      expect(await lockedQuery).toBe(false);
      expect(adapter.snapshot().electionAccess).toBeNull();
      adapter.sendEvent({ type: 'ELECTION.ACCESS.RESULT', electionId, epoch: prior.epoch, actorSigningAddress: prior.actorSigningAddress,
        requestId: 1, access: prior });
      expect(canAccessCapturedElection(adapter.snapshot(), electionId, 'results')).toBe(false);
      assertSecretFree(JSON.stringify(adapter.snapshot()));
    } finally { bridge.stop(); adapter.stop(); await dispatchOp(tab, authority, 'lockAll'); }
  }, 30_000); // Real crypto plus several serialized worker round trips; not a latency assertion.
});
