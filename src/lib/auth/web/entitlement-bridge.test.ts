/**
 * FEAT-016 Tasks 6.7/6.8 — entitlement bridge + composition routing tests.
 *
 * Proves the page-side bootstrap bridge:
 *   - stage/connectivity/control mappings are closed and deterministic;
 *   - start fires exactly one licenceBootstrapStart with the real network
 *     binding; progress events map to epoch-scoped ENTITLEMENT.STAGE events;
 *   - the machine epoch guard is preserved (stale projections cannot apply);
 *   - Retry maps to exact resubmission only in delayed confirmation and to
 *     recovery in unavailable/repair/unsupported states;
 *   - offline gates the workspace (ENTITLEMENT.RESET) and forwards
 *     offline eligibility; reconnect pushes online and recovers by query;
 *   - a forced-lock progress outcome invokes the real session Lock path;
 *   - target authority routing is fail-closed: Web selects the
 *     SharedWorker+BFF path, native selects native ops when present and
 *     fails closed (never Browser/BFF) when absent.
 *
 * Normative source: FEAT-016 FeatureDescription "Web", "Root State-Machine
 * Contract", "Authority and Target Composition"; Tasks 6.7/6.8.
 */
import { describe, expect, it } from 'vitest';
import {
  connectivityToBridgeInput,
  stageForPhase,
  controlKindForStage,
  resolveEntitlementAuthorityForTarget,
  type EntitlementAuthorityPlan,
} from './entitlement-bridge';
import { EntitlementBridge } from './entitlement-bridge';
import type { AuthRenderProjection } from '../react/adapter';
import type { ClientOperationResult } from '../../browser-vault/production/client';
import type { AuthIntent } from '../types';

function projection(overrides: Partial<AuthRenderProjection>): AuthRenderProjection {
  return {
    authState: 'authenticated',
    connectivity: 'online',
    protectedAccess: false,
    entitlementStage: 'entitlementResolving',
    entitlementReady: false,
    sessionEpoch: 7,
    entitlementRequired: true,
    safeIdentity: { alias: 'Ada', abbreviatedSigningAddress: 'NVh…1a2b' },
    authenticatedIdentity: {
      alias: 'Ada',
      publicSigningKey: '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5',
      publicEncryptionKey: '02b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    },
    outcomeCode: null,
    supportCode: null,
    onboardingKind: null,
    ...overrides,
  };
}

class FakeAdapter {
  current: AuthRenderProjection = projection({});
  readonly sent: unknown[] = [];
  snapshot(): AuthRenderProjection {
    return this.current;
  }
  sendEvent(event: unknown): void {
    this.sent.push(event);
  }
  send(intent: AuthIntent): void {
    this.sent.push(intent);
  }
  subscribe(): () => void {
    return () => undefined;
  }
}

class FakeClient {
  progressHandler: ((p: { phase: string; projection: unknown; lastOutcomeCode: string | null; pendingTransactionId: string | null; emittedAtMs: number }) => void) | null = null;
  readonly dispatched: Array<{ operation: string; payload: Record<string, unknown> | undefined }> = [];
  queue: ClientOperationResult[] = [];
  onLicenceProgress(handler: (p: { phase: string; projection: unknown; lastOutcomeCode: string | null; pendingTransactionId: string | null; emittedAtMs: number }) => void): void {
    this.progressHandler = handler;
  }
  async dispatch(operation: string, payload?: Record<string, unknown>): Promise<ClientOperationResult> {
    this.dispatched.push({ operation, payload });
    const result = this.queue.shift();
    if (result !== undefined) {
      return result;
    }
    return { operationId: 'op', outcome: 'OK', retryable: false, allowedActions: [], payload: { ok: true, snapshot: { phase: 'entitlementReady' } } };
  }
}

const okResult = (phase: string, ok = true): ClientOperationResult => ({
  operationId: 'op',
  outcome: 'OK',
  retryable: false,
  allowedActions: [],
  payload: { kind: 'licence-bootstrap-step', ok, snapshot: { phase } },
});

function harness(options: { stage?: string; connectivity?: string } = {}) {
  const adapter = new FakeAdapter();
  adapter.current = projection({
    entitlementStage: (options.stage ?? 'entitlementResolving') as never,
    connectivity: (options.connectivity ?? 'online') as never,
  });
  const client = new FakeClient();
  const lockCalls: number[] = [];
  const bridge = new EntitlementBridge({
    adapter: adapter as never,
    client: client as never,
    networkBinding: 'hushnetwork-devnet',
    lockSession: async () => {
      lockCalls.push(1);
      return true;
    },
    isForegrounded: () => true,
    subscribeVisibility: () => () => undefined,
  });
  return { adapter, client, bridge, lockCalls };
}

describe('closed mappings', () => {
  it('maps every coordinator phase to the machine stage vocabulary', () => {
    expect(stageForPhase('resolving')).toBe('entitlementResolving');
    expect(stageForPhase('baselineSigning')).toBe('baselineSigning');
    expect(stageForPhase('baselineSubmitting')).toBe('baselineSubmitting');
    expect(stageForPhase('awaitingIndex')).toBe('awaitingIndex');
    expect(stageForPhase('confirmationDelayed')).toBe('confirmationDelayed');
    expect(stageForPhase('entitlementUnavailable')).toBe('entitlementUnavailable');
    expect(stageForPhase('entitlementUnsupported')).toBe('entitlementUnsupported');
    expect(stageForPhase('entitlementRepair')).toBe('entitlementRepair');
    expect(stageForPhase('entitlementReady')).toBe('entitlementReady');
    expect(stageForPhase('lockedOut')).toBe('lockedOut');
    expect(stageForPhase('unknown')).toBeNull();
  });

  it('maps connectivity to the authority loop vocabulary', () => {
    expect(connectivityToBridgeInput('online')).toBe('online');
    expect(connectivityToBridgeInput('paused')).toBe('paused');
    expect(connectivityToBridgeInput('offline')).toBe('offline');
    expect(connectivityToBridgeInput('reconnecting')).toBe('reconnecting');
    expect(connectivityToBridgeInput('unknown')).toBe('online');
  });

  it('maps Retry controls by stage (exact retry only in delayed confirmation)', () => {
    expect(controlKindForStage('confirmationDelayed')).toBe('retry');
    expect(controlKindForStage('entitlementUnavailable')).toBe('recover');
    expect(controlKindForStage('entitlementRepair')).toBe('recover');
    expect(controlKindForStage('entitlementUnsupported')).toBe('recover');
    expect(controlKindForStage('awaitingIndex')).toBeNull();
    expect(controlKindForStage('entitlementResolving')).toBeNull();
    expect(controlKindForStage('entitlementReady')).toBeNull();
    expect(controlKindForStage(null)).toBeNull();
  });

  it('resolves the entitlement authority plan per target (fail closed on native gaps)', () => {
    const plan: EntitlementAuthorityPlan | null = resolveEntitlementAuthorityForTarget({
      targetClass: 'web',
      hasNativeLicenceOperations: false,
    });
    expect(plan?.authority).toBe('browser-sharedworker-bff');
    expect(plan?.native).toBe(false);
    expect(
      resolveEntitlementAuthorityForTarget({ targetClass: 'ubuntu', hasNativeLicenceOperations: true })?.authority,
    ).toBe('native');
    expect(
      resolveEntitlementAuthorityForTarget({ targetClass: 'android', hasNativeLicenceOperations: true })?.authority,
    ).toBe('native');
    expect(
      resolveEntitlementAuthorityForTarget({ targetClass: 'ubuntu', hasNativeLicenceOperations: false })?.authority,
    ).toBe('fail-closed');
    expect(
      resolveEntitlementAuthorityForTarget({ targetClass: 'android', hasNativeLicenceOperations: false })?.authority,
    ).toBe('fail-closed');
  });
});

describe('EntitlementBridge', () => {
  it('starts exactly one bootstrap session with the real network binding and applies progress', async () => {
    const { adapter, client, bridge } = harness();
    bridge.start();
    client.queue = [okResult('awaitingIndex')];
    bridge.observe(adapter.current);
    // Observe fires start asynchronously; flush microtasks.
    await Promise.resolve();
    await Promise.resolve();
    expect(client.dispatched.map((d) => d.operation)).toEqual(['licenceBootstrapEligibility', 'licenceBootstrapStart']);
    expect(client.dispatched.find((d) => d.operation === 'licenceBootstrapStart')?.payload).toEqual({ networkBinding: 'hushnetwork-devnet' });
    // Progress broadcast applies the safe stage with the machine epoch.
    client.progressHandler?.({ phase: 'awaitingIndex', projection: null, lastOutcomeCode: 'accepted', pendingTransactionId: null, emittedAtMs: 1 });
    const stageEvent = adapter.sent.find((m) => (m as { type?: string }).type === 'ENTITLEMENT.STAGE');
    expect(stageEvent).toEqual({ type: 'ENTITLEMENT.STAGE', stage: 'awaitingIndex', epoch: 7 });
    bridge.stop();
  });

  it('ignores stale progress after the machine left authenticated', async () => {
    const { adapter, client, bridge } = harness();
    bridge.start();
    client.queue = [okResult('awaitingIndex')];
    bridge.observe(adapter.current);
    await Promise.resolve();
    await Promise.resolve();
    adapter.current = projection({ authState: 'locked', entitlementStage: null });
    client.progressHandler?.({ phase: 'entitlementReady', projection: null, lastOutcomeCode: 'ready', pendingTransactionId: null, emittedAtMs: 2 });
    expect(adapter.sent.some((m) => (m as { type?: string }).type === 'ENTITLEMENT.STAGE' && (m as { stage?: string }).stage === 'entitlementReady')).toBe(false);
    bridge.stop();
  });

  it('gates the workspace on offline and re-eligibility never grants access', async () => {
    const { adapter, client, bridge } = harness({ stage: 'entitlementResolving', connectivity: 'online' });
    bridge.start();
    client.queue = [okResult('entitlementReady')];
    bridge.observe(adapter.current); // starts the session
    await Promise.resolve();
    await Promise.resolve();
    expect(bridge.isRunning).toBe(true);
    adapter.current = projection({ entitlementStage: 'entitlementReady', entitlementReady: true, connectivity: 'offline' });
    bridge.observe(adapter.current);
    expect(adapter.sent.some((m) => (m as { type?: string }).type === 'ENTITLEMENT.RESET')).toBe(true);
    expect(
      client.dispatched.some((d) => d.operation === 'licenceBootstrapEligibility' && d.payload?.connectivity === 'offline'),
    ).toBe(true);
    // Online returns: eligibility online + the coordinator requery path resumes.
    adapter.current = projection({ entitlementStage: 'entitlementResolving', connectivity: 'online' });
    bridge.observe(adapter.current);
    expect(
      client.dispatched.some((d) => d.operation === 'licenceBootstrapEligibility' && d.payload?.connectivity === 'online'),
    ).toBe(true);
    bridge.stop();
  });

  it('routes Retry: exact retry in delayed confirmation, recovery elsewhere', async () => {
    const delayed = harness({ stage: 'entitlementResolving' });
    delayed.bridge.start();
    delayed.client.queue = [okResult('awaitingIndex')];
    delayed.bridge.observe(delayed.adapter.current);
    await Promise.resolve();
    await Promise.resolve();
    delayed.adapter.current = projection({ entitlementStage: 'confirmationDelayed' });
    const handledDelayed = delayed.bridge.handleIntent({ type: 'INTENT.ENTITLEMENT_RETRY' });
    await Promise.resolve();
    expect(handledDelayed).toBe(true);
    expect(
      delayed.client.dispatched.some((d) => d.operation === 'licenceBootstrapControl' && d.payload?.control === 'retry'),
    ).toBe(true);
    delayed.bridge.stop();

    const unavailable = harness({ stage: 'entitlementResolving' });
    unavailable.bridge.start();
    unavailable.client.queue = [okResult('awaitingIndex')];
    unavailable.bridge.observe(unavailable.adapter.current);
    await Promise.resolve();
    await Promise.resolve();
    unavailable.adapter.current = projection({ entitlementStage: 'entitlementUnavailable' });
    const handled = unavailable.bridge.handleIntent({ type: 'INTENT.ENTITLEMENT_RETRY' });
    await Promise.resolve();
    expect(handled).toBe(true);
    expect(
      unavailable.client.dispatched.some((d) => d.operation === 'licenceBootstrapControl' && d.payload?.control === 'recover'),
    ).toBe(true);
    unavailable.bridge.stop();
  });

  it('maps a forced-lock progress outcome onto the real session Lock path', async () => {
    const { adapter, client, bridge, lockCalls } = harness();
    bridge.start();
    client.queue = [okResult('awaitingIndex')];
    bridge.observe(adapter.current);
    await Promise.resolve();
    await Promise.resolve();
    client.progressHandler?.({ phase: 'lockedOut', projection: null, lastOutcomeCode: 'unauthenticated-forced-lock', pendingTransactionId: null, emittedAtMs: 3 });
    expect(lockCalls.length).toBe(1);
    // The machine never receives a fabricated stage for lockedOut.
    expect(adapter.sent.some((m) => (m as { stage?: string }).stage === 'lockedOut')).toBe(false);
    bridge.stop();
  });

  it('revalidation gates synchronously and issues a fresh-query control', async () => {
    const { adapter, client, bridge } = harness({ stage: 'entitlementResolving', connectivity: 'online' });
    bridge.start();
    client.queue = [okResult('entitlementReady')];
    bridge.observe(adapter.current);
    await Promise.resolve();
    await Promise.resolve();
    adapter.current = projection({ entitlementStage: 'entitlementReady', entitlementReady: true, connectivity: 'online' });
    bridge.revalidate('foreground');
    await Promise.resolve();
    expect(adapter.sent.some((m) => (m as { type?: string }).type === 'ENTITLEMENT.RESET')).toBe(true);
    const control = client.dispatched.find((d) => d.operation === 'licenceBootstrapControl');
    expect(control?.payload).toEqual({ control: 'revalidate', trigger: 'foreground' });
    bridge.stop();
  });
});
