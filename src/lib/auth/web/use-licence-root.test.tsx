/**
 * FEAT-017 Task 6.1/6.2 — useLicenceRootFacts (root composition hook) tests.
 *
 * AuthRoot drives the Account licence summary (A0), the N0/N1 top-bar
 * surfaces, and the full-width LicenceWorkspaceHost from ONE `LicenceRootFacts`
 * value derived from the SAME EntitlementBridge safe mirror + machine
 * projection. These tests lock the Task 6.1 composition contract:
 *  - no licence facts are rendered before the first authority progress
 *    broadcast and none while the machine projection is absent (root gate —
 *    stale values are never displayed);
 *  - the hook recomputes when a NEW safe broadcast arrives (a live pending
 *    upgrade repaints Account to the A0P view-progress surface and the
 *    workspace input in one re-render — same authority facts);
 *  - the subscription follows the current bridge (a rebuilt authority after
 *    re-authentication starts empty and only its own broadcasts repaint) and
 *    unmounting cleans up without state-update warnings.
 *
 * The bridge under test is the REAL `EntitlementBridge` (the same page-side
 * composition bridge AuthRoot instantiates) driven by the same fake adapter +
 * fake client vocabulary the entitlement-bridge suite uses; progress is
 * delivered through the real handleProgress path.
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…06; Task 6.1
 * behavior spec + acceptance criteria.
 */
import { describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { EntitlementBridge } from './entitlement-bridge';
import { useLicenceRootFacts } from './use-licence-root';
import type { AuthRenderProjection } from '../react/adapter';
import type { ClientOperationResult } from '../../browser-vault/production/client';
import {
  directFreeWithOptionsProjection,
  upgradeOperationOf,
} from '../../../lib/licensing/fixtures/presentation-fixtures';

function projection(overrides: Partial<AuthRenderProjection>): AuthRenderProjection {
  return {
    authState: 'authenticated',
    connectivity: 'online',
    protectedAccess: false,
    entitlementStage: 'entitlementReady',
    entitlementReady: true,
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

/** Safe licence progress shape (additive protocol event, mirror of LicenceProgress). */
interface ProgressShape {
  phase: string;
  projection: unknown | null;
  lastOutcomeCode: string | null;
  pendingTransactionId: string | null;
  upgradeOperation: unknown | null;
  upgradeNotificationEligible: boolean;
  emittedAtMs: number;
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
  send(intent: unknown): void {
    this.sent.push(intent);
  }
  subscribe(): () => void {
    return () => undefined;
  }
}

class FakeClient {
  progressHandler: ((p: ProgressShape) => void) | null = null;
  readonly dispatched: Array<{ operation: string; payload: Record<string, unknown> | undefined }> = [];
  queue: ClientOperationResult[] = [];
  onLicenceProgress(handler: (p: ProgressShape) => void): void {
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

const okResult = (phase: string): ClientOperationResult => ({
  operationId: 'op',
  outcome: 'OK',
  retryable: false,
  allowedActions: [],
  payload: { kind: 'licence-bootstrap-step', ok: true, snapshot: { phase } },
});

/** One REAL bridge started over a ready machine (adapter) + fake transport. */
function readyBridge(): { bridge: EntitlementBridge; client: FakeClient; adapter: FakeAdapter } {
  const adapter = new FakeAdapter();
  adapter.current = projection({ entitlementStage: 'entitlementResolving', entitlementReady: false });
  const client = new FakeClient();
  const bridge = new EntitlementBridge({
    adapter: adapter as never,
    client: client as never,
    networkBinding: 'hushnetwork-devnet',
    lockSession: async () => true,
    isForegrounded: () => true,
    subscribeVisibility: () => () => undefined,
  });
  bridge.start();
  client.queue = [okResult('entitlementReady')];
  bridge.observe(adapter.current); // session starts synchronously (running=true)
  adapter.current = projection({ entitlementStage: 'entitlementReady', entitlementReady: true, connectivity: 'online' });
  return { bridge, client, adapter };
}

function readyProgress(overrides: Partial<ProgressShape> = {}): ProgressShape {
  return {
    phase: 'entitlementReady',
    projection: directFreeWithOptionsProjection(),
    lastOutcomeCode: 'ready',
    pendingTransactionId: null,
    upgradeOperation: null,
    upgradeNotificationEligible: false,
    emittedAtMs: 1,
    ...overrides,
  };
}

describe('useLicenceRootFacts (Task 6.1 root composition hook)', () => {
  it('renders no licence facts before the first authority broadcast and none without a bridge', () => {
    const { bridge } = readyBridge();
    const projectionReady = projection({});
    const { result, unmount } = renderHook(() => useLicenceRootFacts(bridge, projectionReady));
    // Mirror is still empty (no broadcast yet): Account + workspace show
    // nothing — the root never displays stale values.
    expect(result.current.input).toBeNull();
    expect(result.current.account).toBeNull();
    unmount();

    // No bridge (AuthRoot before composition): empty by construction.
    const withoutBridge = renderHook(() => useLicenceRootFacts(null, projectionReady));
    expect(withoutBridge.result.current).toEqual({ input: null, account: null });
    withoutBridge.unmount();

    // No machine projection yet (AuthRoot initializing): empty by construction.
    const withoutProjection = renderHook(() => useLicenceRootFacts(bridge, null));
    expect(withoutProjection.result.current).toEqual({ input: null, account: null });
    withoutProjection.unmount();
  });

  it('derives Account + workspace input from the SAME authority broadcast (fresh ready truth)', async () => {
    const { bridge, client } = readyBridge();
    const projectionReady = projection({});
    const { result, unmount } = renderHook(() => useLicenceRootFacts(bridge, projectionReady));
    act(() => {
      client.progressHandler?.(readyProgress());
    });
    expect(result.current.input).not.toBeNull();
    if (result.current.input === null) return;
    expect(result.current.input.phase).toBe('entitlementReady');
    expect(result.current.input.projection?.planId).toBe('hushvoting.direct.free');
    // Account summary comes from the same mirror projection (A0 upgrade
    // action because strictly higher options exist).
    expect(result.current.account).not.toBeNull();
    expect(result.current.account?.available).toBe(true);
    expect(result.current.account?.planDisplayName).toBe('HushVoting! Direct Free');
    expect(result.current.account?.action).toBe('upgrade');
    unmount();
  });

  it('a live pending upgrade broadcast repaints Account to the A0P view-progress surface and the workspace input together', async () => {
    const { bridge, client } = readyBridge();
    const projectionReady = projection({});
    const { result, unmount } = renderHook(() => useLicenceRootFacts(bridge, projectionReady));
    act(() => {
      client.progressHandler?.(readyProgress());
    });
    act(() => {
      // Same cadence, one sealed confirmed-upgrade operation now pending:
      // the next safe broadcast carries the live operation (D017-01/03).
      client.progressHandler?.(
        readyProgress({
          upgradeOperation: upgradeOperationOf('pending'),
          emittedAtMs: 2,
        }),
      );
    });
    expect(result.current.input?.upgradeOperation?.status).toBe('pending');
    expect(result.current.account?.action).toBe('view-progress');
    expect(result.current.account?.currentLimitsRemain).toBe(true);
    expect(result.current.account?.pendingStatusText).not.toBeNull();
    unmount();
  });

  it('a new bridge (rebuilt authority) repaints from its own broadcasts and unmount cleans up', async () => {
    const first = readyBridge();
    const second = readyBridge();
    const projectionReady = projection({});
    const { result, rerender, unmount } = renderHook(
      ({ bridge }: { bridge: EntitlementBridge }) => useLicenceRootFacts(bridge, projectionReady),
      { initialProps: { bridge: first.bridge } },
    );
    // First authority broadcast → facts available.
    act(() => {
      first.client.progressHandler?.(readyProgress());
    });
    expect(result.current.account?.available).toBe(true);
    // Authority rebuild (re-authentication/epoch change): AuthRoot creates a
    // fresh bridge whose mirror is empty; the hook resubscribes and the root
    // immediately stops showing licence facts (no remembered state).
    rerender({ bridge: second.bridge });
    expect(result.current.input).toBeNull();
    expect(result.current.account).toBeNull();
    // Only the CURRENT authority's broadcasts repaint the root.
    act(() => {
      second.client.progressHandler?.(readyProgress({ upgradeOperation: upgradeOperationOf('pending'), emittedAtMs: 3 }));
    });
    expect(result.current.input?.upgradeOperation?.status).toBe('pending');
    // Unmounting with further authority activity never throws or warns.
    unmount();
    act(() => {
      second.client.progressHandler?.(readyProgress({ emittedAtMs: 4 }));
    });
  });
});
