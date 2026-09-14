/**
 * FEAT-016 Task 3.6 — deterministic coordinator tests.
 *
 * Fake monotonic clock + stubbed ports prove: query-first start/restart;
 * exactly one serialized query at a time; 3 s query-only cadence while
 * awaiting with NO automatic resubmission; 30 s reachable-foreground delayed
 * threshold (background/offline time excluded); immediate delayed on paused;
 * ACCEPTED/PENDING/ALREADY_EXISTS never grant access; Retry reuses the exact
 * sealed bytes; restart reuses the bound pending record only when truth stays
 * no-active; first UNAUTHENTICATED retries once with a fresh envelope and the
 * second forces Lock; Lock ignores stale completions; ready stops polling and
 * retires confirmed/superseded pending records. No wall-clock sleeps.
 */

import { describe, expect, it } from 'vitest';
import {
  ENTITLEMENT_QUERY_POLL_INTERVAL_MS,
} from './policy';
import type { LicenceQueryTransportResult } from './contracts';
import type { LicenceAdmissionOutcome } from './direct-free';
import {
  LicenceEntitlementCoordinator,
  type Eligibility,
  type LicenceCoordinatorPorts,
} from './coordinator';
import type { LicencePendingTransactionRecord } from './pending-transaction';

const ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
const NETWORK = 'hush-network-local-devnet-5195086';

const eligible: Eligibility = { authenticated: true, foregrounded: true, reachable: true, paused: false };

function activeResult(reference = '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e'): LicenceQueryTransportResult {
  return {
    ok: true,
    state: 'active',
    active: {
      LicenceReference: reference,
      PlanId: 'hushvoting.veritas.2000',
      PlanFamily: 'veritas',
      DisplayName: 'HushVoting! Veritas 2k',
      SafeDescription: 'Annual Veritas licence',
      EligibleVoterCap: 2000,
      UnlimitedElections: true,
      TermKind: 'annual',
      TermYears: 1,
      EffectiveFromUtc: '2026-01-01T00:00:00.000Z',
      ExpiresAtUtc: '2027-01-01T00:00:00.000Z',
      AssignedCatalogueVersion: 'hushvoting-licence-catalogue/v1.0.0',
      AllowedGovernanceOptionIds: [],
      HigherOptions: [],
    },
  };
}

function noActiveResult(): LicenceQueryTransportResult {
  return {
    ok: true,
    state: 'noActive',
    template: {
      TransitionIntent: 'baseline_free',
      RequestedPlanId: 'hushvoting.direct.free',
      ObservedCatalogueVersion: 'hushvoting-licence-catalogue/v1.0.0',
    },
  };
}

class Harness {
  clockMs = 1_752_000_000_000;
  queryQueue: LicenceQueryTransportResult[] = [];
  admissionQueue: LicenceAdmissionOutcome[] = [];
  submitCalls: Array<{ exactJson: string; transactionId: string }> = [];
  queryCalls = 0;
  identityCounter = 0;
  journal = new Map<string, LicencePendingTransactionRecord>();
  deleteCalls: string[] = [];

  ports: LicenceCoordinatorPorts = {
    nowMs: () => this.clockMs,
    queryTransport: async () => {
      this.queryCalls += 1;
      const next = this.queryQueue.shift();
      if (next === undefined) {
        throw new Error('harness: query queue exhausted');
      }
      return next;
    },
    submitBaseline: async (record) => {
      this.submitCalls.push({ exactJson: record.transaction.exactJson, transactionId: record.transactionId });
      const next = this.admissionQueue.shift();
      if (next === undefined) {
        throw new Error('harness: admission queue exhausted');
      }
      return next;
    },
    nextBaselineIdentity: () => {
      this.identityCounter += 1;
      return {
        transactionId: `11111111-2222-4333-8444-${String(this.identityCounter).padStart(12, '0')}`,
        timestampUtc: new Date(this.clockMs).toISOString(),
      };
    },
    savePending: (record) => {
      this.journal.set(record.transactionId, record);
      return { ok: true };
    },
    loadPending: (transactionId) => {
      const record = this.journal.get(transactionId);
      return record ? { ok: true, record } : { ok: false, reason: 'not-found' };
    },
    loadPendingForIdentity: (identityBinding, networkBinding) => {
      for (const record of this.journal.values()) {
        if (record.identityBinding === identityBinding && record.networkBinding === networkBinding) {
          return { ok: true, record };
        }
      }
      return { ok: false };
    },
    deletePending: (transactionId) => {
      this.deleteCalls.push(transactionId);
      this.journal.delete(transactionId);
    },
  };

  coordinator = new LicenceEntitlementCoordinator(ACTOR, NETWORK, this.ports);

  advance(ms: number): void {
    this.clockMs += ms;
  }
}

function makeHarness(): Harness {
  return new Harness();
}

describe('bootstrap and admission', () => {
  it('no-active signs/submits exactly one baseline and never opens before indexed truth', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    expect(h.submitCalls).toHaveLength(1);
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');
    expect(h.coordinator.snapshot().projection).toBeNull();
    expect(h.journal.size).toBe(1); // exact record persisted (seal-before-submit)
  });

  it('ACCEPTED/PENDING never grant access and poll does not resubmit automatically', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('pending');
    await h.coordinator.start();
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');

    // Three poll ticks over reachable time with no-active still absent.
    h.queryQueue.push(noActiveResult(), noActiveResult(), noActiveResult());
    for (let i = 0; i < 3; i += 1) {
      h.advance(ENTITLEMENT_QUERY_POLL_INTERVAL_MS);
      await h.coordinator.tick(eligible);
    }
    // Query-only: submit is never re-invoked by polling.
    expect(h.submitCalls).toHaveLength(1);
    expect(h.queryCalls).toBe(4); // start query + 3 poll queries
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');
  });

  it('a later active query opens with the safe projection and retires the pending record', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    const pendingId = h.coordinator.snapshot().pendingTransactionId;
    expect(pendingId).not.toBeNull();

    h.queryQueue.push(activeResult(pendingId ?? ''));
    h.advance(ENTITLEMENT_QUERY_POLL_INTERVAL_MS);
    await h.coordinator.tick(eligible);
    const snap = h.coordinator.snapshot();
    expect(snap.phase).toBe('entitlementReady');
    expect(snap.projection).not.toBeNull();
    expect(snap.pendingTransactionId).toBeNull();
    expect(h.deleteCalls).toContain(pendingId);
    expect(h.journal.size).toBe(0);
  });

  it('delayed confirmation appears at 30 s of reachable foreground time', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');

    // 20 s reachable -> still awaiting (first advance anchors the clock).
    h.queryQueue.push(noActiveResult());
    h.advance(20_000);
    await h.coordinator.tick(eligible);
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');

    // Accumulate 30 s of reachable time across ticks -> delayed.
    h.queryQueue.push(noActiveResult(), noActiveResult(), noActiveResult());
    for (let i = 0; i < 3; i += 1) {
      h.advance(10_000);
      await h.coordinator.tick(eligible);
    }
    expect(h.coordinator.snapshot().phase).toBe('confirmationDelayed');
    expect(h.coordinator.snapshot().lastOutcomeCode).toBe('confirmation-delayed-30s');
  });

  it('a paused-chain signal shows delayed confirmation before 30 seconds', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    h.advance(5_000);
    await h.coordinator.onConnectivity('paused');
    expect(h.coordinator.snapshot().phase).toBe('confirmationDelayed');
    expect(h.coordinator.snapshot().lastOutcomeCode).toBe('chain-paused');
  });

  it('excludes background/offline time from the delayed window', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    // 60 s offline/background: never counts.
    h.advance(60_000);
    const backgrounded: Eligibility = { ...eligible, foregrounded: false };
    await h.coordinator.tick(backgrounded);
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');
    // Paused=false but unreachable also stops work.
    const offlineEligibility: Eligibility = { ...eligible, reachable: false };
    await h.coordinator.tick(offlineEligibility);
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex');
  });
});

describe('retry, restart, and reconciliation', () => {
  it('Retry resubmits the exact transaction bytes (same id, same JSON)', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    const first = h.submitCalls[0];
    h.advance(1_000);
    h.admissionQueue.push('pending');
    await h.coordinator.retryExact();
    expect(h.submitCalls).toHaveLength(2);
    expect(h.submitCalls[1]).toEqual(first); // byte-identical reuse
    expect(h.coordinator.snapshot().phase).toBe('awaitingIndex'); // PENDING = reconciliation
  });

  it('ALREADY_EXISTS triggers an immediate fresh query (never access)', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('alreadyExists');
    // After already-exists, the immediate query returns active.
    h.queryQueue.push(activeResult());
    await h.coordinator.start();
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
    expect(h.queryCalls).toBe(2);
  });

  it('restart queries first and resubmits the exact bound record only when truth stays no-active', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    const original = h.submitCalls[0];

    // Simulate process restart: new coordinator over the same journal + truth no-active.
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('pending');
    const restarted = new LicenceEntitlementCoordinator(ACTOR, NETWORK, h.ports);
    const snapshot = await restarted.start();
    // The record was found (bound pending) and resubmitted exactly; no new identity.
    expect(snapshot.phase).toBe('awaitingIndex');
    expect(h.identityCounter).toBe(1); // no second baseline identity minted
    expect(h.submitCalls).toHaveLength(2);
    expect(h.submitCalls[1]).toEqual(original);
  });

  it('a higher/other-device active assignment supersedes and retires the local pending record', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    const pendingId = h.coordinator.snapshot().pendingTransactionId ?? '';
    // Active truth is a DIFFERENT (higher) licence reference.
    h.queryQueue.push(activeResult('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55'));
    h.advance(ENTITLEMENT_QUERY_POLL_INTERVAL_MS);
    await h.coordinator.tick(eligible);
    const snap = h.coordinator.snapshot();
    expect(snap.phase).toBe('entitlementReady');
    expect(snap.projection?.licenceReference).toBe('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55');
    expect(h.deleteCalls).toContain(pendingId);
    expect(snap.pendingTransactionId).toBeNull();
  });
});

describe('authentication, connectivity, and cancellation', () => {
  it('first UNAUTHENTICATED retries once; second forces Lock', async () => {
    const h = makeHarness();
    h.queryQueue.push({ ok: false, status: 'UNAUTHENTICATED' }, { ok: false, status: 'UNAUTHENTICATED' });
    await h.coordinator.start();
    expect(h.queryCalls).toBe(2);
    expect(h.coordinator.snapshot().phase).toBe('lockedOut');
    expect(h.coordinator.snapshot().consecutiveUnauthenticated).toBe(2);
  });

  it('first UNAUTHENTICATED then success proceeds normally', async () => {
    const h = makeHarness();
    h.queryQueue.push({ ok: false, status: 'UNAUTHENTICATED' }, activeResult());
    await h.coordinator.start();
    expect(h.queryCalls).toBe(2);
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
  });

  it('offline gates work; reconnect queries fresh first', async () => {
    const h = makeHarness();
    h.queryQueue.push(noActiveResult());
    h.admissionQueue.push('accepted');
    await h.coordinator.start();
    await h.coordinator.onConnectivity('offline');
    expect(h.coordinator.snapshot().phase).toBe('resolving');
    expect(h.coordinator.snapshot().projection).toBeNull();
    const queriesBefore = h.queryCalls;
    h.advance(10_000);
    await h.coordinator.tick(eligible); // offline-reachable semantics: still resolving, but coordinator must not double-query
    h.queryQueue.push(activeResult());
    await h.coordinator.onConnectivity('online');
    expect(h.queryCalls).toBe(queriesBefore + 1); // reconnect query only
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
  });

  it('ready state does not poll', async () => {
    const h = makeHarness();
    h.queryQueue.push(activeResult());
    await h.coordinator.start();
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
    h.advance(30_000);
    await h.coordinator.tick(eligible);
    expect(h.queryCalls).toBe(1); // no background/foreground polling while ready
  });

  it('Lock cancels in-flight work and stale completions are ignored', async () => {
    const h = makeHarness();
    // Do not prefill the query queue: start blocks on an unresolved promise.
    const gate: { release?: (r: LicenceQueryTransportResult) => void } = {};
    const originalQuery = h.ports.queryTransport;
    h.ports.queryTransport = () =>
      new Promise<LicenceQueryTransportResult>((resolve) => {
        gate.release = resolve;
      });
    const pendingStart = h.coordinator.start();
    await h.coordinator.lock();
    // Release the stale completion AFTER lock: it must be ignored.
    gate.release?.(activeResult());
    await pendingStart;
    expect(h.coordinator.snapshot().phase).toBe('lockedOut');
    expect(h.coordinator.snapshot().projection).toBeNull();
    h.ports.queryTransport = originalQuery;
  });

  it('authority unavailable is never no-active/Free and stays retryable', async () => {
    const h = makeHarness();
    h.queryQueue.push({ ok: true, state: 'unavailable', code: 'licence_index_unavailable' });
    await h.coordinator.start();
    expect(h.coordinator.snapshot().phase).toBe('entitlementUnavailable');
    expect(h.submitCalls).toHaveLength(0);
    expect(h.coordinator.snapshot().projection).toBeNull();
  });
});
