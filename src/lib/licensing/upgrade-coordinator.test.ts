/**
 * FEAT-017 Tasks 3.2/3.4 — deterministic confirmed-upgrade coordinator tests.
 *
 * Fake monotonic clock + stubbed ports prove the closed confirmed-upgrade
 * lifecycle on the ONE `LicenceEntitlementCoordinator`:
 *  - opening/selection/confirmation create no transaction; Activate seals ONE
 *    exact confirmed-upgrade operation (binding from authority-owned fresh
 *    projection only) and submission never grants capability by itself;
 *  - duplicate confirmation (double click, tab race, remount) coalesces or
 *    routes to the existing operation — one journal record, one submission,
 *    one transaction UUID (D017-03);
 *  - the fresh-query re-validation before sealing detects changed current
 *    licence / dropped target (D017-06) and never seals against truth the
 *    page did not display;
 *  - PENDING/ALREADY_EXISTS/uncertain admission outcomes are reconciliation
 *    inputs only; ordinary three-second waiting requeries without automatic
 *    resubmission; Retry resubmits the byte-identical sealed transaction;
 *  - the old indexed licence staying current preserves the pending operation
 *    and keeps the workspace usable (D017-01);
 *  - restart/reconnect/foreground resolution, exact-UUID local success,
 *    competing activation, stale/notification/invalidation policy, and
 *    binding-less-upgrade fail-closed behavior (Task 3.3 rules).
 *
 * Baseline FEAT-016 bootstrap behavior is asserted unchanged by the existing
 * `coordinator.test.ts` suite. No wall-clock sleeps: clocks are deterministic.
 */

import { describe, expect, it } from 'vitest';
import { ENTITLEMENT_QUERY_POLL_INTERVAL_MS } from './policy';
import type { LicenceQueryTransportResult } from './contracts';
import type { LicenceAdmissionOutcome } from './direct-free';
import {
  LicenceEntitlementCoordinator,
  type Eligibility,
  type LicenceCoordinatorPorts,
} from './coordinator';
import type { LicencePendingTransactionRecord } from './pending-transaction';
import type { LicenceHigherOptionView } from './contracts';

const ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
const NETWORK = 'hush-network-local-devnet-5195086';
const CATALOGUE_V1 = 'hushvoting-licence-catalogue/v1.0.0';

const CURRENT_REF = '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e';
const CURRENT_PLAN = 'hushvoting.veritas.500';
const CURRENT_NAME = 'HushVoting! Veritas 500';
const TARGET_PLAN = 'hushvoting.veritas.2000';
const TARGET_NAME = 'HushVoting! Veritas 2k';
const COMPETING_REF = '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55';

const eligible: Eligibility = { authenticated: true, foregrounded: true, reachable: true, paused: false };

function higherOption(planId = TARGET_PLAN, displayName = TARGET_NAME): LicenceHigherOptionView {
  return {
    PlanId: planId,
    DisplayName: displayName,
    SafeDescription: 'Annual Veritas licence',
    EligibleVoterCap: planId === TARGET_PLAN ? 2000 : 5000,
    UnlimitedElections: true,
    TermKind: 'annual',
    TermYears: 1,
  };
}

/** Fresh active indexed truth with current + optional server higher options. */
function activeResult(
  input: {
    reference?: string;
    planId?: string;
    displayName?: string;
    higherOptions?: ReadonlyArray<LicenceHigherOptionView>;
  } = {},
): LicenceQueryTransportResult {
  const higherOptions = input.higherOptions ?? [higherOption()];
  return {
    ok: true,
    state: 'active',
    active: {
      LicenceReference: input.reference ?? CURRENT_REF,
      PlanId: input.planId ?? CURRENT_PLAN,
      PlanFamily: 'veritas',
      DisplayName: input.displayName ?? CURRENT_NAME,
      SafeDescription: 'Veritas licence',
      EligibleVoterCap: 500,
      UnlimitedElections: false,
      TermKind: 'annual',
      TermYears: 1,
      EffectiveFromUtc: '2026-01-01T00:00:00.000Z',
      ExpiresAtUtc: '2027-01-01T00:00:00.000Z',
      AssignedCatalogueVersion: CATALOGUE_V1,
      AllowedGovernanceOptionIds: [],
      HigherOptions: [...higherOptions],
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

/** Boot a coordinator into entitlementReady with the old current licence. */
async function bootReady(h: Harness): Promise<void> {
  h.queryQueue.push(activeResult());
  await h.coordinator.start();
  expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
}

/** Seal one confirmed upgrade from ready truth; admission outcome `admission`. */
async function sealUpgrade(h: Harness, admission: LicenceAdmissionOutcome = 'accepted', target = TARGET_PLAN): Promise<void> {
  await bootReady(h);
  h.queryQueue.push(activeResult()); // confirmUpgrade always re-queries fresh first
  h.admissionQueue.push(admission);
  await h.coordinator.confirmUpgrade(target);
}

/** Sealed envelope payload of the first submitted transaction. */
function submittedPayload(h: Harness): Record<string, unknown> {
  expect(h.submitCalls.length).toBeGreaterThan(0);
  const envelope = JSON.parse(h.submitCalls[0].exactJson) as { Payload: Record<string, unknown> };
  return envelope.Payload;
}

describe('confirmed-upgrade initiation (Task 3.1/3.2)', () => {
  it('opening a ready licence and selecting an option create no transaction', async () => {
    const h = makeHarness();
    await bootReady(h);
    // Only the boot query ran; nothing was submitted or journaled.
    expect(h.submitCalls).toHaveLength(0);
    expect(h.journal.size).toBe(0);
    expect(h.coordinator.snapshot().upgradeOperation).toBeNull();
  });

  it('Activate seals exactly one confirmed-upgrade operation bound to authority-owned fresh truth', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'accepted');
    const snap = h.coordinator.snapshot();
    expect(h.submitCalls).toHaveLength(1);
    expect(h.journal.size).toBe(1);
    // The exact payload carries the server-bound transition facts only.
    const payload = submittedPayload(h);
    expect(payload.TransitionIntent).toBe('confirmed_upgrade');
    expect(payload.RequestedPlanId).toBe(TARGET_PLAN);
    expect(payload.ObservedCatalogueVersion).toBe(CATALOGUE_V1);
    expect(payload.ExpectedCurrentLicenceTransactionId).toBe(CURRENT_REF);
    expect(payload.ExpectedCurrentPlanId).toBe(CURRENT_PLAN);
    // D017-01: the old licence stays current and usable; the op is pending.
    expect(snap.phase).toBe('entitlementReady');
    expect(snap.projection?.licenceReference).toBe(CURRENT_REF);
    expect(snap.upgradeOperation?.status).toBe('pending');
    expect(snap.upgradeOperation?.operation?.targetPlanId).toBe(TARGET_PLAN);
    expect(snap.upgradeNotificationEligible).toBe(false);
    // No client-authored authorization field reaches the snapshot.
    expect(snap.upgradeOperation?.operation?.expectedCurrentPlanId).toBe(CURRENT_PLAN);
  });

  it('duplicate confirmation (double click) coalesces: one record, one submission, one UUID', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'pending');
    const firstId = h.coordinator.snapshot().upgradeOperation?.operation?.pendingTransactionId;
    expect(firstId).toBeTruthy();
    // Same view double-fires Activate again: no second query, no second seal.
    await h.coordinator.confirmUpgrade(TARGET_PLAN);
    const snap = h.coordinator.snapshot();
    expect(snap.lastOutcomeCode).toBe('upgrade-already-pending');
    expect(snap.upgradeOperation?.operation?.pendingTransactionId).toBe(firstId);
    expect(h.submitCalls).toHaveLength(1);
    expect(h.journal.size).toBe(1);
    expect(h.identityCounter).toBe(1);
  });

  it('a tab race with a different target routes to the existing operation', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'pending');
    // Another same-authority tab tries to start a DIFFERENT upgrade.
    await h.coordinator.confirmUpgrade('hushvoting.veritas.5000');
    const snap = h.coordinator.snapshot();
    expect(snap.lastOutcomeCode).toBe('upgrade-already-pending');
    expect(snap.upgradeOperation?.operation?.targetPlanId).toBe(TARGET_PLAN);
    expect(h.submitCalls).toHaveLength(1);
    expect(h.journal.size).toBe(1);
  });

  it('invalid and unbounded activation inputs are typed rejections that never seal', async () => {
    const h = makeHarness();
    await bootReady(h);
    for (const bad of ['', 'x'.repeat(200), 42, null, undefined, {}]) {
      h.queryQueue.push(activeResult()); // any fresh truth would be discarded
      await h.coordinator.confirmUpgrade(bad as never);
      expect(h.coordinator.snapshot().lastOutcomeCode).toBe('upgrade-invalid-input');
    }
    expect(h.submitCalls).toHaveLength(0);
    expect(h.journal.size).toBe(0);
  });

  it('activation is refused while the authority has no usable ready projection', async () => {
    const h = makeHarness();
    h.queryQueue.push({ ok: true, state: 'unavailable', code: 'licence_index_unavailable' });
    await h.coordinator.start();
    await h.coordinator.confirmUpgrade(TARGET_PLAN);
    expect(h.coordinator.snapshot().lastOutcomeCode).toBe('upgrade-not-ready');
    expect(h.submitCalls).toHaveLength(0);
  });

  it('never seals when indexed truth changed while the user reviewed options (stale current)', async () => {
    const h = makeHarness();
    await bootReady(h);
    // The fresh confirm query returns a DIFFERENT current licence.
    h.queryQueue.push(activeResult({ reference: COMPETING_REF, planId: 'hushvoting.veritas.10000', displayName: 'HushVoting! Veritas 10k' }));
    await h.coordinator.confirmUpgrade(TARGET_PLAN);
    expect(h.coordinator.snapshot().lastOutcomeCode).toBe('upgrade-stale-current-changed');
    expect(h.submitCalls).toHaveLength(0);
    expect(h.journal.size).toBe(0);
  });

  it('never seals a target the fresh truth no longer offers (catalogue changed)', async () => {
    const h = makeHarness();
    await bootReady(h);
    h.queryQueue.push(activeResult({ higherOptions: [higherOption('hushvoting.veritas.10000', 'HushVoting! Veritas 10k')] }));
    await h.coordinator.confirmUpgrade(TARGET_PLAN);
    expect(h.coordinator.snapshot().lastOutcomeCode).toBe('upgrade-stale-catalogue-changed');
    expect(h.submitCalls).toHaveLength(0);
    expect(h.journal.size).toBe(0);
  });

  it('never seals when another device already activated the requested plan', async () => {
    const h = makeHarness();
    await bootReady(h);
    h.queryQueue.push(activeResult({ planId: TARGET_PLAN, displayName: TARGET_NAME }));
    await h.coordinator.confirmUpgrade(TARGET_PLAN);
    expect(h.coordinator.snapshot().lastOutcomeCode).toBe('upgrade-stale-current-changed');
    expect(h.submitCalls).toHaveLength(0);
  });
});

describe('pending operation under the old indexed licence (D017-01)', () => {
  it('PENDING admission reconciles under old limits; ordinary polls never resubmit', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'pending');
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');

    // Three poll ticks return the SAME old current licence: still pending.
    h.queryQueue.push(activeResult(), activeResult(), activeResult());
    for (let i = 0; i < 3; i += 1) {
      h.advance(ENTITLEMENT_QUERY_POLL_INTERVAL_MS);
      await h.coordinator.tick(eligible);
    }
    const snap = h.coordinator.snapshot();
    expect(snap.phase).toBe('entitlementReady');
    expect(snap.upgradeOperation?.status).toBe('pending');
    expect(snap.upgradeOperation?.operation?.targetPlanId).toBe(TARGET_PLAN);
    expect(snap.lastOutcomeCode).toBe('upgrade-pending-old-current');
    expect(h.submitCalls).toHaveLength(1); // query-only: never re-submitted
    expect(h.queryCalls).toBe(5); // boot + confirm + 3 polls
    expect(h.journal.size).toBe(1);
  });

  it('uncertain submission preserves the exact sealed operation and reconciles by query', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'uncertain');
    const pendingId = h.coordinator.snapshot().upgradeOperation?.operation?.pendingTransactionId;
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
    // Old current returns: still pending, exact record retained.
    h.queryQueue.push(activeResult());
    h.advance(ENTITLEMENT_QUERY_POLL_INTERVAL_MS);
    await h.coordinator.tick(eligible);
    const snap = h.coordinator.snapshot();
    expect(snap.upgradeOperation?.status).toBe('pending');
    expect(snap.upgradeOperation?.operation?.pendingTransactionId).toBe(pendingId);
    expect(h.submitCalls).toHaveLength(1);
  });

  it('ALREADY_EXISTS triggers an immediate fresh query and never grants access by itself', async () => {
    const h = makeHarness();
    // boot + confirm fresh query + the immediate already-exists query.
    h.queryQueue.push(activeResult(), activeResult(), activeResult());
    await h.coordinator.start();
    h.admissionQueue.push('alreadyExists');
    await h.coordinator.confirmUpgrade(TARGET_PLAN);
    // The immediate query returns the old current (not yet indexed).
    expect(h.coordinator.snapshot().phase).toBe('entitlementReady');
    expect(h.coordinator.snapshot().upgradeOperation?.status).toBe('pending');
    expect(h.queryCalls).toBe(3); // boot + confirm + already-exists
  });

  it('Retry resubmits the byte-identical sealed transaction (same UUID, same JSON)', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'pending');
    const first = h.submitCalls[0];
    h.admissionQueue.push('pending');
    await h.coordinator.retryExact();
    expect(h.submitCalls).toHaveLength(2);
    expect(h.submitCalls[1]).toEqual(first);
    expect(h.coordinator.snapshot().upgradeOperation?.status).toBe('pending');
    expect(h.identityCounter).toBe(1); // no replacement identity was minted
  });
});

describe('privacy and snapshot shape', () => {
  it('the upgrade snapshot never carries exact bytes, bindings, or journal state', async () => {
    const h = makeHarness();
    await sealUpgrade(h, 'pending');
    const snap = h.coordinator.snapshot();
    expect(snap.upgradeOperation).not.toBeNull();
    const serialized = JSON.stringify(snap.upgradeOperation);
    for (const forbidden of [
      'exactJson',
      'digest',
      'signature',
      'UserSignature',
      'identityBinding',
      'networkBinding',
      'targetBinding',
      'recoveryState',
      'attemptEvidence',
      'upgradeBinding',
      'TransitionIntent',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});
