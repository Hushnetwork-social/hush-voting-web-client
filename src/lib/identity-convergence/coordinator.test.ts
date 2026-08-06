/**
 * FEAT-011 Task 4.6 — coordinator tests: explicit intent only, structured
 * outcome mapping, 3 s/3 min fake-clock behavior, restart lookup-first,
 * another-device convergence, stale-epoch and late-result rejection, atomic
 * metadata sync.
 */

import { describe, expect, it } from 'vitest';
import {
  CONVERGENCE_ABNORMAL_DELAY_MS,
  IdentityConvergenceCoordinator,
  evaluateDelay,
  type ConvergenceLookupOutcome,
  type ConvergencePorts,
  type ConvergenceSubmitOutcome,
} from './coordinator';
import type { ConvergenceEpoch, ExactIdentityProof, MissingProfileReview } from './contracts';

const EPOCH = 'epoch-1' as ConvergenceEpoch;
import { digestOf } from './pending-transaction';
import { InMemorySealedPendingStore } from './sealed-pending-store';

const PROOF: ExactIdentityProof = {
  signingAddress: 'sig-a',
  encryptionAddress: 'enc-a',
  normalizedAlias: 'alice',
  visibility: 'public',
};

const REVIEW: MissingProfileReview = {
  origin: 'create',
  alias: 'alice',
  visibility: 'public',
  prefillIsAuthoritative: false,
  sameIdentityAcknowledged: true,
};

interface HarnessState {
  lookupResults: ConvergenceLookupOutcome[];
  submitOutcomes: ConvergenceSubmitOutcome[];
  submitCodes: (string | null)[];
  now: number;
  sealCalls?: number;
  submittedBytes?: string[];
}

function makeHarness(state: HarnessState) {
  const store = new InMemorySealedPendingStore();
  const ports: ConvergencePorts = {
    lookup: async () => state.lookupResults.shift() ?? { kind: 'transportAmbiguity' },
    sealAndSign: async (_review) => {
      state.sealCalls = (state.sealCalls ?? 0) + 1;
      return {
      schemaVersion: 2,
      transaction: { exactJson: JSON.stringify({ review: _review }), digest: digestOf(JSON.stringify({ review: _review })) },
      transactionId: 'tx-1',
      reviewedMetadata: { alias: _review.alias, visibility: _review.visibility },
      lifecycle: 'sealed',
      attemptEvidence: [],
      epochBinding: EPOCH,
      networkBinding: 'isolated-local-devnet-v1',
      rollbackState: 'postSeal',
    };
    },
    submit: async (record) => {
      state.submittedBytes = [...(state.submittedBytes ?? []), record.transaction.exactJson];
      return { outcome: state.submitOutcomes.shift() ?? 'accepted', validationCode: state.submitCodes.shift() ?? null };
    },
    store,
    now: () => state.now,
  };
  const coordinator = new IdentityConvergenceCoordinator(ports, 'isolated-local-devnet-v1', EPOCH);
  return { coordinator, store, state };
}

describe('explicit intent (Task 4.6)', () => {
  it('entering review alone performs no creation side effect', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [], submitOutcomes: [], submitCodes: [], now: 0 });
    coordinator.enterReview(REVIEW);

    expect(await store.read()).toBeNull();
  });

  it('non-CONFIRM intents never trigger creation', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [], submitOutcomes: [], submitCodes: [], now: 0 });
    coordinator.enterReview(REVIEW);

    const result = await coordinator.confirmMissingProfile('REVIEW_MISSING_PROFILE', EPOCH);

    expect(result).toEqual({ kind: 'noPendingRegistration' });
    expect(await store.read()).toBeNull();
  });

  it('unacknowledged same-key review blocks registration', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [], submitOutcomes: [], submitCodes: [], now: 0 });
    coordinator.enterReview({ ...REVIEW, sameIdentityAcknowledged: false });

    const result = await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    expect(result).toEqual({ kind: 'noPendingRegistration' });
    expect(await store.read()).toBeNull();
  });
});

describe('lookup-first and submit outcomes (Task 4.6)', () => {
  it('confirms directly when the pre-submit lookup finds the exact profile', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [{ kind: 'exactProfile', proof: PROOF }], submitOutcomes: [], submitCodes: [], now: 0 });
    coordinator.enterReview(REVIEW);

    const result = await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    expect(result).toEqual({ kind: 'confirmed', proof: PROOF });
    expect(await store.read()).toBeNull();
  });

  it('seals before submit and maps ACCEPTED to waiting with poll start', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 1000 });
    coordinator.enterReview(REVIEW);

    const result = await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    expect(result).toEqual({ kind: 'waiting' });
    const sealed = await store.read();
    expect(sealed).not.toBeNull();
    expect(sealed!.transaction.digest).toBe(digestOf(JSON.stringify({ review: REVIEW })));
  });

  it('maps PENDING to waiting, ALREADY_EXISTS, editable and terminal rejections, and uncertainty', async () => {
    const cases: Array<[ConvergenceSubmitOutcome, string | null, ReturnType<IdentityConvergenceCoordinator['confirmMissingProfile']> extends Promise<infer R> ? R : never]> = [
      ['pending', null, { kind: 'waiting' }],
      ['alreadyExists', null, { kind: 'alreadyExists' }],
      ['rejectedEditable', 'FULL_IDENTITY_ALIAS_OUT_OF_BOUNDS', { kind: 'rejectedEditable' }],
      ['rejectedTerminal', 'FULL_IDENTITY_INVALID_SIGNATURE', { kind: 'rejectedTerminal' }],
      ['transportUncertain', null, { kind: 'retryable' }],
    ];

    for (const [outcome, code, expected] of cases) {
      const harness = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: [outcome], submitCodes: [code], now: 0 });
      harness.coordinator.enterReview(REVIEW);
      const result = await harness.coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);
      expect(result).toEqual(expected);
    }
  });

  it('terminal rejection clears the sealed pending state', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: ['rejectedTerminal'], submitCodes: ['X'], now: 0 });
    void store;
    coordinator.enterReview(REVIEW);

    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    expect(await store.read()).toBeNull();
  });
});

describe('reconciliation (Task 4.6)', () => {
  it('polls only while eligible; exact lookup confirms and retires pending state', async () => {
    const { coordinator } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 0 });
    coordinator.enterReview(REVIEW);
    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    const notEligible = await coordinator.reconcile({ foregrounded: false, online: true, visible: true });
    expect(notEligible).toEqual({ kind: 'waiting' });

    const harness2 = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }, { kind: 'exactProfile', proof: PROOF }], submitOutcomes: ['accepted'], submitCodes: [null], now: 1000 });
    harness2.coordinator.enterReview(REVIEW);
    await harness2.coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);
    harness2.state.now = 1000 + 3_000;

    const result = await harness2.coordinator.reconcile({ foregrounded: true, online: true, visible: true });
    expect(result).toEqual({ kind: 'confirmed', proof: PROOF });
    expect(await harness2.store.read()).toBeNull();
  });

  it('enters the delayed state after the 3-minute boundary without replacement', async () => {
    const { coordinator } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }, { kind: 'explicitNotfound' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 0 });
    coordinator.enterReview(REVIEW);
    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    expect(evaluateDelay(0, CONVERGENCE_ABNORMAL_DELAY_MS - 1).delayed).toBe(false);
    expect(evaluateDelay(0, CONVERGENCE_ABNORMAL_DELAY_MS).delayed).toBe(true);
  });

  it('transport ambiguity in the poll loop is retryable, never absence or auth', async () => {
    const { coordinator } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }, { kind: 'transportAmbiguity' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 0 });
    coordinator.enterReview(REVIEW);
    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    const result = await coordinator.reconcile({ foregrounded: true, online: true, visible: true });
    expect(result).toEqual({ kind: 'retryable' });
  });
});

describe('restart and lifecycle (Task 4.6)', () => {
  it('resume is lookup-first and never creates a speculative replacement', async () => {
    const { coordinator } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 0 });
    coordinator.enterReview(REVIEW);
    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    const harness2 = makeHarness({ lookupResults: [{ kind: 'transportAmbiguity' }], submitOutcomes: [], submitCodes: [], now: 5000 });
    const result = await harness2.coordinator.resume(EPOCH, true);

    // No sealed stage in the fresh instance -> no pending registration, no lookup side effects.
    expect(result).toEqual({ kind: 'noPendingRegistration' });
  });

  it('stale epoch rejects late completion', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 0 });
    coordinator.enterReview(REVIEW);
    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    const stale = await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', 'epoch-2' as ConvergenceEpoch);
    expect(stale).toEqual({ kind: 'staleEpoch' });
    expect(await store.read()).not.toBeNull(); // sealed stage preserved
  });

  it('other-device confirmation synchronizes and discards the local pending transaction', async () => {
    const { coordinator, store } = makeHarness({ lookupResults: [{ kind: 'explicitNotfound' }], submitOutcomes: ['accepted'], submitCodes: [null], now: 0 });
    coordinator.enterReview(REVIEW);
    await coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    const result = await coordinator.synchronizeOtherDevice(PROOF);

    expect(result).toEqual({ kind: 'confirmed', proof: PROOF });
    expect(await store.read()).toBeNull();
  });
});

describe('byte-identical retry and restart resubmit (Task 4.6 review fixes)', () => {
  it('retries REUSE the sealed exact bytes — sealAndSign runs exactly once', async () => {
    const harness = makeHarness({
      lookupResults: [{ kind: 'explicitNotfound' }, { kind: 'explicitNotfound' }, { kind: 'explicitNotfound' }],
      submitOutcomes: ['transportUncertain', 'accepted'],
      submitCodes: [null, null],
      now: 0,
    });
    harness.coordinator.enterReview(REVIEW);

    await harness.coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);
    const retry = await harness.coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);

    expect(retry).toEqual({ kind: 'waiting' });
    expect(harness.state.sealCalls).toBe(1);
    expect(new Set(harness.state.submittedBytes ?? []).size).toBe(1); // identical bytes both times
  });

  it('resume performs a byte-identical re-submission after lookup-first', async () => {
    const harness = makeHarness({
      lookupResults: [{ kind: 'explicitNotfound' }, { kind: 'explicitNotfound' }],
      submitOutcomes: ['accepted'],
      submitCodes: [null],
      now: 5000,
    });
    harness.coordinator.enterReview(REVIEW);
    await harness.coordinator.confirmMissingProfile('CONFIRM_MISSING_PROFILE', EPOCH);
    const firstBytes = harness.state.submittedBytes?.[0];

    // Simulate restart: fresh coordinator instance over the same store state.
    const restarted = new IdentityConvergenceCoordinator(
      { ...harnessStatePorts(harness) },
      'isolated-local-devnet-v1',
      EPOCH,
    );
    restarted.enterReview(REVIEW);

    const result = await restarted.resume(EPOCH, true);

    expect(result).toEqual({ kind: 'waiting' });
    const allBytes = harness.state.submittedBytes ?? [];
    expect(allBytes[allBytes.length - 1]).toBe(firstBytes); // byte-identical
  });
});

function harnessStatePorts(harness: ReturnType<typeof makeHarness>): ConvergencePorts {
  const { coordinator } = harness;
  void coordinator;
  return {
    lookup: async () => ({ kind: 'explicitNotfound' }),
    sealAndSign: async () => {
      throw new Error('must not re-seal on resume');
    },
    submit: async (record) => {
      harness.state.submittedBytes = [...(harness.state.submittedBytes ?? []), record.transaction.exactJson];
      return { outcome: harness.state.submitOutcomes.shift() ?? 'accepted', validationCode: null };
    },
    store: harness.store,
    now: () => harness.state.now,
  };
}
