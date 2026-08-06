/**
 * FEAT-011 Task 4.5 — one secret-authority-owned identity convergence
 * coordinator shared by Create, Recovery Words, Credential File, and
 * returning unlock.
 *
 * Closed policy (transition-fault-matrix T10–T21):
 *  - entering the review state alone performs NO creation side effect; only
 *    the typed `CONFIRM_MISSING_PROFILE` intent starts seal+submit;
 *  - the exact signed transaction is sealed before the first network call and
 *    reused byte-for-byte after uncertainty;
 *  - ACCEPTED/matching PENDING wait via one coalesced 3 s lookup loop;
 *  - a 3-minute abnormal-delay boundary enters the delayed state without
 *    replacement;
 *  - restart/foreground/reconnect always lookup-first;
 *  - another device confirming first synchronizes chain metadata and discards
 *    the unused local pending transaction;
 *  - authentication requires exact both-key indexed lookup under the current
 *    epoch; stale-epoch and late results are rejected.
 *
 * Framework-neutral and fake-clock testable. Ports are injected; the Browser
 * worker / Ubuntu / Android authorities implement them (Task 4.7 handoff).
 */

import {
  classifyLookupDecision,
  type ConvergenceEpoch,
  type ExactIdentityProof,
  type IdentityLookupDecision,
  type MissingProfileIntent,
  type MissingProfileReview,
} from './contracts';
import {
  RECONCILIATION_ABNORMAL_DELAY_MS,
  RECONCILIATION_POLL_INTERVAL_MS,
  digestOf,
  isRetryEligible,
  matchesBinding,
  type SealedPendingTransactionV2,
  type PendingSubmitOutcome,
} from './pending-transaction';
import type { SealedPendingRef, SealedPendingStore } from './sealed-pending-store';

/** Structured submission outcome from the transport (never free-form message). */
export type ConvergenceSubmitOutcome = 'accepted' | 'pending' | 'alreadyExists' | 'rejectedEditable' | 'rejectedTerminal' | 'transportUncertain';

/** Lookup transport outcome (closed). */
export type ConvergenceLookupOutcome =
  | { readonly kind: 'exactProfile'; readonly proof: ExactIdentityProof }
  | { readonly kind: 'explicitNotfound' }
  | { readonly kind: 'transportAmbiguity' }
  | { readonly kind: 'malformed' };

/** Coordinator ports — implemented by the target authorities (Task 4.7). */
export interface ConvergencePorts {
  /** Exact both-key lookup via the unchanged GetIdentity transport. */
  lookup(): Promise<ConvergenceLookupOutcome>;
  /** Operation-scoped canonical signing + seal inside the secret authority. */
  sealAndSign(review: MissingProfileReview, epoch: ConvergenceEpoch): Promise<SealedPendingTransactionV2>;
  /** Submit the exact sealed transaction (byte-identical). */
  submit(record: SealedPendingTransactionV2): Promise<{ readonly outcome: ConvergenceSubmitOutcome; readonly validationCode: string | null }>;
  /** Persisted sealed store (two-slot CAS). */
  store: SealedPendingStore;
  /** Injectable clock (fake-clock tests). */
  now(): number;
}

/** Closed coordinator reactions. */
export type CoordinatorResult =
  | { readonly kind: 'waiting' } // ACCEPTED/PENDING; poll loop active
  | { readonly kind: 'confirmed'; readonly proof: ExactIdentityProof } // exact indexed confirmation
  | { readonly kind: 'delayed' } // 3-minute boundary
  | { readonly kind: 'retryable' } // transport ambiguity / incomplete
  | { readonly kind: 'alreadyExists' } // immediate fresh lookup required
  | { readonly kind: 'rejectedEditable' } // alias correction only
  | { readonly kind: 'rejectedTerminal' } // cryptographic/key/context
  | { readonly kind: 'staleEpoch' }
  | { readonly kind: 'noPendingRegistration' };

export interface CoordinatorState {
  readonly epoch: ConvergenceEpoch;
  readonly networkBinding: string;
  readonly review: MissingProfileReview | null;
  readonly sealedRef: SealedPendingRef | null;
  readonly acceptedSinceMs: number | null;
}

export class IdentityConvergenceCoordinator {
  private readonly ports: ConvergencePorts;
  private readonly networkBinding: string;
  private state: CoordinatorState;

  constructor(ports: ConvergencePorts, networkBinding: string, epoch: ConvergenceEpoch, initialState?: Partial<CoordinatorState>) {
    this.ports = ports;
    this.networkBinding = networkBinding;
    this.state = {
      epoch,
      networkBinding,
      review: initialState?.review ?? null,
      sealedRef: initialState?.sealedRef ?? null,
      acceptedSinceMs: initialState?.acceptedSinceMs ?? null,
    };
  }

  get epoch(): ConvergenceEpoch {
    return this.state.epoch;
  }

  /** Enter (or resume) the explicit review surface. No side effects. */
  enterReview(review: MissingProfileReview): CoordinatorResult {
    this.state = { ...this.state, review };
    return { kind: 'waiting' };
  }

  /**
   * The ONLY creation trigger: explicit CONFIRM_MISSING_PROFILE intent under
   * the current epoch. Seals the exact transaction BEFORE any network call
   * and submits it once; byte-identical retry after uncertainty.
   */
  async confirmMissingProfile(intent: MissingProfileIntent, epoch: ConvergenceEpoch): Promise<CoordinatorResult> {
    if (intent !== 'CONFIRM_MISSING_PROFILE') {
      return { kind: 'noPendingRegistration' };
    }
    if (epoch !== this.state.epoch) {
      return { kind: 'staleEpoch' };
    }
    const review = this.state.review;
    if (review === null || !review.sameIdentityAcknowledged) {
      return { kind: 'noPendingRegistration' };
    }

    // 1. Seal before submit (exact bytes + digest persisted atomically).
    const sealed = await this.ports.sealAndSign(review, this.state.epoch);
    const ref = await this.ports.store.write(sealed);
    this.state = { ...this.state, review, sealedRef: ref };

    // 2. Lookup-first: a fresh exact lookup runs before ANY submission.
    const lookup = await this.ports.lookup();
    if (lookup.kind === 'exactProfile') {
      await this.ports.store.clear();
      this.state = { ...this.state, sealedRef: null };
      return { kind: 'confirmed', proof: lookup.proof };
    }
    if (lookup.kind === 'transportAmbiguity' || lookup.kind === 'malformed') {
      return { kind: 'retryable' };
    }

    // 3. Submit the exact sealed bytes.
    const submit = await this.ports.submit(sealed);
    switch (submit.outcome) {
      case 'accepted':
      case 'pending':
        this.state = { ...this.state, acceptedSinceMs: this.ports.now() };
        return { kind: 'waiting' };
      case 'alreadyExists':
        return { kind: 'alreadyExists' };
      case 'rejectedEditable':
        return { kind: 'rejectedEditable' };
      case 'rejectedTerminal':
        await this.ports.store.clear();
        this.state = { ...this.state, sealedRef: null };
        return { kind: 'rejectedTerminal' };
      case 'transportUncertain':
        // Exact bytes remain authoritative; lookup-first before any retry.
        return { kind: 'retryable' };
    }
  }

  /**
   * One coalesced reconciliation tick: poll every 3 s while eligible; enter
   * the delayed state after 3 minutes without replacement; never authenticate
   * without exact both-key indexed lookup.
   */
  async reconcile(eligible: { readonly foregrounded: boolean; readonly online: boolean; readonly visible: boolean }): Promise<CoordinatorResult> {
    if (
      !eligible.foregrounded ||
      !eligible.online ||
      !eligible.visible ||
      this.state.sealedRef === null ||
      this.state.acceptedSinceMs === null
    ) {
      return { kind: 'waiting' };
    }

    // acceptedSinceMs is narrowed non-null by the guard above.
    const acceptedSinceMs = this.state.acceptedSinceMs;
    const delay = evaluateDelay(acceptedSinceMs, this.ports.now());
    if (delay.delayed) {
      return { kind: 'delayed' };
    }

    const lookup = await this.ports.lookup();
    if (lookup.kind === 'exactProfile') {
      // Atomic chain-metadata sync + safe retirement of the pending state.
      await this.ports.store.clear();
      this.state = { ...this.state, sealedRef: null, acceptedSinceMs: null };
      return { kind: 'confirmed', proof: lookup.proof };
    }
    if (lookup.kind === 'explicitNotfound') {
      // Still pending on-chain: keep the coalesced loop.
      return { kind: 'waiting' };
    }
    return { kind: 'retryable' };
  }

  /** Restart/foreground/reconnect: always lookup-first from the sealed stage. */
  async resume(epoch: ConvergenceEpoch, eligible: boolean): Promise<CoordinatorResult> {
    if (epoch !== this.state.epoch) {
      return { kind: 'staleEpoch' };
    }
    const record = await this.ports.store.read();
    if (record === null || !matchesBinding(record, this.state.epoch, this.networkBinding)) {
      return { kind: 'noPendingRegistration' };
    }

    if (!isRetryEligible(record)) {
      return { kind: 'noPendingRegistration' };
    }

    const lookup = await this.ports.lookup();
    if (lookup.kind === 'exactProfile') {
      await this.ports.store.clear();
      this.state = { ...this.state, sealedRef: null, acceptedSinceMs: null };
      return { kind: 'confirmed', proof: lookup.proof };
    }
    if (lookup.kind === 'explicitNotfound' && eligible && this.state.acceptedSinceMs !== null) {
      return { kind: 'waiting' };
    }
    // Sealed bytes remain authoritative; a transport ambiguity never creates
    // a replacement transaction.
    return lookup.kind === 'explicitNotfound' ? { kind: 'waiting' } : { kind: 'retryable' };
  }

  /** Other-device confirmation: synchronize chain metadata and discard the unused local transaction. */
  async synchronizeOtherDevice(proof: ExactIdentityProof): Promise<CoordinatorResult> {
    await this.ports.store.clear();
    this.state = { ...this.state, sealedRef: null, acceptedSinceMs: null };
    return { kind: 'confirmed', proof };
  }
}

/** Fake-clock-friendly 3-minute delay evaluation. */
export function evaluateDelay(acceptedSinceMs: number, nowMs: number): { readonly delayed: boolean; readonly elapsedMs: number } {
  const elapsedMs = nowMs - acceptedSinceMs;
  return { delayed: elapsedMs >= RECONCILIATION_ABNORMAL_DELAY_MS, elapsedMs };
}

export const CONVERGENCE_POLL_INTERVAL_MS = RECONCILIATION_POLL_INTERVAL_MS;
export const CONVERGENCE_ABNORMAL_DELAY_MS = RECONCILIATION_ABNORMAL_DELAY_MS;

export { digestOf, isRetryEligible, matchesBinding };

export type { SealedPendingTransactionV2, PendingSubmitOutcome };
