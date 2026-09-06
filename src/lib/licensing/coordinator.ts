/**
 * FEAT-016 Task 3.5/3.6 — one serialized entitlement reconciliation coordinator.
 *
 * Closed, target-neutral coordinator owning the entitlement bootstrap within
 * one credential authority (SharedWorker or native Rust). Hosted by the root
 * state machine through one actor port (Phase 4); signing, journal custody,
 * and transport live in the authority and are injected as ports.
 *
 * Guarantees (locked by Task 3.6 deterministic tests):
 *  - query-first on every start/resume/reconnect/revalidation;
 *  - at most one in-flight call (serialized, no overlap);
 *  - query-only 3 s polling while waiting; no automatic resubmission;
 *  - delayed confirmation at 30 s of monotonic foreground/reachable time or
 *    immediately on a paused-chain signal;
 *  - offline gates and stops poll work; reconnect queries fresh first;
 *  - ACCEPTED/PENDING/ALREADY_EXISTS never grant access;
 *  - Retry resubmits the exact sealed transaction only;
 *  - restart reuses a bound pending record only when truth remains no-active;
 *  - first UNAUTHENTICATED -> one fresh-envelope retry; second -> forced Lock;
 *  - Lock/network/epoch invalidation clears ephemeral state and ignores stale
 *    completions; encrypted pending records survive for query-first recovery.
 *
 * Normative source: FEAT-016 FeatureDescription "Licence Transaction and
 * Pending Journal", "Restart and Recovery", "Timing, Polling, and
 * Connectivity", "Active-Session Revalidation and Expiry"; planning-analysis
 * report §6 (identity-convergence coordinator pattern).
 */

import {
  LICENCE_PENDING_PURPOSE,
  type LicencePendingAttemptEvidence,
  type LicencePendingTransactionRecord,
} from './pending-transaction';
import type { LicenceQueryTransportResult } from './contracts';
import type { LicenceDirectFreeTemplate } from './contracts';
import type { LicenceSafeProjection } from './projection';
import { parseEntitlementQueryResult } from './parser';
import {
  ENTITLEMENT_CONFIRMATION_DELAYED_MS,
  ENTITLEMENT_QUERY_POLL_INTERVAL_MS,
  classifyQueryOutcome,
} from './policy';
import {
  buildDirectFreeUnsignedTransaction,
  decideSubmissionOutcome,
  type LicenceAdmissionOutcome,
} from './direct-free';

/** Observable coordinator phase (subset of the root machine substates). */
export type EntitlementPhase =
  | 'resolving' // fresh query in progress / about to start
  | 'baselineSigning' // template validated; authority signing/sealing
  | 'baselineSubmitting' // exact transaction submitted
  | 'awaitingIndex' // ACCEPTED/PENDING; query-only reconciliation
  | 'confirmationDelayed' // 30 s reachable or paused signal; Retry available
  | 'entitlementUnavailable' // authority/transport unavailable; Retry/Lock
  | 'entitlementUnsupported' // compatible-client/update gate; Retry/Lock
  | 'entitlementRepair' // journal recovery/controlled replacement
  | 'entitlementReady' // compatible active indexed projection
  | 'lockedOut'; // forced Lock (second UNAUTHENTICATED / invalidation)

export interface Eligibility {
  readonly authenticated: boolean;
  readonly foregrounded: boolean;
  readonly reachable: boolean;
  readonly paused: boolean;
}

export interface CoordinatorSnapshot {
  readonly phase: EntitlementPhase;
  readonly projection: LicenceSafeProjection | null;
  readonly pendingTransactionId: string | null;
  readonly consecutiveUnauthenticated: number;
  readonly reachableElapsedMs: number;
  readonly lastOutcomeCode: string | null;
}

/** One exact baseline transaction identity minted by the authority (uuid+UTC). */
export interface BaselineIdentity {
  readonly transactionId: string;
  readonly timestampUtc: string;
}

export interface LicenceCoordinatorPorts {
  nowMs(): number;
  /** Execute one fresh signed query inside the authority; never overlaps. */
  queryTransport(): Promise<LicenceQueryTransportResult>;
  /** Sign/seal/persist then submit the exact record; returns the admission. */
  submitBaseline(record: LicencePendingTransactionRecord): Promise<LicenceAdmissionOutcome>;
  /** Mint one exact transaction identity (uuid + timestamp) for a baseline. */
  nextBaselineIdentity(): BaselineIdentity;
  savePending(record: LicencePendingTransactionRecord): { ok: boolean; reason?: string };
  loadPending(transactionId: string): { ok: boolean; record?: LicencePendingTransactionRecord; reason?: string };
  /** Find the stored pending record for this identity/network (restart recovery). */
  loadPendingForIdentity(identityBinding: string, networkBinding: string): { ok: boolean; record?: LicencePendingTransactionRecord };
  deletePending(transactionId: string): void;
}

export class LicenceEntitlementCoordinator {
  private phase: EntitlementPhase = 'resolving';
  private projection: LicenceSafeProjection | null = null;
  private pendingTransactionId: string | null = null;
  private pendingRecord: LicencePendingTransactionRecord | null = null;
  private consecutiveUnauthenticated = 0;
  private attemptCount = 0;
  private inFlight = false;
  private cancelled = false;
  private needsImmediateQuery = false;
  private lastQueryAtMs: number | null = null;
  private reachableElapsedMs = 0;
  private lastReachableAtMs: number | null = null;
  private confirmationStartedReachableMs: number | null = null;
  private lastOutcomeCode: string | null = null;

  constructor(
    private readonly actorBinding: string,
    private readonly networkBinding: string,
    private readonly ports: LicenceCoordinatorPorts,
  ) {}

  snapshot(): CoordinatorSnapshot {
    return {
      phase: this.phase,
      projection: this.projection,
      pendingTransactionId: this.pendingTransactionId,
      consecutiveUnauthenticated: this.consecutiveUnauthenticated,
      reachableElapsedMs: this.reachableElapsedMs,
      lastOutcomeCode: this.lastOutcomeCode,
    };
  }

  /** Query-first start: restart, after-auth, and explicit bootstrap recovery. */
  async start(): Promise<CoordinatorSnapshot> {
    this.cancelled = false;
    this.attemptCount = 0;
    this.consecutiveUnauthenticated = 0;
    this.projection = null;
    this.phase = 'resolving';
    await this.runFreshQuery('start');
    return this.snapshot();
  }

  /**
   * One host-driven poll cycle. Query cadence is 3 s of reachable time, at
   * most one call in flight; the 30 s window accumulates foreground/reachable
   * monotonic time only and enters delayed confirmation at the threshold or
   * immediately when the host reports paused.
   */
  async tick(eligibility: Eligibility): Promise<CoordinatorSnapshot> {
    this.advanceReachable(eligibility);
    if (
      !eligibility.authenticated ||
      !eligibility.foregrounded ||
      !eligibility.reachable ||
      this.inFlight
    ) {
      return this.snapshot();
    }
    if (
      this.phase !== 'awaitingIndex' &&
      this.phase !== 'confirmationDelayed' &&
      this.phase !== 'entitlementUnavailable'
    ) {
      return this.snapshot();
    }
    if (
      this.lastQueryAtMs !== null &&
      this.ports.nowMs() - this.lastQueryAtMs < ENTITLEMENT_QUERY_POLL_INTERVAL_MS
    ) {
      return this.snapshot();
    }
    await this.runFreshQuery('poll');
    return this.snapshot();
  }

  /** Connectivity events: paused -> immediate delayed; offline -> gate and stop. */
  async onConnectivity(event: 'online' | 'paused' | 'offline' | 'reconnecting'): Promise<CoordinatorSnapshot> {
    if (event === 'offline' || event === 'reconnecting') {
      if (this.phase !== 'lockedOut') {
        // Same-process outage gates immediately; safe entitlement may remain
        // only as hidden reconciliation context (never displayed/authorizing).
        this.phase = 'resolving';
      }
      this.projection = null;
      this.reachableElapsedMs = 0;
      this.lastReachableAtMs = null;
      this.lastOutcomeCode = 'offline';
      return this.snapshot();
    }
    if (event === 'paused') {
      if (this.phase === 'awaitingIndex') {
        this.phase = 'confirmationDelayed';
        this.lastOutcomeCode = 'chain-paused';
      }
      return this.snapshot();
    }
    // online: reconnect always queries first (fresh truth only).
    this.reachableElapsedMs = 0;
    this.lastReachableAtMs = this.ports.nowMs();
    if (
      this.phase === 'resolving' ||
      this.phase === 'confirmationDelayed' ||
      this.phase === 'entitlementUnavailable'
    ) {
      await this.runFreshQuery('reconnect');
    }
    return this.snapshot();
  }

  /** User/UI Retry: resubmits the exact sealed transaction (never a replacement). */
  async retryExact(): Promise<CoordinatorSnapshot> {
    if (this.pendingRecord === null || this.pendingTransactionId === null) {
      await this.start();
      return this.snapshot();
    }
    this.confirmationStartedReachableMs = this.reachableElapsedMs;
    this.lastOutcomeCode = 'retry-exact';
    await this.submitPending(this.pendingRecord);
    return this.snapshot();
  }

  /** Manual/UI Retry after recoverable error states (fresh query first). */
  async recoverFromError(): Promise<CoordinatorSnapshot> {
    if (this.pendingRecord !== null && this.pendingTransactionId !== null) {
      await this.retryExact();
      return this.snapshot();
    }
    await this.runFreshQuery('recovery');
    return this.snapshot();
  }

  /**
   * Revalidation triggers (foreground/resume, reconnect, expiry wake-up,
   * account entry, authoritative rejection): gate first, then fresh query.
   */
  async revalidate(trigger: string): Promise<CoordinatorSnapshot> {
    this.projection = null;
    this.lastOutcomeCode = `revalidate:${trigger}`;
    await this.runFreshQuery(trigger);
    return this.snapshot();
  }

  /** Lock/invalidation: stop work, clear ephemeral projection, ignore late results. */
  async lock(): Promise<CoordinatorSnapshot> {
    this.cancelled = true;
    this.inFlight = false;
    this.projection = null;
    this.pendingRecord = null;
    this.pendingTransactionId = null;
    this.phase = 'lockedOut';
    this.lastOutcomeCode = 'locked';
    return this.snapshot();
  }

  private advanceReachable(eligibility: Eligibility): void {
    const now = this.ports.nowMs();
    if (eligibility.authenticated && eligibility.foregrounded && eligibility.reachable) {
      if (this.lastReachableAtMs === null) {
        this.lastReachableAtMs = now;
      } else {
        this.reachableElapsedMs += Math.max(0, now - this.lastReachableAtMs);
        this.lastReachableAtMs = now;
      }
      if (
        this.confirmationStartedReachableMs !== null &&
        this.reachableElapsedMs - this.confirmationStartedReachableMs >= ENTITLEMENT_CONFIRMATION_DELAYED_MS &&
        (this.phase === 'awaitingIndex' || this.phase === 'baselineSubmitting')
      ) {
        this.phase = 'confirmationDelayed';
        this.lastOutcomeCode = 'confirmation-delayed-30s';
      }
    } else {
      this.lastReachableAtMs = null;
    }
  }

  /** One serialized query with the single fresh-envelope UNAUTHENTICATED retry. */
  private async runFreshQuery(reason: string): Promise<void> {
    if (this.inFlight || this.cancelled) {
      return;
    }
    this.inFlight = true;
    try {
      for (let attempt = 1; attempt <= 2; attempt += 1) {
        if (this.cancelled) {
          return;
        }
        this.attemptCount += 1;
        const transport = await this.ports.queryTransport();
        if (this.cancelled) {
          return; // stale completion ignored
        }
        this.lastQueryAtMs = this.ports.nowMs();
        const outcome = parseEntitlementQueryResult(
          transport,
          this.actorBinding as never,
          this.networkBinding as never,
        );
        if (outcome.outcome === 'unauthenticated' && attempt === 1 && reason !== 'retry') {
          this.consecutiveUnauthenticated = 1;
          this.lastOutcomeCode = 'unauthenticated-retry-once';
          continue; // one completely fresh envelope
        }
        if (outcome.outcome === 'unauthenticated') {
          this.consecutiveUnauthenticated = 2;
          this.projection = null;
          this.pendingRecord = null;
          this.pendingTransactionId = null;
          this.phase = 'lockedOut';
          this.lastOutcomeCode = 'unauthenticated-forced-lock';
          return;
        }
        this.consecutiveUnauthenticated = 0;
        await this.applyQueryOutcome(outcome, reason);
        return;
      }
    } finally {
      this.inFlight = false;
    }
  }

  private async applyQueryOutcome(
    outcome: ReturnType<typeof parseEntitlementQueryResult>,
    reason: string,
  ): Promise<void> {
    const cls = classifyQueryOutcome(outcome);
    switch (cls) {
      case 'ready': {
        if (outcome.outcome !== 'ready') return;
        this.reconcilePendingAgainstActive(outcome.projection.licenceReference);
        this.projection = outcome.projection;
        this.phase = 'entitlementReady';
        this.lastOutcomeCode = 'ready';
        return;
      }
      case 'noActive': {
        if (outcome.outcome !== 'noActive') return;
        this.projection = null;
        await this.handleNoActive(outcome.template, reason);
        return;
      }
      case 'unavailable':
        this.projection = null;
        this.phase = 'entitlementUnavailable';
        this.lastOutcomeCode = outcome.outcome === 'unavailable' ? outcome.code : 'unavailable';
        return;
      case 'unsupported':
        this.projection = null;
        this.phase = 'entitlementUnsupported';
        this.lastOutcomeCode =
          outcome.outcome === 'unsupported'
            ? outcome.reason === 'unknown-plan-family'
              ? 'plan-family-unknown'
              : 'catalogue-incompatible'
            : 'unsupported';
        return;
      case 'authenticationFailure':
        // Handled inside runFreshQuery (never reached from apply directly).
        this.phase = 'lockedOut';
        this.lastOutcomeCode = 'unauthenticated-forced-lock';
        return;
      case 'transient':
        this.projection = null;
        this.lastOutcomeCode = 'transport-uncertain';
        // Exact record preserved; resolution comes from poll or Retry.
        this.phase =
          this.pendingRecord !== null && this.pendingTransactionId !== null
            ? 'awaitingIndex'
            : 'entitlementUnavailable';
        return;
      case 'malformed':
        this.projection = null;
        this.phase = 'entitlementRepair';
        this.lastOutcomeCode = 'malformed-response';
        return;
      case 'terminalGuidance':
        this.projection = null;
        this.phase = 'entitlementUnsupported';
        this.lastOutcomeCode = 'terminal-guidance';
        return;
    }
    void reason;
  }

  private async handleNoActive(template: LicenceDirectFreeTemplate, reason: string): Promise<void> {
    // Query-first restart rule: resubmit a bound pending record only when
    // truth remains no-active; never fabricate a second transaction. Polling
    // cycles NEVER resubmit automatically (query-only reconciliation).
    const bound = await this.findBoundPending();
    if (bound !== null) {
      if (reason === 'poll') {
        this.pendingRecord = bound;
        this.pendingTransactionId = bound.transactionId;
        if (this.phase !== 'confirmationDelayed') {
          this.phase = 'awaitingIndex';
          this.lastOutcomeCode = 'still-waiting-no-auto-resubmit';
        }
        // Delayed confirmation retains its reason (30 s / paused); polls continue.
        return;
      }
      this.pendingRecord = bound;
      this.pendingTransactionId = bound.transactionId;
      this.lastOutcomeCode = 'no-active-resubmit-exact';
      await this.submitPending(bound);
      return;
    }
    // Journal loss or no prior record: one controlled baseline construction
    // from the exact server template with an authority-minted identity.
    this.phase = 'baselineSigning';
    this.lastOutcomeCode = 'constructing-baseline';
    const identity = this.ports.nextBaselineIdentity();
    const built = buildDirectFreeUnsignedTransaction(template, identity.transactionId, identity.timestampUtc);
    if (!built.ok) {
      this.phase = 'entitlementRepair';
      this.lastOutcomeCode = 'template-rejected';
      return;
    }
    const record: LicencePendingTransactionRecord = {
      schemaVersion: 1,
      purpose: LICENCE_PENDING_PURPOSE,
      transaction: { exactJson: built.canonicalUnsignedJson, digest: built.digest },
      transactionId: identity.transactionId,
      identityBinding: this.actorBinding,
      networkBinding: this.networkBinding,
      targetBinding: 'web-sharedworker',
      createdUtc: identity.timestampUtc,
      attemptEvidence: [],
      recoveryState: 'sealed',
    };
    const saved = this.ports.savePending(record);
    if (!saved.ok) {
      this.phase = 'entitlementRepair';
      this.lastOutcomeCode = 'journal-unavailable';
      return;
    }
    this.pendingRecord = record;
    this.pendingTransactionId = record.transactionId;
    await this.submitPending(record);
  }

  private async findBoundPending(): Promise<LicencePendingTransactionRecord | null> {
    if (this.pendingTransactionId !== null) {
      const direct = this.ports.loadPending(this.pendingTransactionId);
      if (direct.ok && direct.record !== undefined) {
        return direct.record;
      }
    }
    const byIdentity = this.ports.loadPendingForIdentity(this.actorBinding, this.networkBinding);
    if (byIdentity.ok && byIdentity.record !== undefined) {
      return byIdentity.record;
    }
    return null;
  }

  private reconcilePendingAgainstActive(activeLicenceReference: string): void {
    if (this.pendingTransactionId === null) {
      return;
    }
    const pendingIsActive = activeLicenceReference === this.pendingTransactionId;
    this.retirePending(pendingIsActive ? 'confirmed-indexed' : 'superseded');
    this.pendingRecord = null;
    this.pendingTransactionId = null;
  }

  private async submitPending(record: LicencePendingTransactionRecord): Promise<void> {
    if (this.cancelled) {
      return;
    }
    this.inFlight = true;
    this.phase = 'baselineSubmitting';
    this.confirmationStartedReachableMs = this.reachableElapsedMs;
    try {
      const admission = await this.ports.submitBaseline(record);
      if (this.cancelled) {
        return;
      }
      this.recordAttempt(record, admission);
      const decision = decideSubmissionOutcome(admission);
      switch (decision.kind) {
        case 'reconcileByQuery':
          this.phase = 'awaitingIndex';
          this.lastOutcomeCode = admission === 'accepted' ? 'accepted' : 'pending';
          break;
        case 'queryImmediately':
          this.phase = 'resolving';
          this.lastOutcomeCode = 'already-exists-query-now';
          this.needsImmediateQuery = true;
          break;
        case 'failClosed':
          this.phase = 'entitlementRepair';
          this.lastOutcomeCode = 'terminal-rejected';
          break;
        case 'preserveAndReconcile':
          // Exact record preserved; resolution comes from a fresh query.
          this.phase = 'awaitingIndex';
          this.lastOutcomeCode = 'submit-uncertain';
          break;
      }
    } finally {
      this.inFlight = false;
    }
    if (this.needsImmediateQuery && !this.cancelled) {
      this.needsImmediateQuery = false;
      await this.runFreshQuery('already-exists');
    }
  }

  private recordAttempt(record: LicencePendingTransactionRecord, admission: LicenceAdmissionOutcome): void {
    const evidence: LicencePendingAttemptEvidence = {
      at: new Date(this.ports.nowMs()).toISOString(),
      outcome:
        admission === 'accepted'
          ? 'accepted'
          : admission === 'pending'
            ? 'pending'
            : admission === 'alreadyExists'
              ? 'alreadyExists'
              : admission === 'terminalRejected'
                ? 'terminalRejected'
                : 'uncertain',
    };
    const updated: LicencePendingTransactionRecord = {
      ...record,
      recoveryState:
        admission === 'terminalRejected'
          ? 'unrecoverable'
          : record.recoveryState === 'sealed'
            ? admission === 'accepted'
              ? 'waitingAccepted'
              : 'waitingPending'
            : record.recoveryState,
      attemptEvidence: [...record.attemptEvidence, evidence],
    };
    this.ports.savePending(updated);
    this.pendingRecord = updated;
  }

  private retirePending(state: 'confirmed-indexed' | 'superseded'): void {
    if (this.pendingTransactionId !== null) {
      const loaded = this.ports.loadPending(this.pendingTransactionId);
      if (loaded.ok && loaded.record !== undefined) {
        const updated: LicencePendingTransactionRecord = {
          ...loaded.record,
          recoveryState: state === 'confirmed-indexed' ? 'confirmedIndexed' : 'superseded',
        };
        this.ports.savePending(updated);
      }
      this.ports.deletePending(this.pendingTransactionId);
    }
  }
}
