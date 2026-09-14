/**
 * FEAT-016 Tasks 6.7/6.8 — entitlement bootstrap bridge (page side).
 *
 * The composition bridge that drives the SharedWorker licence session from
 * the ROOT state machine and React lifecycle — the ONLY page-side owner of
 * the bootstrap control flow. It:
 *   - observes the adapter projection and starts exactly one bootstrap
 *     session when the compound `authenticated` gate enters resolving;
 *   - forwards safe progress from the authority to the machine as
 *     epoch-scoped ENTITLEMENT.STAGE events (never granting protected
 *     rendering by itself — the machine and adapter own that boundary);
 *   - pushes eligibility (foreground/connectivity) to the authority loop;
 *   - handles INTENT.ENTITLEMENT_RETRY (Retry → exact resubmission;
 *     recoverable states → fresh query recovery);
 *   - maps a forced-lock outcome (double UNAUTHENTICATED) onto the real
 *     session Lock path (worker wipe + locked root) and gates the workspace
 *     synchronously on offline and revalidation triggers.
 *
 * React never signs, journals, polls, or stores anything; page code imports
 * only safe snapshots. Native targets never construct this bridge (the
 * target composition selects native operations or fails closed — no Browser/
 * BFF fallback).
 *
 * Normative source: FEAT-016 FeatureDescription "Root State-Machine
 * Contract", "Timing, Polling, and Connectivity", "Active-Session
 * Revalidation and Expiry"; Task 6.7 behavior spec.
 */

import type { BrowserVaultClient, ClientOperationResult, LicenceProgress } from '../../browser-vault/production/client';
import type { AuthAdapter, AuthRenderProjection } from '../react/adapter';
import type { ConnectivityStateCode, EntitlementStageCode } from '../types';
import type { AuthIntent } from '../types';
import type { LicenceRevalidationTrigger } from '../../licensing/session-contract';
import { isLicenceRevalidationTrigger } from '../../licensing/session-contract';

/**
 * FEAT-017 page-safe licence workspace intents the root composition may
 * dispatch. Every intent is routed to the SAME authority op vocabulary the
 * entitlement bootstrap uses; the page never signs, journals, or constructs.
 */
export type LicenceWorkspaceIntent =
  /** Account/options entry → fresh signed query (never stale display). */
  | { readonly type: 'LICENCE.REFRESH_ACCOUNT_ENTRY' }
  /** Authoritative FEAT-018 rejection → refresh + gate (no client auth). */
  | { readonly type: 'LICENCE.AUTHORITATIVE_REJECTION_REFRESH' }
  /** D0 exact retry of the sealed operation. */
  | { readonly type: 'LICENCE.RETRY_EXACT' }
  /** C0 activation of one validated server plan handle. */
  | { readonly type: 'LICENCE.ACTIVATE'; readonly targetPlanId: string }
  /** R0/N1 acknowledgement (clears the one-shot terminal outcome/notice). */
  | { readonly type: 'LICENCE.ACKNOWLEDGE_OUTCOME' };

/** Map a licence workspace intent to the closed client dispatch payload. */
export function licenceIntentToDispatch(
  intent: LicenceWorkspaceIntent,
): { readonly operation: string; readonly payload?: Record<string, unknown> } | null {
  switch (intent.type) {
    case 'LICENCE.REFRESH_ACCOUNT_ENTRY':
      return { operation: 'licenceBootstrapControl', payload: { control: 'revalidate', trigger: 'account-entry' } };
    case 'LICENCE.AUTHORITATIVE_REJECTION_REFRESH':
      return { operation: 'licenceBootstrapControl', payload: { control: 'revalidate', trigger: 'authoritative-rejection' } };
    case 'LICENCE.RETRY_EXACT':
      return { operation: 'licenceBootstrapControl', payload: { control: 'retry' } };
    case 'LICENCE.ACTIVATE':
      return { operation: 'licenceUpgradeConfirm', payload: { targetPlanId: intent.targetPlanId } };
    case 'LICENCE.ACKNOWLEDGE_OUTCOME':
      return { operation: 'licenceUpgradeAcknowledge' };
  }
}

/** Connectivity inputs forwarded to the authority loop (closed vocabulary). */
export type BridgeConnectivityInput = 'online' | 'offline' | 'paused' | 'reconnecting';

/** Closed mapping from the machine connectivity code to the loop input. */
export function connectivityToBridgeInput(state: ConnectivityStateCode): BridgeConnectivityInput {
  switch (state) {
    case 'paused':
      return 'paused';
    case 'offline':
      return 'offline';
    case 'reconnecting':
      return 'reconnecting';
    case 'online':
    case 'unknown':
    default:
      return 'online';
  }
}

/** Coordinator phase → machine entitlement stage (lockedOut is special). */
export function stageForPhase(phase: string): EntitlementStageCode | 'lockedOut' | null {
  switch (phase) {
    case 'resolving':
      return 'entitlementResolving';
    case 'baselineSigning':
      return 'baselineSigning';
    case 'baselineSubmitting':
      return 'baselineSubmitting';
    case 'awaitingIndex':
      return 'awaitingIndex';
    case 'confirmationDelayed':
      return 'confirmationDelayed';
    case 'entitlementUnavailable':
      return 'entitlementUnavailable';
    case 'entitlementUnsupported':
      return 'entitlementUnsupported';
    case 'entitlementRepair':
      return 'entitlementRepair';
    case 'entitlementReady':
      return 'entitlementReady';
    case 'lockedOut':
      return 'lockedOut';
    default:
      return null;
  }
}

/** Retry mapping for the current machine stage (closed). */
export function controlKindForStage(stage: EntitlementStageCode | null): 'retry' | 'recover' | null {
  switch (stage) {
    case 'confirmationDelayed':
      return 'retry'; // exact sealed transaction resubmission
    case 'entitlementUnavailable':
    case 'entitlementRepair':
    case 'entitlementUnsupported':
      return 'recover'; // fresh-query recovery
    default:
      return null;
  }
}

/**
 * Target-aware entitlement authority plan. Web selects the SharedWorker+BFF
 * path; recognized native targets select closed native operations when the
 * qualified native licence surface is present and FAIL CLOSED when it is
 * absent or mismatched — no Browser worker, IndexedDB, BFF, WebView signing,
 * or synthetic provider fallback is ever selected for a native target.
 */
export interface EntitlementAuthorityInput {
  readonly targetClass: 'web' | 'ubuntu' | 'android';
  readonly hasNativeLicenceOperations: boolean;
}

export type EntitlementAuthorityPlan =
  | { readonly authority: 'browser-sharedworker-bff'; readonly native: false }
  | { readonly authority: 'native'; readonly native: true }
  | { readonly authority: 'fail-closed'; readonly native: true };

export function resolveEntitlementAuthorityForTarget(input: EntitlementAuthorityInput): EntitlementAuthorityPlan | null {
  switch (input.targetClass) {
    case 'web':
      return { authority: 'browser-sharedworker-bff', native: false };
    case 'ubuntu':
    case 'android':
      return input.hasNativeLicenceOperations
        ? { authority: 'native', native: true }
        : { authority: 'fail-closed', native: true };
    default:
      return null;
  }
}

/** One entitlement op outcome on the page (never secret-bearing). */
export interface EntitlementStepOutcome {
  readonly ok: boolean;
  readonly reason?: string;
  readonly phase?: string;
}

export interface EntitlementBridgeDependencies {
  readonly adapter: AuthAdapter;
  readonly client: BrowserVaultClient;
  readonly networkBinding: string;
  /** Real session Lock path (worker wipe + machine Lock), reused by forced lock. */
  readonly lockSession: () => Promise<boolean>;
  /** Injectable foreground source (tests). */
  readonly isForegrounded?: () => boolean;
  /** Injectable visibility subscription (tests). */
  readonly subscribeVisibility?: (handler: () => void) => () => void;
}

const parseStepOutcome = (result: ClientOperationResult): EntitlementStepOutcome => {
  if (result.outcome !== 'OK') {
    const reason =
      typeof result.payload === 'object' && result.payload !== null
        ? ((result.payload as { reason?: string }).reason ?? 'authority-unavailable')
        : 'authority-unavailable';
    return { ok: false, reason };
  }
  const payload = result.payload as { ok?: boolean; reason?: string; snapshot?: { phase?: string } } | undefined;
  return {
    ok: payload?.ok !== false,
    reason: payload?.reason,
    phase: payload?.snapshot?.phase,
  };
};

/**
 * One page-side entitlement bootstrap bridge. Idempotent start: while a
 * start is in flight (or already running) duplicate starts reuse the
 * authority session and never create a second query/submission loop.
 */
export class EntitlementBridge {
  private running = false;
  private starting: Promise<void> | null = null;
  private lastConnectivity: BridgeConnectivityInput | null = null;
  private foregrounded = true;
  private unsubProgress: (() => void) | null = null;
  private unsubVisibility: (() => void) | null = null;
  /** FEAT-017 page-side mirror of the last safe licence progress. */
  private lastLicenceProgress: LicenceProgress | null = null;
  private readonly licenceWorkspaceListeners = new Set<(progress: LicenceProgress) => void>();

  constructor(private readonly deps: EntitlementBridgeDependencies) {}

  get isRunning(): boolean {
    return this.running;
  }

  /**
   * FEAT-017 page-side safe licence facts (projection + upgrade operation +
   * one-shot notification eligibility). NULL until the first authority
   * progress broadcast arrives; never carries exact bytes/journal state.
   */
  licenceFacts(): LicenceProgress | null {
    return this.lastLicenceProgress;
  }

  /** Subscribe to safe licence progress (root workspace composition). */
  subscribeLicenceWorkspace(handler: (progress: LicenceProgress) => void): () => void {
    this.licenceWorkspaceListeners.add(handler);
    if (this.lastLicenceProgress !== null) {
      handler(this.lastLicenceProgress);
    }
    return () => this.licenceWorkspaceListeners.delete(handler);
  }

  /**
   * FEAT-017 workspace intent routing. Confirmed-upgrade activation and the
   * authoritative-rejection refresh are only routed while the authority
   * session is running (authenticated + ready). Returned boolean tells the
   * root whether the intent was accepted by the licence authority.
   */
  handleLicenceWorkspaceIntent(intent: LicenceWorkspaceIntent): boolean {
    if (!this.running) {
      return false;
    }
    const mapped = licenceIntentToDispatch(intent);
    if (mapped === null) {
      return false;
    }
    const stage = this.deps.adapter.snapshot().entitlementStage;
    if (
      intent.type === 'LICENCE.REFRESH_ACCOUNT_ENTRY' ||
      intent.type === 'LICENCE.AUTHORITATIVE_REJECTION_REFRESH'
    ) {
      if (stage !== 'entitlementReady') {
        return false;
      }
      // Synchronous gate before the fresh query (never stale presentation).
      this.deps.adapter.sendEvent({ type: 'ENTITLEMENT.RESET' } as never);
    }
    void this.dispatchLicenceOp(mapped.operation, mapped.payload);
    return true;
  }

  /** Subscribe to authority progress + lifecycle visibility. */
  start(): void {
    if (this.unsubProgress === null) {
      const unsub = this.deps.client.onLicenceProgress((progress) => {
        this.handleProgress(progress);
      });
      this.unsubProgress = unsub;
    }
    if (this.unsubVisibility === null && this.deps.subscribeVisibility !== undefined) {
      this.unsubVisibility = this.deps.subscribeVisibility(() => {
        const visible = this.deps.isForegrounded?.() ?? true;
        if (visible !== this.foregrounded) {
          this.foregrounded = visible;
          void this.pushEligibility();
        }
        if (visible && this.running) {
          const stage = this.deps.adapter.snapshot().entitlementStage;
          if (stage === 'entitlementReady') {
            this.revalidate('foreground');
          }
        }
      });
    }
  }

  stop(): void {
    this.unsubProgress?.();
    this.unsubProgress = null;
    this.unsubVisibility?.();
    this.unsubVisibility = null;
    this.running = false;
    this.starting = null;
    this.lastLicenceProgress = null;
    this.licenceWorkspaceListeners.clear();
  }

  /** Page intent routing (INTENT.ENTITLEMENT_RETRY and friends). */
  handleIntent(intent: AuthIntent): boolean {
    if (!this.running) {
      return false;
    }
    if (intent.type === 'INTENT.ENTITLEMENT_RETRY') {
      const stage = this.deps.adapter.snapshot().entitlementStage;
      const control = controlKindForStage(stage);
      if (control !== null) {
        void this.dispatchControl(control, 'retry-user');
        return true;
      }
    }
    return false;
  }

  /** Revalidation trigger entry (foreground/expiry/account-entry/...). */
  revalidate(trigger: LicenceRevalidationTrigger): void {
    if (!isLicenceRevalidationTrigger(trigger) || !this.running) {
      return;
    }
    const stage = this.deps.adapter.snapshot().entitlementStage;
    if (stage === 'entitlementReady') {
      // Synchronous gate before the fresh query (never render from stale truth).
      this.deps.adapter.sendEvent({ type: 'ENTITLEMENT.RESET' } as never);
    }
    void this.dispatchControl('revalidate', trigger);
  }

  /** Observe the latest adapter projection (machine-driven transitions). */
  observe(projection: AuthRenderProjection): void {
    if (projection.authState !== 'authenticated' || projection.entitlementRequired === false) {
      if (this.running) {
        // Lock/logout/replacement/invalidation: session teardown is owned by
        // the authority; this bridge simply stops driving.
        this.running = false;
        this.starting = null;
      }
      return;
    }
    const input = connectivityToBridgeInput(projection.connectivity);
    if (input !== this.lastConnectivity) {
      this.lastConnectivity = input;
      if (this.running) {
        void this.pushEligibility();
        if (
          input === 'offline' &&
          projection.entitlementStage === 'entitlementReady'
        ) {
          // Temporary disconnection can never keep the workspace mounted.
          this.deps.adapter.sendEvent({ type: 'ENTITLEMENT.RESET' } as never);
        }
      }
    }
    if (!this.running && projection.entitlementStage === 'entitlementResolving') {
      this.ensureStarted();
    }
  }

  /** Safe progress from the authority → epoch-scoped machine events. */
  private handleProgress(progress: LicenceProgress): void {
    if (!this.running) {
      return;
    }
    const projection = this.deps.adapter.snapshot();
    if (projection.authState !== 'authenticated') {
      return; // stale progress after Lock can never restore access
    }
    // FEAT-017 page mirror: safe facts only, epoch-guarded by the caller.
    this.lastLicenceProgress = progress;
    for (const listener of this.licenceWorkspaceListeners) {
      try {
        listener(progress);
      } catch {
        // A failing listener never breaks authority delivery.
      }
    }
    const stage = stageForPhase(progress.phase);
    if (stage === null) {
      return;
    }
    if (stage === 'lockedOut') {
      // Second consecutive UNAUTHENTICATED: real session Lock + guidance.
      void this.deps.lockSession();
      return;
    }
    this.deps.adapter.sendEvent({
      type: 'ENTITLEMENT.STAGE',
      stage,
      epoch: projection.sessionEpoch,
    } as never);
  }

  private ensureStarted(): void {
    if (this.starting !== null || this.running) {
      return;
    }
    this.starting = this.startBootstrap().finally(() => {
      this.starting = null;
    });
    void this.starting;
  }

  private async startBootstrap(): Promise<void> {
    const projection = this.deps.adapter.snapshot();
    if (projection.authState !== 'authenticated' || projection.entitlementRequired === false) {
      return;
    }
    this.running = true;
    await this.pushEligibility();
    try {
      const result = await this.deps.client.dispatch('licenceBootstrapStart', {
        networkBinding: this.deps.networkBinding,
      });
      const outcome = parseStepOutcome(result);
      if (!outcome.ok) {
        // Transient/unavailable start: leave the machine at the resolving
        // gate; the next connectivity/lifecycle tick retries (bounded).
        this.running = false;
        this.starting = null;
        return;
      }
      if (outcome.phase !== undefined) {
        const stage = stageForPhase(outcome.phase);
        if (stage !== null && stage !== 'lockedOut') {
          const current = this.deps.adapter.snapshot();
          if (current.authState === 'authenticated') {
            this.deps.adapter.sendEvent({
              type: 'ENTITLEMENT.STAGE',
              stage,
              epoch: current.sessionEpoch,
            } as never);
          }
        }
      }
    } catch {
      this.running = false;
      this.starting = null;
    }
  }

  private async pushEligibility(): Promise<void> {
    if (!this.running) {
      return;
    }
    const projection = this.deps.adapter.snapshot();
    const connectivity = connectivityToBridgeInput(projection.connectivity);
    this.lastConnectivity = connectivity;
    const payload: { foreground?: boolean; connectivity?: BridgeConnectivityInput } = {};
    if (this.foregrounded !== undefined) {
      payload.foreground = this.foregrounded;
    }
    payload.connectivity = connectivity;
    try {
      await this.deps.client.dispatch('licenceBootstrapEligibility', payload);
    } catch {
      // Best-effort eligibility push; the next projection change retries.
    }
  }

  private async dispatchControl(control: 'retry' | 'recover' | 'revalidate', trigger: string): Promise<void> {
    if (!this.running) {
      return;
    }
    const payload: { control: string; trigger?: string } = { control };
    if (control === 'revalidate') {
      payload.trigger = trigger;
    }
    try {
      const result = await this.deps.client.dispatch('licenceBootstrapControl', payload);
      const outcome = parseStepOutcome(result);
      if (outcome.ok && outcome.phase !== undefined) {
        const stage = stageForPhase(outcome.phase);
        const projection = this.deps.adapter.snapshot();
        if (stage !== null && stage !== 'lockedOut' && projection.authState === 'authenticated') {
          this.deps.adapter.sendEvent({
            type: 'ENTITLEMENT.STAGE',
            stage,
            epoch: projection.sessionEpoch,
          } as never);
        }
      }
    } catch {
      // A failed control never fabricates a state; next trigger retries.
    }
  }

  /** Dispatch one FEAT-017 licence op to the closed authority vocabulary. */
  private async dispatchLicenceOp(operation: string, payload: Record<string, unknown> | undefined): Promise<void> {
    if (!this.running) {
      return;
    }
    try {
      const result = await this.deps.client.dispatch(operation as never, payload);
      const outcome = parseStepOutcome(result);
      if (outcome.ok && outcome.phase !== undefined) {
        const stage = stageForPhase(outcome.phase);
        const projection = this.deps.adapter.snapshot();
        if (stage !== null && stage !== 'lockedOut' && projection.authState === 'authenticated') {
          this.deps.adapter.sendEvent({
            type: 'ENTITLEMENT.STAGE',
            stage,
            epoch: projection.sessionEpoch,
          } as never);
        }
      }
    } catch {
      // A failed op never fabricates a state; the loop reconciles next tick.
    }
  }
}
