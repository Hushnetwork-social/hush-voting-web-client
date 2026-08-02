/**
 * FEAT-004 worker authority — strict handshake/dispatch, epochs, serialization.
 *
 * One reviewed authority source drives both the SharedWorker and the dedicated
 * worker entries. Every inbound message passes `validateClientMessage` before
 * dispatch; malformed/unknown/stale/wrong-channel/duplicate messages fail
 * closed with a typed safe result and never start a secret operation. Exactly
 * one active operation is allowed per authority; Lock/cancellation invalidates
 * the epoch; unacknowledged cleanup within the one-second bound forces cleanup
 * of the owning worker (injected `onForceCleanup`). Worker death always
 * projects Locked.
 *
 * Framework-neutral: no browser globals; primitives (clock, randomness, secret
 * operation execution, event delivery, force-cleanup) are injected so the
 * authority is deterministic in tests while the worker entries wire real
 * MessagePorts in Phase 6.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker hierarchy",
 * "Worker protocol", "Activity, visibility, and abandoned clients".
 */
import {
  BROWSER_PROTOCOL_VERSION,
  validateClientMessage,
  type BrowserClientMessage,
  type BrowserWorkerEvent,
  type OperationRequest,
} from '../contracts/protocol';
import {
  consumeFreshCapability,
  FRESH_CAPABILITY_REQUIRED_BY_OPERATION,
  issueFreshCapability,
  type AuthorityPhase,
  type FreshCapabilityPurpose,
  type FreshPasswordCapability,
} from './capabilities';

/** Authority-facing primitives (injected). */
export interface AuthorityEnvironment {
  readonly nowMs: () => number;
  readonly randomId: (prefix: string) => string;
  /** The authority's own exact build identity (bound by every handshake). */
  readonly appIdentity: { readonly appVersion: string; readonly buildDigest: string };
  /** Execute one approved operation inside the secret boundary. */
  readonly executeOperation: (request: OperationRequest, epoch: number) => Promise<{ readonly outcome: string; readonly retryable: boolean; readonly allowedActions: readonly string[]; readonly retryDeadlineMs?: number; readonly supportCode?: string }>;
  /** Deliver one event to one client channel. */
  readonly deliver: (clientChannel: string, event: BrowserWorkerEvent) => void;
  /** Broadcast a global invalidation to every connected client. */
  readonly broadcast: (event: BrowserWorkerEvent) => void;
  /** Bounded cleanup acknowledgement deadline (ms). */
  readonly cleanupBoundMs?: number;
  /** Forced cleanup of the owning worker when the bound cannot be proven. */
  readonly onForceCleanup: () => void;
}

export const DEFAULT_CLEANUP_BOUND_MS = 1000 as const;

export interface AuthoritySnapshot {
  readonly epoch: number;
  readonly phase: AuthorityPhase;
  readonly activeOperationId: string | null;
  readonly acceptedChannels: readonly string[];
}

/**
 * One secret authority. Owns the epoch, capability phases, per-channel
 * connections, fresh capabilities, operation serialization, and invalidation.
 */
export class WorkerAuthority {
  private epoch = 0;
  private phase: AuthorityPhase = 'locked';
  private activeOperationId: string | null = null;
  private readonly acceptedChannels = new Set<string>();
  private readonly freshCapabilities = new Map<string, FreshPasswordCapability>();
  private readonly env: AuthorityEnvironment;
  private readonly cleanupBoundMs: number;

  constructor(
    env: AuthorityEnvironment,
    initialPhase: AuthorityPhase = 'locked',
    initialEpoch = 1,
  ) {
    this.env = env;
    this.cleanupBoundMs = env.cleanupBoundMs ?? DEFAULT_CLEANUP_BOUND_MS;
    this.phase = initialPhase;
    this.epoch = initialEpoch;
  }

  snapshot(): AuthoritySnapshot {
    return {
      epoch: this.epoch,
      phase: this.phase,
      activeOperationId: this.activeOperationId,
      acceptedChannels: [...this.acceptedChannels],
    };
  }

  /** Handle one inbound message; returns the closed outcome code for diagnostics. */
  handle(message: unknown): { readonly accepted: boolean; readonly outcome: string } {
    const validated = validateClientMessage(message);
    if (validated === null) {
      return { accepted: false, outcome: 'MESSAGE_REJECTED' };
    }
    switch (validated.kind) {
      case 'handshake':
        return this.handleHandshake(validated);
      case 'operation':
        return this.handleOperation(validated);
      case 'cancel':
        return this.handleCancel(validated);
      case 'lifecycle':
        return this.handleLifecycle(validated);
    }
  }

  private handleHandshake(request: Extract<BrowserClientMessage, { kind: 'handshake' }>): { readonly accepted: boolean; readonly outcome: string } {
    if (request.protocolVersion !== BROWSER_PROTOCOL_VERSION) {
      this.env.deliver(request.clientChannel, { kind: 'handshake-rejected', protocolVersion: BROWSER_PROTOCOL_VERSION, reason: 'version-mismatch' });
      return { accepted: false, outcome: 'HANDSHAKE_VERSION_MISMATCH' };
    }
    // Exact application build compatibility (acceptance criterion 25): a mixed
    // page/worker build must never interop.
    if (request.appVersion !== this.env.appIdentity.appVersion || request.buildDigest !== this.env.appIdentity.buildDigest) {
      this.env.deliver(request.clientChannel, { kind: 'handshake-rejected', protocolVersion: BROWSER_PROTOCOL_VERSION, reason: 'build-mismatch' });
      return { accepted: false, outcome: 'HANDSHAKE_BUILD_MISMATCH' };
    }
    if (this.acceptedChannels.has(request.clientChannel)) {
      // Duplicate handshake on the same channel fails closed.
      this.env.deliver(request.clientChannel, { kind: 'handshake-rejected', protocolVersion: BROWSER_PROTOCOL_VERSION, reason: 'malformed' });
      return { accepted: false, outcome: 'HANDSHAKE_DUPLICATE_CHANNEL' };
    }
    this.acceptedChannels.add(request.clientChannel);
    this.env.deliver(request.clientChannel, {
      kind: 'handshake-accepted',
      protocolVersion: BROWSER_PROTOCOL_VERSION,
      appVersion: request.appVersion,
      buildDigest: request.buildDigest,
      clientChannel: request.clientChannel,
      authorityEpoch: this.epoch,
      operationId: this.env.randomId('op-'),
      session: { state: this.phase },
    });
    return { accepted: true, outcome: 'HANDSHAKE_ACCEPTED' };
  }

  private isKnownChannel(clientChannel: string): boolean {
    return this.acceptedChannels.has(clientChannel);
  }

  private handleOperation(request: OperationRequest): { readonly accepted: boolean; readonly outcome: string } {
    if (request.authorityEpoch !== this.epoch) {
      return { accepted: false, outcome: 'OPERATION_STALE_EPOCH' };
    }
    if (!this.isKnownChannel(request.clientChannel)) {
      return { accepted: false, outcome: 'OPERATION_UNKNOWN_CHANNEL' };
    }
    if (this.activeOperationId !== null) {
      return { accepted: false, outcome: 'OPERATION_BUSY' };
    }
    const requiredPurpose = FRESH_CAPABILITY_REQUIRED_BY_OPERATION[request.operation];
    if (requiredPurpose !== null) {
      const consumption = consumeFreshCapability(
        request.freshCapabilityId !== undefined ? (this.freshCapabilities.get(request.freshCapabilityId) ?? null) : null,
        { purpose: requiredPurpose, clientChannel: request.clientChannel, authorityEpoch: this.epoch, nowMs: this.env.nowMs() },
      );
      if (!consumption.ok) {
        return { accepted: false, outcome: `OPERATION_CAPABILITY_${consumption.reason.toUpperCase()}` };
      }
      this.freshCapabilities.set(consumption.capability.id, consumption.capability);
    }
    this.activeOperationId = request.operationId;
    void this.runOperation(request);
    return { accepted: true, outcome: 'OPERATION_STARTED' };
  }

  private async runOperation(request: OperationRequest): Promise<void> {
    // Stale/preempted operations (epoch advanced mid-flight) must not deliver
    // their outcome: the client already received a global invalidation.
    const startEpoch = this.epoch;
    try {
      const result = await this.env.executeOperation(request, this.epoch);
      if (this.epoch !== startEpoch) {
        return; // invalidated while running; outcome dropped
      }
      this.env.deliver(request.clientChannel, {
        kind: 'operation-outcome',
        operationId: request.operationId,
        clientChannel: request.clientChannel,
        outcome: result.outcome,
        retryable: result.retryable,
        allowedActions: result.allowedActions,
        ...(result.retryDeadlineMs !== undefined ? { retryDeadlineMs: result.retryDeadlineMs } : {}),
        ...(result.supportCode !== undefined ? { supportCode: result.supportCode } : {}),
      });
    } finally {
      if (this.activeOperationId === request.operationId) {
        this.activeOperationId = null;
      }
    }
  }

  private handleCancel(request: Extract<BrowserClientMessage, { kind: 'cancel' }>): { readonly accepted: boolean; readonly outcome: string } {
    if (!this.isKnownChannel(request.clientChannel) || request.authorityEpoch !== this.epoch) {
      return { accepted: false, outcome: 'CANCEL_REJECTED' };
    }
    this.invalidate('lock'); // cancel invalidates the operation AND the authority epoch
    return { accepted: true, outcome: 'CANCEL_ACCEPTED' };
  }

  private handleLifecycle(request: Extract<BrowserClientMessage, { kind: 'lifecycle' }>): { readonly accepted: boolean; readonly outcome: string } {
    if (!this.isKnownChannel(request.clientChannel) || request.authorityEpoch !== this.epoch) {
      return { accepted: false, outcome: 'LIFECYCLE_REJECTED' };
    }
    if (request.signal === 'disconnect') {
      this.acceptedChannels.delete(request.clientChannel);
    }
    return { accepted: true, outcome: 'LIFECYCLE_ACCEPTED' };
  }

  /** Issue a fresh capability for an approved purpose on a channel. */
  issueCapability(params: { readonly purpose: FreshCapabilityPurpose; readonly clientChannel: string }): FreshPasswordCapability | null {
    if (!this.isKnownChannel(params.clientChannel)) {
      return null;
    }
    const capability = issueFreshCapability({
      id: this.env.randomId('cap-'),
      purpose: params.purpose,
      clientChannel: params.clientChannel,
      authorityEpoch: this.epoch,
      nowMs: this.env.nowMs(),
    });
    this.freshCapabilities.set(capability.id, capability);
    return capability;
  }

  /** Set the authority phase (authority-owned transitions only). */
  setPhase(phase: AuthorityPhase): void {
    this.phase = phase;
  }

  /** Global invalidation: revoke everything, clear secrets, bump the epoch. */
  invalidate(reason: 'lock' | 'removal' | 'takeover' | 'update-mismatch' | 'authority-loss' | 'cleanup-failed'): void {
    this.epoch += 1;
    this.activeOperationId = null;
    this.freshCapabilities.clear();
    this.acceptedChannels.clear();
    this.env.broadcast({ kind: 'global-invalidation', authorityEpoch: this.epoch, reason });
  }

  /** Update-mismatch handling: no new capability, safe abort, global lock. */
  handleUpdateMismatch(): void {
    this.invalidate('update-mismatch');
  }
}
