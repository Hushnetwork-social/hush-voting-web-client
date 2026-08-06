/**
 * FEAT-010 page-side browser-vault client (Task 7.3).
 *
 * The page's ONLY connection to the sealed SharedWorker authority. Owns the
 * handshake (exact protocol + build compatibility), operation dispatch with
 * epoch/operation scoping, out-of-band secret transfer (SecretSubmissionSink),
 * fresh-capability issuance, cancellation, and global-invalidation delivery.
 * A failed handshake never falls back to any other storage/transport.
 *
 * SECRET BOUNDARY: `submitSecret` transfers the secret to the authenticated
 * MessagePort and immediately clears the page-side copy; the secret never
 * enters React state, logs, telemetry, or history.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker protocol",
 * "Shared tabs"; FEAT-002 "Secret submission boundary"; FEAT-010 "Real
 * Composition"; AC-010-004/006/029.
 */

import {
  BROWSER_PROTOCOL_VERSION,
  type BrowserWorkerEvent,
  type CapabilityIssued,
  type OperationOutcome,
  type RuntimeConfigId,
} from '../contracts/protocol';

/** Application build identity (exact-match with the worker). */
export interface ClientAppIdentity {
  readonly appVersion: string;
}

/** Typed handshake outcome. */
export type HandshakeResult =
  | { readonly ok: true; readonly authorityEpoch: number; readonly session: { readonly state: string } }
  | { readonly ok: false; readonly reason: 'version-mismatch' | 'build-mismatch' | 'unsupported-config' | 'malformed' | 'transport' };

/** One dispatched operation result (typed, secret-free). */
export interface ClientOperationResult {
  readonly operationId: string;
  readonly outcome: string;
  readonly retryable: boolean;
  readonly allowedActions: readonly string[];
  readonly retryDeadlineMs?: number;
  readonly supportCode?: string;
  readonly payload?: unknown;
}

/** Closed operation kinds the page may dispatch (v2 vocabulary). */
export type ClientOperationKind =
  | 'provisionFromValidatedBundle'
  | 'unlockPassword'
  | 'changeDevicePassword'
  | 'verifyOnlineIdentity'
  | 'lockAll'
  | 'removeLocalUser'
  | 'createCandidate'
  | 'revealCandidateWords'
  | 'concealCandidate'
  | 'destroyCandidate'
  | 'deriveWordsCandidate'
  | 'importFileCandidate'
  | 'retainTransactionDigest'
  | 'submitIdentityTransaction'
  | 'promoteLifecycle'
  | 'inspectStartup';

/** Secret purposes accepted by the sink. */
export type SecretPurpose = 'devicePassword' | 'mnemonic' | 'filePassword' | 'fileBytes';

export interface BrowserVaultClientOptions {
  readonly workerUrl?: string;
  readonly appIdentity: ClientAppIdentity;
  readonly runtimeConfigId: RuntimeConfigId;
  readonly randomId?: (prefix: string) => string;
  readonly nowMs?: () => number;
  /** Injectable worker factory (tests use a fake port/worker). */
  readonly workerFactory?: (url: string) => { readonly port: MessagePortLike } | null;
}

/** Narrow MessagePort surface used by the client (test-injectable). */
export interface MessagePortLike {
  readonly postMessage: (message: unknown) => void;
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  readonly close?: () => void;
  readonly start?: () => void;
}

function b64urlFromBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Compute the worker bundle build digest (exact handshake identity). */
export async function computeWorkerBundleDigest(url: string, fetchImpl: typeof fetch = fetch): Promise<string | null> {
  try {
    const response = await fetchImpl(url, { cache: 'no-store' });
    const text = await response.text();
    if (!response.ok || text.length === 0) {
      return null;
    }
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('').slice(0, 12);
  } catch {
    return null;
  }
}

/** Diagnostic beacon (BroadcastChannel; never affects client behavior). */
export function emitClientBeacon(status: { readonly ok: boolean; readonly reason?: string; readonly stage: string }): void {
  try {
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel('hushvoting-vault-advisory');
      channel.postMessage({ kind: 'vault-client-diag', ...status });
      channel.close();
    }
  } catch {
    // diagnostic only
  }
}

/** Default worker factory (real browser SharedWorker). */
export function defaultWorkerFactory(url: string): { readonly port: MessagePortLike } | null {
  try {
    if (typeof SharedWorker === 'undefined') {
      return null;
    }
    const worker = new SharedWorker(url, { type: 'module', name: 'hushvoting-vault-authority' });
    worker.port.start();
    return { port: worker.port as unknown as MessagePortLike };
  } catch {
    return null;
  }
}

/**
 * The page-side vault client. One instance per tab; the SharedWorker
 * authority is shared across tabs by construction.
 */
export class BrowserVaultClient {
  private readonly workerUrl: string;
  private readonly appIdentity: ClientAppIdentity;
  private readonly runtimeConfigId: RuntimeConfigId;
  private readonly randomId: (prefix: string) => string;
  private readonly nowMs: () => number;
  private readonly workerFactory: (url: string) => { readonly port: MessagePortLike } | null;

  private port: MessagePortLike | null = null;
  private clientChannel: string | null = null;
  private authorityEpoch = 0;
  private connected = false;
  private readonly pending = new Map<string, (result: ClientOperationResult) => void>();
  private pendingCapabilityResolvers: Array<(issued: CapabilityIssued) => void> = [];
  private invalidationHandler: ((reason: string) => void) | null = null;
  private inFlightConnect: Promise<HandshakeResult> | null = null;
  /** Secret transfers queued per operation id (posted BEFORE the operation). */
  private readonly pendingSecretPosts = new Map<string, Promise<void>>();

  constructor(options: BrowserVaultClientOptions) {
    this.workerUrl = options.workerUrl ?? '/workers/vault-shared-worker.js';
    this.appIdentity = options.appIdentity;
    this.runtimeConfigId = options.runtimeConfigId;
    this.randomId = options.randomId ?? ((prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`);
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.workerFactory = options.workerFactory ?? defaultWorkerFactory;
  }

  /** True once the handshake succeeded and operations may dispatch. */
  isConnected(): boolean {
    return this.connected && this.port !== null;
  }

  /** Current authority epoch (safe). */
  epoch(): number {
    return this.authorityEpoch;
  }

  /** Connect and handshake. Never falls back on failure. */
  connect(): Promise<HandshakeResult> {
    if (this.connected) {
      return Promise.resolve({ ok: true, authorityEpoch: this.authorityEpoch, session: { state: 'connected' } });
    }
    if (this.inFlightConnect !== null) {
      return this.inFlightConnect;
    }
    this.inFlightConnect = this.performConnect().finally(() => {
      this.inFlightConnect = null;
    });
    return this.inFlightConnect;
  }

  private async performConnect(): Promise<HandshakeResult> {
    // Exact build identity: digest the served worker bundle (the worker does
    // the same over its own URL); a mismatch rejects the handshake.
    const buildDigest = await computeWorkerBundleDigest(this.workerUrl);
    if (buildDigest === null) {
      emitClientBeacon({ ok: false, reason: 'digest-unavailable', stage: 'connect' });
      return { ok: false, reason: 'transport' };
    }
    const created = this.workerFactory(this.workerUrl);
    if (created === null) {
      emitClientBeacon({ ok: false, reason: 'worker-creation-failed', stage: 'connect' });
      return { ok: false, reason: 'transport' };
    }
    this.port = created.port;
    this.clientChannel = this.randomId('chan-');

    const accepted = new Promise<HandshakeResult>((resolve) => {
      const port = this.port;
      if (port === null) {
        resolve({ ok: false, reason: 'transport' });
        return;
      }
      port.onmessage = (event) => {
        const message = event.data as BrowserWorkerEvent | null;
        if (typeof message !== 'object' || message === null) {
          return;
        }
        if (!this.connected && message.kind === 'handshake-accepted' && message.clientChannel === this.clientChannel) {
          this.authorityEpoch = message.authorityEpoch;
          this.connected = true;
          resolve({ ok: true, authorityEpoch: message.authorityEpoch, session: message.session });
        } else if (!this.connected && message.kind === 'handshake-rejected') {
          resolve({ ok: false, reason: message.reason });
        }
        this.handleWorkerEvent(event);
      };
    });

    const handshake = {
      kind: 'handshake',
      protocolVersion: BROWSER_PROTOCOL_VERSION,
      appVersion: this.appIdentity.appVersion,
      buildDigest,
      clientChannel: this.clientChannel,
      runtimeConfigId: this.runtimeConfigId,
    };
    this.port.postMessage(handshake);
    const result = await accepted;
    emitClientBeacon({ ok: result.ok, reason: result.ok ? undefined : result.reason, stage: 'handshake' });
    return result;
  }

  /** Register the global-invalidation handler (Lock/removal/takeover). */
  onInvalidation(handler: (reason: string) => void): void {
    this.invalidationHandler = handler;
  }

  /** Dispatch one operation; resolves on the matching typed outcome.
   * A caller-supplied `operationId` lets SecretSubmissionSink transfers be
   * keyed to the SAME operation the worker consumes. */
  async dispatch(operation: ClientOperationKind, payload?: Readonly<Record<string, unknown>>, freshCapabilityId?: string, operationId?: string): Promise<ClientOperationResult> {
    if (!this.connected || this.port === null || this.clientChannel === null) {
      // Auto-reconnect: the authority may have invalidated the epoch (e.g.
      // the machine cancels completed actors, which bumps the worker epoch).
      const handshake = await this.connect();
      if (!handshake.ok) {
        return { operationId: '', outcome: 'TRANSPORT_UNAVAILABLE', retryable: false, allowedActions: [] };
      }
    }
    const resolvedOperationId = operationId ?? this.randomId('op-');
    // The operation must never reach the worker before its secret transfers.
    await (this.pendingSecretPosts.get(resolvedOperationId) ?? Promise.resolve());
    this.pendingSecretPosts.delete(resolvedOperationId);
    const message = {
      kind: 'operation',
      operation,
      operationVersion: 1,
      clientChannel: this.clientChannel,
      authorityEpoch: this.authorityEpoch,
      operationId: resolvedOperationId,
      ...(payload !== undefined && payload !== null && Object.keys(payload).length > 0 ? { payload } : {}),
      ...(freshCapabilityId !== undefined ? { freshCapabilityId } : {}),
    };
    return new Promise<ClientOperationResult>((resolve) => {
      this.pending.set(resolvedOperationId, resolve);
      this.port?.postMessage(message);
    });
  }

  /** Cancel an in-flight operation (epoch invalidation is authority-owned). */
  cancel(operationId: string): void {
    if (!this.connected || this.port === null || this.clientChannel === null) {
      return;
    }
    this.port.postMessage({ kind: 'cancel', operationId, clientChannel: this.clientChannel, authorityEpoch: this.authorityEpoch });
  }

  /**
   * SECRET SUBMISSION SINK: transfer a secret out-of-band to the
   * authenticated port and clear the page-side copy immediately.
   */
  submitSecret(operationId: string, purpose: SecretPurpose, value: string | Uint8Array): void {
    const encoded = typeof value === 'string' ? value : b64urlFromBytes(value);
    const post = (): void => {
      this.port?.postMessage({
        kind: 'secret-transfer',
        operationId,
        clientChannel: this.clientChannel ?? '',
        authorityEpoch: this.authorityEpoch,
        purpose,
        value: encoded,
      });
    };
    const chain = async (): Promise<void> => {
      if (!this.connected || this.port === null || this.clientChannel === null) {
        // Auto-reconnect: the machine cancels completed actors, which bumps
        // the worker epoch; the secret must still reach the authority.
        const handshake = await this.connect();
        if (!handshake.ok) {
          return;
        }
      }
      post();
    };
    // Chain behind earlier transfers for the same operation so the worker
    // always receives every secret BEFORE the operation that consumes it.
    const previous = this.pendingSecretPosts.get(operationId) ?? Promise.resolve();
    const chained = previous.then(chain);
    this.pendingSecretPosts.set(operationId, chained);
  }

  /** Request a fresh one-use purpose-bound capability (≤60 s). */
  async issueCapability(purpose: 'provision' | 'changePassword' | 'removeLocalUser' | 'revealMnemonic' | 'exportEncryptedFile'): Promise<CapabilityIssued> {
    if (!this.connected || this.port === null || this.clientChannel === null) {
      // Auto-reconnect (the machine cancels completed actors, which bumps the
      // worker epoch and drops the client connection).
      const handshake = await this.connect();
      if (!handshake.ok) {
        throw new Error('vault client not connected');
      }
    }
    return new Promise<CapabilityIssued>((resolve) => {
      this.pendingCapabilityResolvers.push(resolve);
      this.port?.postMessage({
        kind: 'issue-capability',
        purpose,
        clientChannel: this.clientChannel,
        authorityEpoch: this.authorityEpoch,
      });
    });
  }

  /** Send a lifecycle signal (best-effort). */
  lifecycle(signal: 'pagehide' | 'visibility-hidden' | 'disconnect' | 'heartbeat'): void {
    if (!this.connected || this.port === null || this.clientChannel === null) {
      return;
    }
    this.port.postMessage({ kind: 'lifecycle', signal, clientChannel: this.clientChannel, authorityEpoch: this.authorityEpoch });
  }

  /** Close the connection (pagehide/disconnect). */
  close(): void {
    this.lifecycle('disconnect');
    if (this.port?.close) {
      try {
        this.port.close();
      } catch {
        // ignore
      }
    }
    this.port = null;
    this.connected = false;
  }

  private handleWorkerEvent(event: { readonly data: unknown }): void {
    const message = event.data as BrowserWorkerEvent | null;
    if (typeof message !== 'object' || message === null) {
      return;
    }
    switch (message.kind) {
      case 'handshake-accepted':
        this.authorityEpoch = message.authorityEpoch;
        this.connected = true;
        break;
      case 'operation-outcome': {
        const outcome = message as OperationOutcome;
        if (outcome.clientChannel !== this.clientChannel) {
          return;
        }
        const resolve = this.pending.get(outcome.operationId);
        if (resolve) {
          this.pending.delete(outcome.operationId);
          resolve({
            operationId: outcome.operationId,
            outcome: outcome.outcome,
            retryable: outcome.retryable,
            allowedActions: outcome.allowedActions,
            ...(outcome.retryDeadlineMs !== undefined ? { retryDeadlineMs: outcome.retryDeadlineMs } : {}),
            ...(outcome.supportCode !== undefined ? { supportCode: outcome.supportCode } : {}),
            ...(outcome.payload !== undefined ? { payload: outcome.payload } : {}),
          });
        }
        break;
      }
      case 'capability-issued': {
        const issued = message as CapabilityIssued;
        if (issued.clientChannel !== this.clientChannel) {
          return;
        }
        const resolve = this.pendingCapabilityResolvers.shift();
        resolve?.(issued);
        break;
      }
      case 'global-invalidation': {
        this.authorityEpoch = message.authorityEpoch;
        this.connected = false;
        for (const resolve of this.pending.values()) {
          resolve({ operationId: '', outcome: 'AUTHORITY_INVALIDATED', retryable: false, allowedActions: [] });
        }
        this.pending.clear();
        this.invalidationHandler?.(message.reason);
        break;
      }
      case 'handshake-rejected':
        // Keep the connection closed; caller observes the handshake result.
        break;
    }
  }
}

/** Typed operation helpers for the adapters (never secret-bearing). */
export const clientExports = { b64urlFromBytes, computeWorkerBundleDigest };
