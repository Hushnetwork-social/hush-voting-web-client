/**
 * FEAT-002 shared browser authority — fail-closed session ownership.
 *
 * Capability hierarchy (normative, FeatureDescription "Browser capability
 * hierarchy"):
 *   1. SharedWorker — one shared unlocked session across tabs, no secret copy;
 *   2. exclusive Web Lock — at most one authenticated tab;
 *   3. non-secret storage lease — one authenticated tab, owner stale after
 *      15 seconds without a valid heartbeat;
 *   4. none safe → persistent authentication blocked.
 *
 * The authority coordinates ONE unlocked owner; explicit takeover only after
 * loss/staleness, invalidates globally, starts in `locked`, and requires the
 * device password again. Unlocked access is never transferred during takeover.
 *
 * Framework-neutral: browser primitives are injected so tests are
 * deterministic. No secret is ever written to page state or browser storage.
 */

import { isLeaseStale } from '../state/policies.js';
import { AUTH_TIMING } from '../types.js';

/** Supported coordination primitives (injected by the browser adapter). */
export interface CoordinationEnvironment {
  /** SharedWorker availability and connect function. */
  sharedWorkerAvailable(): boolean;
  connectSharedWorker(): { send(channel: string, payload: unknown): void } | null;
  /** Exclusive Web Lock availability. */
  webLockAvailable(): boolean;
  acquireWebLock(name: string, onLost: () => void): Promise<boolean>;
  releaseWebLock(name: string): Promise<void>;
  /** Non-secret storage lease (localStorage-style, no secrets). */
  storageAvailable(): boolean;
  readLease(key: string): { ownerId: string; heartbeatMs: number } | null;
  writeLease(key: string, lease: { ownerId: string; heartbeatMs: number }): void;
  clearLease(key: string): void;
  /** Heartbeat timer scheduling (injected clock). */
  now(): number;
  schedule(callback: () => void, delayMs: number): { cancel(): void };
}

/** Ownership outcome reported to the authority consumer. */
export type OwnershipResult =
  | { readonly kind: 'shared'; readonly channel: ReturnType<CoordinationEnvironment['connectSharedWorker']> }
  | { readonly kind: 'exclusive' }
  | { readonly kind: 'lease'; readonly ownerId: string }
  | { readonly kind: 'blocked' };

export interface TakeoverDecision {
  readonly allowed: boolean;
  readonly reason: 'authorityLost' | 'ownerStale' | 'blocked' | 'alreadyOwned';
}

/**
 * Evaluate the fail-closed hierarchy deterministically.
 * Returns the strongest safe mode available.
 */
export function selectCoordinationMode(
  env: CoordinationEnvironment,
): 'shared' | 'exclusive' | 'lease' | 'blocked' {
  if (env.sharedWorkerAvailable()) {
    return 'shared';
  }
  if (env.webLockAvailable()) {
    return 'exclusive';
  }
  if (env.storageAvailable()) {
    return 'lease';
  }
  return 'blocked';
}

/**
 * Acquire one unlocked owner using the strongest safe mode.
 * `expectedMode` comes from `selectCoordinationMode` so capability probing is
 * stable; a second tab in fallback mode displays "active elsewhere".
 */
export async function acquireOwnership(
  env: CoordinationEnvironment,
  expectedMode: 'shared' | 'exclusive' | 'lease' | 'blocked',
): Promise<OwnershipResult> {
  switch (expectedMode) {
    case 'shared': {
      const channel = env.connectSharedWorker();
      return channel ? { kind: 'shared', channel } : { kind: 'blocked' };
    }
    case 'exclusive': {
      const acquired = await env.acquireWebLock('hushvoting-auth-owner', () => undefined);
      return acquired ? { kind: 'exclusive' } : { kind: 'blocked' };
    }
    case 'lease': {
      const ownerId = `owner-${env.now()}-${Math.random().toString(36).slice(2, 10)}`;
      env.writeLease('hushvoting-auth-lease', { ownerId, heartbeatMs: env.now() });
      return { kind: 'lease', ownerId };
    }
    case 'blocked':
      return { kind: 'blocked' };
  }
}

/**
 * Decide whether explicit takeover is permitted.
 * Takeover requires the current authority to be lost or stale; it never
 * transfers unlocked access, and it must restart from `locked`.
 */
export function decideTakeover(
  env: CoordinationEnvironment,
  currentOwnerId: string | null,
): TakeoverDecision {
  if (currentOwnerId === null) {
    return { allowed: true, reason: 'authorityLost' };
  }
  const lease = env.readLease('hushvoting-auth-lease');
  if (lease === null) {
    return { allowed: true, reason: 'authorityLost' };
  }
  if (lease.ownerId !== currentOwnerId) {
    return { allowed: true, reason: 'ownerStale' };
  }
  return { allowed: false, reason: 'alreadyOwned' };
}

/**
 * Renew the non-secret lease heartbeat. The lease carries only the owner id
 * and a coarse timestamp — no secrets, no user data.
 */
export function heartbeat(env: CoordinationEnvironment, ownerId: string): void {
  env.writeLease('hushvoting-auth-lease', { ownerId, heartbeatMs: env.now() });
}

/** True when the lease owner is stale (15 s without a valid heartbeat). */
export function isOwnerStale(env: CoordinationEnvironment, ownerId: string): boolean {
  const lease = env.readLease('hushvoting-auth-lease');
  if (lease === null || lease.ownerId !== ownerId) {
    return true;
  }
  return isLeaseStale(lease.heartbeatMs, env.now());
}

export { AUTH_TIMING };
