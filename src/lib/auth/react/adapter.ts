/**
 * FEAT-002 thin React adapter — one bridge between React and the XState
 * authority. Framework-dependent by design (this is the ONLY place React
 * touches the machine).
 *
 * The adapter:
 * - owns one actor instance and its lifecycle;
 * - exposes typed intents (never raw events with secrets);
 * - projects the machine snapshot to render-safe state;
 * - enforces the synchronous protected-content boundary: protected rendering
 *   is permitted only when the snapshot is in `authenticated` with a current
 *   capability. React effects alone never determine protected access.
 *
 * Normative source: FeatureDescription "Protected-content boundary",
 * "State and actor ownership".
 */

import { useMemo, useSyncExternalStore } from 'react';
import { createActor, type Actor, type SnapshotFrom } from 'xstate';
import { authMachine, type AuthMachineEvent, type AuthMachineInput } from '../state/machine';
import type { AuthIntent, AuthStateCode, ConnectivityStateCode } from '../types';

/** Render-safe projection of the authority snapshot. */
export interface AuthRenderProjection {
  readonly authState: AuthStateCode;
  readonly connectivity: ConnectivityStateCode;
  /** True only when protected content may mount (authenticated + capability). */
  readonly protectedAccess: boolean;
  readonly safeIdentity: { alias: string; abbreviatedSigningAddress: string } | null;
  readonly outcomeCode: string | null;
  readonly supportCode: string | null;
  readonly onboardingKind: string | null;
}

function authStateFromValue(value: unknown): AuthStateCode {
  const auth = (value as { auth?: unknown }).auth;
  if (typeof auth === 'string') {
    return auth as AuthStateCode;
  }
  if (auth !== null && typeof auth === 'object') {
    const keys = Object.keys(auth as object);
    return (keys[0] ?? 'initializing') as AuthStateCode;
  }
  return 'initializing';
}

function connectivityFromValue(value: unknown): ConnectivityStateCode {
  const connectivity = (value as { connectivity?: unknown }).connectivity;
  return (typeof connectivity === 'string' ? connectivity : 'unknown') as ConnectivityStateCode;
}

type AuthSnapshot = SnapshotFrom<typeof authMachine>;

function projectSnapshot(snapshot: AuthSnapshot): AuthRenderProjection {
  const value = snapshot.value;
  const authState = authStateFromValue(value);
  const connectivity = connectivityFromValue(value);
  const context = (snapshot.context ?? {}) as {
    safeIdentity?: { alias: string; abbreviatedSigningAddress: string } | null;
    outcomeCode?: string | null;
    supportCode?: string | null;
    onboardingKind?: string | null;
  };
  return {
    authState,
    connectivity,
    // Synchronous capability boundary: only authenticated grants protected access.
    protectedAccess: authState === 'authenticated',
    safeIdentity: context.safeIdentity ?? null,
    outcomeCode: context.outcomeCode ?? null,
    supportCode: context.supportCode ?? null,
    onboardingKind: context.onboardingKind ?? null,
  };
}

/** Create the authority adapter and start it (convenience wrapper). */
export function createAuthAdapter(input: AuthMachineInput): AuthAdapter {
  return new AuthAdapter(input);
}

/** Adapter options (production composition wires the real secret sink). */
export interface AuthAdapterOptions {
  /** SecretSubmissionSink: direct secret transfer to the sealed authority. */
  readonly secretSink?: (operationId: string, secret: string) => void;
}

/** Thin adapter wrapping one actor instance. */
export class AuthAdapter {
  private readonly actor: Actor<typeof authMachine>;
  private cachedProjection: AuthRenderProjection | null = null;
  private readonly secretSink: ((operationId: string, secret: string) => void) | null;
  private activeUnlockOperationId: string | null = null;
  private pendingSecret: string | null = null;

  /** Build from machine input (production/composition path) or an existing actor (tests). */
  constructor(inputOrActor: AuthMachineInput | Actor<typeof authMachine>, options: AuthAdapterOptions = {}) {
    this.secretSink = options.secretSink ?? null;
    if ('send' in (inputOrActor as Actor<typeof authMachine>)) {
      this.actor = inputOrActor as Actor<typeof authMachine>;
    } else {
      this.actor = createActor(authMachine, { input: inputOrActor as AuthMachineInput });
      this.actor.start();
    }
    // Refresh the cached projection whenever the actor snapshot changes.
    this.actor.subscribe(() => {
      const snapshot = this.actor.getSnapshot();
      this.cachedProjection = projectSnapshot(snapshot);
      // Track the active unlock operation so the sink can address the secret
      // to the exact operation the sealed authority consumes.
      const context = (snapshot.context ?? {}) as { activeOperationId?: string | null };
      if (this.cachedProjection.authState === 'unlocking' && typeof context.activeOperationId === 'string') {
        this.activeUnlockOperationId = context.activeOperationId;
        // Flush a secret buffered before the operation id was known.
        if (this.pendingSecret !== null && this.secretSink !== null) {
          const secret = this.pendingSecret;
          this.pendingSecret = null;
          this.secretSink(this.activeUnlockOperationId, secret);
        }
      }
      // Connectivity signal: typed network outcomes drive the connectivity
      // region (offline stays retryable; exact success reports online).
      const outcome = this.cachedProjection.outcomeCode;
      const connectivity = this.cachedProjection.connectivity;
      if ((outcome === 'VERIFY_TIMEOUT' || outcome === 'VERIFY_NETWORK_UNAVAILABLE') && connectivity !== 'offline') {
        this.actor.send({ type: 'CONNECTIVITY.CHANGE', state: 'offline' });
      } else if (outcome === 'VERIFY_SUCCESS' && connectivity !== 'online') {
        this.actor.send({ type: 'CONNECTIVITY.CHANGE', state: 'online' });
      }
    });
  }

  /** Dispatch a typed intent. Intents never carry secrets. */
  send(intent: AuthIntent): void {
    this.actor.send(intent as AuthMachineEvent);
  }

  /**
   * Direct secret transfer channel (UI → secret authority). The secret is
   * handed to the downstream sink and NEVER enters the machine, React state,
   * logs, or telemetry. Downstream FEAT-003/004 wire the real sink; until
   * then the secret is discarded after the UI clears its input.
   */
  submitSecret(secret: string): void {
    if (this.secretSink !== null) {
      // The intent first: the machine transitions to `unlocking` and its
      // actor invokes the sealed authority, which issues the operation id
      // asynchronously. The secret is buffered and flushed by the snapshot
      // subscription the moment the operation id is known — it travels
      // DIRECTLY to the sealed authority under that exact id (the machine
      // only ever learns the opaque typed outcome).
      this.pendingSecret = secret;
      this.send({ type: 'INTENT.UNLOCK' });
      return;
    }
    // No sink (tests/legacy): the machine only learns an opaque operation
    // result; the secret is discarded after the UI clears its input.
    void secret;
    this.send({ type: 'INTENT.UNLOCK' });
  }

  /** Dispatch a system/actor-scoped event (used by the browser controller). */
  sendEvent(event: AuthMachineEvent): void {
    this.actor.send(event);
  }

  /** Subscribe to snapshot projections. Returns an unsubscribe function. */
  subscribe(listener: () => void): () => void {
    const subscription = this.actor.subscribe(listener);
    return () => subscription.unsubscribe();
  }

  /** Current render-safe projection (cached: stable reference between snapshot changes). */
  snapshot(): AuthRenderProjection {
    if (this.cachedProjection === null) {
      this.cachedProjection = projectSnapshot(this.actor.getSnapshot());
    }
    return this.cachedProjection;
  }

  stop(): void {
    this.actor.stop();
  }
}

/**
 * React hook: subscribe to one adapter and return the render projection.
 * Uses useSyncExternalStore so protected rendering flips synchronously on
 * capability change (no effect-gated security boundary).
 */
export function useAuthProjection(adapter: AuthAdapter | null): AuthRenderProjection | null {
  const subscribe = useMemo(
    () => (listener: () => void) => (adapter === null ? () => undefined : adapter.subscribe(listener)),
    [adapter],
  );
  const getSnapshot = useMemo(
    () => () => (adapter === null ? null : adapter.snapshot()),
    [adapter],
  );
  const serverSnapshot = useMemo(() => null, []);
  return useSyncExternalStore(subscribe, getSnapshot, () => serverSnapshot);
}

/**
 * Protected-boundary hook: returns true only when the projection grants
 * protected access. Purely synchronous — no effect ordering can ever grant
 * access; React effects must not be the security boundary.
 */
export function useProtectedAccess(projection: AuthRenderProjection | null): boolean {
  return projection !== null && projection.protectedAccess;
}

/**
 * Strictly synchronous protected-content gate (no async in the decision).
 * Prefer this in render paths; React effect ordering can never grant access.
 */
export function synchronouslyPermitsProtectedContent(projection: AuthRenderProjection | null): boolean {
  return projection !== null && projection.protectedAccess;
}
