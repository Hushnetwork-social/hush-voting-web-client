/**
 * FEAT-002 synthetic actor test kit.
 *
 * TEST-ONLY BOUNDARY: this module is importable only from test files and the
 * focused browser harness. It is never imported by production composition;
 * the production artifact scan (Phase 7) and the registration gate reject any
 * synthetic actor in a production registry.
 *
 * Actors implement the published port contracts and contain only synthetic
 * public test credentials where required — never real user material.
 */

import type {
  ActorOperation,
  BrowserCoordinationPort,
  CancellablePort,
  IdentityVerificationPort,
  LocalUserAuthorityPort,
  NavigationPort,
  OnboardingPort,
  RemovalPort,
  SecretAuthorityPort,
} from '../ports.js';
import type {
  OperationId,
  SessionEpoch,
} from '../types.js';
import type {
  CoordinationResult,
  InitializationResult,
  OnboardingResult,
  RemovalResult,
  UnlockResult,
  VerificationResult,
} from '../results.js';

let operationSeq = 0;

function nextOperationId(): OperationId {
  operationSeq += 1;
  return `test-op-${operationSeq}` as OperationId;
}

/** Deterministic scriptable result queue for each port. */
export interface ScriptedResults {
  initialize: InitializationResult[];
  unlock: UnlockResult[];
  verify: VerificationResult[];
  onboarding: OnboardingResult[];
  removal: RemovalResult[];
  coordination: CoordinationResult[];
}

function shift<T>(queue: T[], fallback: T): T {  if (queue.length > 0) {
    return queue.shift() as T;
  }
  return fallback;
}

/** Test-kit operation handle: port contract plus deterministic completion control. */
export type TestActorOperation<TResult> = ActorOperation<TResult> & {
  /** Resolves the operation with the queued/fallback result (test control). */
  complete(): void;
};

function deferred<T>(resolveWith: () => T): TestActorOperation<T> {
  const operationId = nextOperationId();
  let resolve!: (value: T) => void;
  const result = new Promise<T>((r) => {
    resolve = r;
  });
  return {
    operationId,
    result,
    complete: () => resolve(resolveWith()),
  };
}

/** In-memory local-user authority test actor. */
export function createLocalUserAuthorityTestActor(
  queue: InitializationResult[],
): LocalUserAuthorityPort {
  const active = new Map<OperationId, () => void>();
  return {
    initialize(epoch: SessionEpoch): ActorOperation<InitializationResult> {
      const op = deferred(() => shift(queue, { code: 'INIT_NO_LOCAL_USER' }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    cancel(operationId: OperationId): void {
      active.delete(operationId);
    },
  };
}

/** In-memory secret-authority test actor (never receives secrets — contract-level). */
export function createSecretAuthorityTestActor(queue: UnlockResult[]): SecretAuthorityPort {
  const active = new Map<OperationId, () => void>();
  return {
    beginUnlock(epoch: SessionEpoch): ActorOperation<UnlockResult> {
      const op = deferred(() => shift(queue, { code: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    cancel(operationId: OperationId): void {
      active.delete(operationId);
    },
  };
}

/** In-memory identity-verification test actor. */
export function createIdentityVerificationTestActor(
  queue: VerificationResult[],
): IdentityVerificationPort {
  const active = new Map<OperationId, () => void>();
  return {
    verifyOnline(epoch: SessionEpoch, _localUserRef: string): ActorOperation<VerificationResult> {
      const op = deferred(() => shift(queue, { code: 'VERIFY_NETWORK_UNAVAILABLE' }));
      active.set(op.operationId, op.complete);
      void epoch;
      void _localUserRef;
      return op;
    },
    cancel(operationId: OperationId): void {
      active.delete(operationId);
    },
  };
}

/** In-memory onboarding test actor. */
export function createOnboardingTestActor(
  queue: OnboardingResult[],
  verifyQueue: VerificationResult[] = [
    {
      code: 'VERIFY_PROFILE_MISSING',
      safeCandidate: { alias: 'Test User', abbreviatedSigningAddress: 'NVh…d3f' },
    },
  ],
): OnboardingPort & CancellablePort {
  const active = new Map<OperationId, () => void>();
  return {
    start(_kind: 'createUser' | 'restoreCredentialFile' | 'restoreRecoveryWords', epoch: SessionEpoch): ActorOperation<OnboardingResult> {
      const op = deferred<OnboardingResult>(() => shift(queue, { code: 'ONBOARDING_BACK' }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    cleanup(epoch: SessionEpoch): ActorOperation<OnboardingResult> {
      const op = deferred<OnboardingResult>(() => shift(queue, { code: 'ONBOARDING_CLEANUP_COMPLETE' }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    confirmMissingProfile(epoch: SessionEpoch): ActorOperation<VerificationResult> {
      const op = deferred<VerificationResult>(() => shift(verifyQueue, {
        code: 'VERIFY_PROFILE_MISSING',
        safeCandidate: { alias: 'Test User', abbreviatedSigningAddress: 'NVh…d3f' },
      }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    cancel(operationId: OperationId): void {
      active.delete(operationId);
    },
  };
}

/** In-memory removal test actor. */
export function createRemovalTestActor(queue: RemovalResult[]): RemovalPort {
  const active = new Map<OperationId, () => void>();
  return {
    removeLocalUser(epoch: SessionEpoch): ActorOperation<RemovalResult> {
      const op = deferred<RemovalResult>(() => shift(queue, { code: 'REMOVAL_COMPLETE' }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    cancel(operationId: OperationId): void {
      active.delete(operationId);
    },
  };
}

/** In-memory browser-coordination test actor. */
export function createBrowserCoordinationTestActor(
  queue: CoordinationResult[],
): BrowserCoordinationPort {
  const active = new Map<OperationId, () => void>();
  return {
    acquire(epoch: SessionEpoch): ActorOperation<CoordinationResult> {
      const op = deferred<CoordinationResult>(() => shift(queue, { code: 'COORDINATION_SAFE' }));
      active.set(op.operationId, op.complete);
      void epoch;
      return op;
    },
    release(): Promise<void> {
      return Promise.resolve();
    },
    cancel(operationId: OperationId): void {
      active.delete(operationId);
    },
  };
}

/** Deterministic in-memory navigation port. */
export function createNavigationTestActor(): NavigationPort {
  const stack: string[] = [];
  return {
    push(destination: import('../types.js').TypedDestinationKind) {
      const token = `nav-${stack.length}-${destination}`;
      stack.push(token);
      return token as import('../types.js').NavigationToken;
    },
    resolve(token: import('../types.js').NavigationToken) {
      const found = stack.find((entry) => entry === token);
      return found ? (found.split('-')[2] as import('../types.js').TypedDestinationKind) : null;
    },
    clear() {
      stack.length = 0;
    },
  };
}
