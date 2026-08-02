/**
 * FEAT-002 auto-resolving actors for the DEVELOPMENT composition.
 *
 * The deterministic test kit (`actors.ts`) resolves only when `complete()` is
 * called, which is correct for model tests. In a real browser, the machine's
 * invoke awaits the promise, so dev actors must resolve on their own. These
 * variants wrap the deterministic kit and auto-complete pending operations a
 * microtask after they start, making the dev server flow actually work.
 *
 * TEST-ONLY: imported only from `composition.dev.ts` (production pruned).
 */

import type {
  BrowserCoordinationPort,
  IdentityVerificationPort,
  LocalUserAuthorityPort,
  NavigationPort,
  OnboardingPort,
  RemovalPort,
  SecretAuthorityPort,
} from '../ports';
import type {
  CoordinationResult,
  InitializationResult,
  OnboardingResult,
  RemovalResult,
  UnlockResult,
  VerificationResult,
} from '../results';
import {
  completeAllPendingOperations,
  createBrowserCoordinationTestActor,
  createIdentityVerificationTestActor,
  createLocalUserAuthorityTestActor,
  createNavigationTestActor,
  createOnboardingTestActor,
  createRemovalTestActor,
  createSecretAuthorityTestActor,
} from './actors';

/** Resolve pending operations on the next macrotask so the machine advances. */
function autoResolve(): void {
  setTimeout(() => {
    completeAllPendingOperations();
  }, 0);
}

export function createAutoResolvingLocalUserAuthority(queue: InitializationResult[]): LocalUserAuthorityPort {
  const port = createLocalUserAuthorityTestActor(queue);
  const original = port.initialize.bind(port);
  port.initialize = (epoch) => {
    const op = original(epoch);
    autoResolve();
    return op;
  };
  return port;
}

export function createAutoResolvingSecretAuthority(queue: UnlockResult[]): SecretAuthorityPort {
  const port = createSecretAuthorityTestActor(queue);
  const original = port.beginUnlock.bind(port);
  port.beginUnlock = (epoch) => {
    const op = original(epoch);
    autoResolve();
    return op;
  };
  return port;
}

export function createAutoResolvingIdentityVerification(queue: VerificationResult[]): IdentityVerificationPort {
  const port = createIdentityVerificationTestActor(queue);
  const original = port.verifyOnline.bind(port);
  port.verifyOnline = (epoch, ref) => {
    const op = original(epoch, ref);
    autoResolve();
    return op;
  };
  return port;
}

export function createAutoResolvingOnboarding(
  queue: OnboardingResult[],
  verifyQueue: VerificationResult[] = [{ code: 'VERIFY_SUCCESS' }],
): OnboardingPort {
  const port = createOnboardingTestActor(queue, verifyQueue);
  const originalStart = port.start.bind(port);
  const originalCleanup = port.cleanup.bind(port);
  const originalConfirm = port.confirmMissingProfile.bind(port);
  port.start = (kind, epoch) => {
    const op = originalStart(kind, epoch);
    autoResolve();
    return op;
  };
  port.cleanup = (epoch) => {
    const op = originalCleanup(epoch);
    autoResolve();
    return op;
  };
  port.confirmMissingProfile = (epoch) => {
    const op = originalConfirm(epoch);
    autoResolve();
    return op;
  };
  return port;
}

export function createAutoResolvingRemoval(queue: RemovalResult[]): RemovalPort {
  const port = createRemovalTestActor(queue);
  const original = port.removeLocalUser.bind(port);
  port.removeLocalUser = (epoch) => {
    const op = original(epoch);
    autoResolve();
    return op;
  };
  return port;
}

export function createAutoResolvingBrowserCoordination(queue: CoordinationResult[]): BrowserCoordinationPort {
  const port = createBrowserCoordinationTestActor(queue);
  const original = port.acquire.bind(port);
  port.acquire = (epoch) => {
    const op = original(epoch);
    autoResolve();
    return op;
  };
  return port;
}

export function createAutoResolvingNavigation(): NavigationPort {
  return createNavigationTestActor();
}
