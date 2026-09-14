/**
 * FEAT-016 Task 4.2/4.4 — compound authenticated entitlement-stage tests.
 *
 * Proves the root machine keeps identity authenticated while entitlement
 * substages gate protected rendering: every ENTITLEMENT.STAGE maps to its
 * child; stale-epoch completions are ignored (never restore access);
 * ENTITLEMENT.RESET re-enters resolving; Lock exits and clears entitlement
 * context; and the adapter projection grants protected access ONLY in
 * entitlementReady with a live authenticated identity (strict compositions).
 */

import { describe, expect, it } from 'vitest';
import { createActor } from 'xstate';
import { AuthAdapter } from '../react/adapter';
import { authMachine } from './machine';
import { INITIAL_EPOCH, nextEpoch } from './policies';
import type { AuthActors } from '../ports';
import type { AuthMachineEvent } from './machine';
import type { CapabilityId, EntitlementStageCode, SessionEpoch } from '../types';
import {
  completeAllPendingOperations,
  pendingOperationCount,
  createBrowserCoordinationTestActor,
  createIdentityVerificationTestActor,
  createLocalUserAuthorityTestActor,
  createNavigationTestActor,
  createOnboardingTestActor,
  createRemovalTestActor,
  createSecretAuthorityTestActor,
} from '../testing/actors';

const VERIFIED_IDENTITY = {
  alias: 'Alice',
  publicSigningKey: '02abcdef',
  publicEncryptionKey: '03abcdef',
} as const;

const ALL_STAGES: ReadonlyArray<EntitlementStageCode> = [
  'entitlementResolving',
  'baselineSigning',
  'baselineSubmitting',
  'awaitingIndex',
  'confirmationDelayed',
  'entitlementUnavailable',
  'entitlementUnsupported',
  'entitlementRepair',
  'entitlementReady',
];

function makeActors(): AuthActors {
  return {
    localUserAuthority: createLocalUserAuthorityTestActor([{ code: 'INIT_NO_LOCAL_USER' }]),
    secretAuthority: createSecretAuthorityTestActor([{ code: 'UNLOCK_SUCCESS' }]),
    identityVerification: createIdentityVerificationTestActor([
      { code: 'VERIFY_SUCCESS', identity: VERIFIED_IDENTITY },
      { code: 'VERIFY_SUCCESS', identity: VERIFIED_IDENTITY },
      { code: 'VERIFY_SUCCESS', identity: VERIFIED_IDENTITY },
    ]),
    onboarding: {
      createUser: createOnboardingTestActor([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'test-local-user-1' }]),
      restoreCredentialFile: createOnboardingTestActor([{ code: 'ONBOARDING_BACK' }]),
      restoreRecoveryWords: createOnboardingTestActor([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'test-local-user-1' }]),
    },
    removal: createRemovalTestActor([{ code: 'REMOVAL_COMPLETE' }]),
    browserCoordination: createBrowserCoordinationTestActor([{ code: 'COORDINATION_SAFE' }]),
    navigation: createNavigationTestActor(),
    telemetry: null,
  };
}

function createDriver(actors: AuthActors, entitlementRequired = true) {
  const machine = createActor(authMachine, {
    input: {
      actors,
      registeredCapabilities: new Set<CapabilityId>(),
      safeCoordination: true,
      entitlementRequired,
    },
  });
  machine.start();
  return machine;
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function flush(): Promise<void> {
  for (let i = 0; i < 20; i += 1) {
    completeAllPendingOperations();
    await settle();
    if (pendingOperationCount() === 0) {
      break;
    }
  }
}

type Driver = ReturnType<typeof createDriver>;

function authCode(snapshot: { value: unknown }): string {
  const value = snapshot.value as { auth: string | Record<string, unknown> };
  return typeof value.auth === 'string' ? value.auth : (Object.keys(value.auth)[0] ?? '?');
}

async function reachAuthenticated(_machine: Driver): Promise<void> {
  await flush(); // init -> noLocalUser
  _machine.send({ type: 'INTENT.CREATE_USER' });
  await flush(); // onboarding -> verifyingIdentityOnline -> authenticated
}

function entitlementChild(snapshot: { value: unknown }): EntitlementStageCode | null {
  const value = snapshot.value as { auth: { authenticated?: string | Record<string, unknown> } };
  const child = value.auth.authenticated;
  if (typeof child === 'string') {
    return (ALL_STAGES as ReadonlyArray<string>).includes(child) ? (child as EntitlementStageCode) : null;
  }
  if (child !== null && typeof child === 'object') {
    const key = Object.keys(child)[0];
    return key !== undefined && (ALL_STAGES as ReadonlyArray<string>).includes(key)
      ? (key as EntitlementStageCode)
      : null;
  }
  return null;
}

function stageEvent(stage: EntitlementStageCode, epoch: SessionEpoch): AuthMachineEvent {
  return { type: 'ENTITLEMENT.STAGE', stage, epoch };
}

describe('compound authenticated entitlement substages', () => {
  it('enters entitlementResolving and keeps auth authenticated (no protected access yet)', async () => {
    const machine = createDriver(makeActors());
    await reachAuthenticated(machine);
    expect(authCode(machine.getSnapshot())).toBe('authenticated');
    expect(entitlementChild(machine.getSnapshot())).toBe('entitlementResolving');
  });

  it('maps every ENTITLEMENT.STAGE to its child state and mirrors context', async () => {
    const machine = createDriver(makeActors());
    await reachAuthenticated(machine);
    for (const stage of ALL_STAGES) {
      machine.send(stageEvent(stage, INITIAL_EPOCH));
      await settle();
      expect(entitlementChild(machine.getSnapshot())).toBe(stage);
      expect(authCode(machine.getSnapshot())).toBe('authenticated');
      expect((machine.getSnapshot().context as { entitlementStage: EntitlementStageCode | null }).entitlementStage).toBe(stage);
    }
  });

  it('ignores stale-epoch completions (late results never restore access)', async () => {
    const machine = createDriver(makeActors());
    await reachAuthenticated(machine);
    const staleEpoch = nextEpoch(INITIAL_EPOCH);
    machine.send(stageEvent('entitlementReady', staleEpoch));
    await settle();
    expect(entitlementChild(machine.getSnapshot())).toBe('entitlementResolving');
  });

  it('ENTITLEMENT.RESET re-enters the blocking resolution gate from ready', async () => {
    const machine = createDriver(makeActors());
    await reachAuthenticated(machine);
    machine.send(stageEvent('entitlementReady', INITIAL_EPOCH));
    await settle();
    expect(entitlementChild(machine.getSnapshot())).toBe('entitlementReady');
    machine.send({ type: 'ENTITLEMENT.RESET' });
    await settle();
    expect(entitlementChild(machine.getSnapshot())).toBe('entitlementResolving');
  });

  it('Lock from ready leaves authenticated and clears entitlement context', async () => {
    const machine = createDriver(makeActors());
    await reachAuthenticated(machine);
    machine.send(stageEvent('entitlementReady', INITIAL_EPOCH));
    await settle();
    machine.send({ type: 'INTENT.LOCK' });
    await settle();
    expect(authCode(machine.getSnapshot())).toBe('locked');
    expect((machine.getSnapshot().context as { entitlementStage: unknown }).entitlementStage).toBeNull();
  });
});

describe('adapter protected-access projection (strict composition)', () => {
  it('grants protected access ONLY in entitlementReady with a live identity', async () => {
    const actors = makeActors();
    const machine = createActor(authMachine, {
      input: {
        actors,
        registeredCapabilities: new Set<CapabilityId>(),
        safeCoordination: true,
        entitlementRequired: true,
      },
    });
    machine.start();
    await flush();
    machine.send({ type: 'INTENT.CREATE_USER' });
    await flush();

    const adapter = new AuthAdapter(machine);
    // Identity authenticated but entitlement resolving -> protected stays false.
    expect(adapter.snapshot().authState).toBe('authenticated');
    expect(adapter.snapshot().entitlementReady).toBe(false);
    expect(adapter.snapshot().protectedAccess).toBe(false);

    // Each non-ready stage keeps the workspace gated.
    for (const stage of ALL_STAGES) {
      if (stage === 'entitlementReady') continue;
      adapter.sendEvent(stageEvent(stage, INITIAL_EPOCH));
      expect(adapter.snapshot().protectedAccess).toBe(false);
    }

    // Fresh query returned ready truth with a live identity -> protected true.
    adapter.sendEvent(stageEvent('entitlementReady', INITIAL_EPOCH));
    expect(adapter.snapshot().entitlementReady).toBe(true);
    expect(adapter.snapshot().protectedAccess).toBe(true);

    // Revalidation/invalidation revokes synchronously.
    adapter.sendEvent({ type: 'ENTITLEMENT.RESET' });
    expect(adapter.snapshot().protectedAccess).toBe(false);
    adapter.stop();
  });
});
