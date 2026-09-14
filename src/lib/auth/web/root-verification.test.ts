import { describe, expect, it, vi } from 'vitest';
import { createActor } from 'xstate';
import { authMachine } from '../state/machine';
import { createWebIdentityVerification } from './web-actors';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import type { AuthActors } from '../ports';
import type { CapabilityId, LocalUserRef, SessionEpoch } from '../types';
import {
  completeAllPendingOperations,
  createBrowserCoordinationTestActor,
  createLocalUserAuthorityTestActor,
  createNavigationTestActor,
  createOnboardingTestActor,
  createRemovalTestActor,
  createSecretAuthorityTestActor,
} from '../testing/actors';

// EPIC-001 -> FEAT-010 AC-010-013 -> Phase 3 Tasks 3.1/3.2,
// Phase 6 Tasks 6.7/6.8. Isolated FEAT evidence only.
describe('HushVotingApp TwinTests — root verification after child completion', () => {
  // FEAT-008 existing-profile activation/resume -> Phase 3 Tasks 3.7/3.8.
  it.each(['OK', 'UNKNOWN_FAILURE'])('waits for staged durable promotion and handles %s before granting root access', async promotion => {
    let finish!: (value: { outcome: string }) => void;
    const dispatch = vi.fn((operation: string) => operation === 'verifyOnlineIdentity'
      ? Promise.resolve({ outcome: 'OK', payload: { requiresPromotion: true } })
      : new Promise<{ outcome: string }>(resolve => { finish = resolve; }));
    const client = { isConnected: () => true, dispatch, cancel: vi.fn() } as unknown as BrowserVaultClient;
    const operation = createWebIdentityVerification(client).verifyOnline(1 as SessionEpoch, 'staged-recovery' as LocalUserRef);
    let settled = false;
    void operation.result.then(() => { settled = true; });
    await vi.waitFor(() => expect(dispatch).toHaveBeenCalledWith('promoteLifecycle', { status: 'Active' }));
    expect(settled).toBe(false);
    finish({ outcome: promotion });
    expect((await operation.result).code).toBe(promotion === 'OK' ? 'VERIFY_SUCCESS' : 'UNKNOWN_FAILURE');
    expect(dispatch.mock.calls).toEqual([['verifyOnlineIdentity'], ['promoteLifecycle', { status: 'Active' }]]);
  });

  it.each(['OK', 'SIGNING_KEY_MISMATCH', 'ENCRYPTION_KEY_MISMATCH'])(
    'requires fresh root verification and handles %s after opaque child completion', async outcome => {
      let finish!: (result: { outcome: string }) => void;
      const dispatch = vi.fn(() => new Promise<{ outcome: string }>(resolve => { finish = resolve; }));
      const client = { isConnected: () => true, dispatch, cancel: vi.fn() } as unknown as BrowserVaultClient;
      const actors: AuthActors = {
        localUserAuthority: createLocalUserAuthorityTestActor([{ code: 'INIT_NO_LOCAL_USER' }]),
        secretAuthority: createSecretAuthorityTestActor([]),
        identityVerification: createWebIdentityVerification(client),
        onboarding: {
          createUser: createOnboardingTestActor([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'opaque-verification-only' }]),
          restoreCredentialFile: createOnboardingTestActor([]),
          restoreRecoveryWords: createOnboardingTestActor([]),
        },
        removal: createRemovalTestActor([]),
        browserCoordination: createBrowserCoordinationTestActor([{ code: 'COORDINATION_SAFE' }]),
        navigation: createNavigationTestActor(), telemetry: null,
      };
      const machine = createActor(authMachine, { input: { actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true } });
      try {
        machine.start();
        await vi.waitFor(() => {
          completeAllPendingOperations();
          expect(machine.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true);
        });
        machine.send({ type: 'INTENT.CREATE_USER' });
        await vi.waitFor(() => {
          completeAllPendingOperations();
          expect(dispatch).toHaveBeenCalledExactlyOnceWith('verifyOnlineIdentity');
        });
        expect(machine.getSnapshot().context.localUserRef).toBe('opaque-verification-only');
        expect(machine.getSnapshot().matches({ auth: 'verifyingIdentityOnline' })).toBe(true);
        expect(machine.getSnapshot().matches({ auth: 'authenticated' })).toBe(false);
        finish({ outcome });
        await vi.waitFor(() => expect(machine.getSnapshot().matches({ auth: outcome === 'OK' ? 'authenticated' : 'blockedError' })).toBe(true));
        expect(dispatch).toHaveBeenCalledOnce();
      } finally {
        machine.stop();
        completeAllPendingOperations();
      }
    },
  );
});
