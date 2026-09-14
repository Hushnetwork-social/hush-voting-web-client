import { afterEach, describe, expect, it, vi } from 'vitest';
import { createActor } from 'xstate';
import { authMachine } from '../state/machine';
import { buildEmptyActors } from '../composition';
import { RecoveryWordsChildRuntime, createWebOnboardingPorts } from './child-bridge';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import type { CapabilityId, OperationId } from '../types';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

afterEach(() => resetChildViews());

function recovery() {
  const child = resolveOnboardingChild('restoreRecoveryWords');
  if (child?.kind !== 'recoveryWords') throw new Error('Expected recovery child');
  return child.props;
}

// EPIC-001 -> FEAT-008 AC-008-065 -> Phase 3 Tasks 3.9/3.10,
// Phase 6 Tasks 6.1/6.2. Actual root machine and child port, isolated worker/storage.
describe('HushVotingApp TwinTests — recovery navigation inspection', () => {
  it.each(['empty', 'changed custody', 'cleanup retry'] as const)('waits for cleanup and fresh custody inspection before navigation: %s', async custody => {
    let releaseCleanup!: (value: { outcome: 'OK' | 'AUTHORITY_BUSY' }) => void;
    let releaseInspection!: (value: { code: 'INIT_NO_LOCAL_USER' } | { code: 'INIT_LOCKED_USER'; safeIdentity: { alias: string; abbreviatedSigningAddress: string } }) => void;
    const dispatch = vi.fn((operation: string) => {
      if (operation === 'inspectStartup') return Promise.resolve({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
      if (operation === 'destroyCandidate') return new Promise(resolve => { releaseCleanup = resolve; });
      return Promise.resolve({ outcome: 'OK', payload: { candidates: [{ ref: 'candidate', signingAddress: 'signing', encryptionAddress: 'encryption', producerIds: ['P-01'] }] } });
    });
    const actors = buildEmptyActors();
    actors.onboarding = createWebOnboardingPorts({
      client: { dispatch, submitSecret: vi.fn(), cancel: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test`,
    });
    let inspections = 0;
    actors.localUserAuthority = {
      cancel: () => undefined,
      initialize: () => ({ operationId: `inspect-${++inspections}` as OperationId,
        result: inspections === 1 ? Promise.resolve({ code: 'INIT_NO_LOCAL_USER' as const })
          : new Promise(resolve => { releaseInspection = resolve; }) }),
    };
    const root = createActor(authMachine, { input: { actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true } });
    root.start();
    try {
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true));
      root.send({ type: 'INTENT.RESTORE_RECOVERY_WORDS' });
      await vi.waitFor(() => expect(recovery().view.screen).toBe('wordEntry'));
      const staleChild = recovery();
      staleChild.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
      await vi.waitFor(() => expect(recovery().view.screen).toBe('candidateSelection'));
      root.send({ type: 'INTENT.BACK_FROM_ONBOARDING' });
      await vi.waitFor(() => expect(dispatch).toHaveBeenCalledWith('destroyCandidate', { candidateRef: 'candidate' }));
      expect(inspections).toBe(1);
      expect(resolveOnboardingChild('restoreRecoveryWords')).toBeNull();
      expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(false);
      if (custody === 'cleanup retry') {
        releaseCleanup({ outcome: 'AUTHORITY_BUSY' });
        await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'blockedError' })).toBe(true));
        expect(inspections).toBe(1);
        root.send({ type: 'INTENT.RETRY' });
        await vi.waitFor(() => expect(dispatch.mock.calls.filter(([operation]) => operation === 'destroyCandidate')).toHaveLength(2));
      }
      releaseCleanup({ outcome: 'OK' });
      await vi.waitFor(() => expect(inspections).toBe(2));
      root.send({ type: 'INTENT.RESTORE_RECOVERY_WORDS' });
      staleChild.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
      await Promise.resolve();
      expect(resolveOnboardingChild('restoreRecoveryWords')).toBeNull();
      expect(dispatch.mock.calls.filter(([operation]) => operation === 'deriveRecoveryCandidates')).toHaveLength(1);
      expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(false);
      releaseInspection(custody !== 'changed custody' ? { code: 'INIT_NO_LOCAL_USER' }
        : { code: 'INIT_LOCKED_USER', safeIdentity: { alias: 'Existing identity', abbreviatedSigningAddress: '02aa…bb' } });
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: custody !== 'changed custody' ? 'noLocalUser' : 'locked' })).toBe(true));
      expect(resolveOnboardingChild('restoreRecoveryWords')).toBeNull();
      expect(dispatch.mock.calls.filter(([operation]) => operation === 'destroyCandidate')).toHaveLength(custody === 'cleanup retry' ? 2 : 1);
    } finally { root.stop(); }
  });

  // AC-008-064/070/078, Phase 3 Tasks 3.9/3.10: partial cleanup and lock acknowledgement.
  it.each(['second candidate', 'transport failure', 'staged lock'] as const)('retains unacknowledged cleanup for explicit retry: %s', async boundary => {
    const candidates = ['first', 'second'].map(ref => ({ ref, signingAddress: `${ref}-sign`, encryptionAddress: `${ref}-encrypt`, producerIds: ['P-01'] }));
    let fail = true;
    const dispatch = vi.fn(async (operation: string, payload?: { candidateRef?: string }) => {
      if (operation === 'inspectStartup') return { outcome: 'OK', payload: { surface: 'verifiedAbsent' } };
      if (operation === 'deriveRecoveryCandidates') return { outcome: 'OK', payload: { candidates } };
      if (operation === 'submitIdentityTransaction') return { outcome: 'OK', payload: { status: 'accepted' } };
      if (fail && ((operation === 'destroyCandidate' && payload?.candidateRef === 'second') || (boundary === 'staged lock' && operation === 'lockAll'))) {
        if (boundary === 'transport failure') throw new Error('Controlled cleanup transport failure');
        return { outcome: 'AUTHORITY_BUSY' };
      }
      return { outcome: 'OK' };
    });
    const runtime = new RecoveryWordsChildRuntime({
      client: { dispatch, submitSecret: vi.fn(), issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test`,
    });
    try {
      await runtime.start();
      await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
      if (boundary === 'staged lock') {
        // Selection deliberately destroys the unused second candidate before staging.
        fail = false;
        runtime.onSelectCandidate(0);
        await runtime.onConfirmExistingProfile();
        await runtime.onConfirmRecreate('Recovered', 'private');
        recovery().onAcknowledgeProtection();
        await runtime.onProtect('public-test-password');
        expect(recovery().view.screen).toBe('registration');
        fail = true;
      }
      dispatch.mockClear();
      const first = runtime.cleanup();
      expect(runtime.cleanup()).toBe(first);
      expect(await first).toEqual({ kind: 'CHILD_CLEANUP_FAILED' });
      expect(resolveOnboardingChild('restoreRecoveryWords')).toBeNull();
      expect(dispatch.mock.calls).toEqual(boundary === 'staged lock' ? [['lockAll']]
        : [['destroyCandidate', { candidateRef: 'first' }], ['destroyCandidate', { candidateRef: 'second' }]]);
      dispatch.mockClear();
      fail = false;
      expect(await runtime.cleanup()).toEqual({ kind: 'CHILD_CLEANUP_COMPLETE' });
      expect(dispatch.mock.calls).toEqual(boundary === 'staged lock' ? [['lockAll']]
        : [['destroyCandidate', { candidateRef: 'second' }]]);
    } finally { fail = false; await runtime.cleanup().catch(() => undefined); }
  });
});
