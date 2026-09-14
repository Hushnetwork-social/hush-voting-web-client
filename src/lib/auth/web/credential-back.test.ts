import { afterEach, describe, expect, it, vi } from 'vitest';
import { createActor } from 'xstate';
import { authMachine } from '../state/machine';
import { buildEmptyActors } from '../composition';
import { createWebOnboardingPorts } from './child-bridge';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import type { CapabilityId, OperationId } from '../types';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

afterEach(() => resetChildViews());

function currentFile() {
  const child = resolveOnboardingChild('restoreCredentialFile');
  if (child?.kind !== 'credentialFile') throw new Error('Expected credential-file child');
  return child.props;
}

// EPIC-001 -> FEAT-009 AC-009-067 -> Phase 3 Tasks 3.9/3.10.
// Real root machine and Web child/port; isolated worker and startup storage.
describe('HushVotingApp TwinTests — validated credential Back', () => {
  it.each(['success', 'cleanup retry', 'changed custody', 'source cleanup retry'])('waits for acknowledged cleanup and rechecks custody before navigation: %s', async mode => {
    const cleanupOperation = mode === 'source cleanup retry' ? 'discardSecretTransfers' : 'destroyCandidate';
    const expectedCleanupPayload = mode === 'source cleanup retry' ? { transferOperationId: 'file-op-test' } : { candidateRef: 'candidate' };
    let release!: (value: { outcome: 'OK' | 'AUTHORITY_BUSY' }) => void;
    const dispatch = vi.fn((operation: string) => {
      if (operation === 'inspectStartup') return Promise.resolve({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
      if (operation === cleanupOperation) return new Promise(resolve => { release = resolve; });
      return Promise.resolve({ outcome: 'OK', payload: { ref: 'candidate', signingAddress: 'signing', encryptionAddress: 'encryption' } });
    });
    const client = { dispatch, submitSecret: vi.fn(), cancel: vi.fn() } as unknown as BrowserVaultClient;
    const onboarding = createWebOnboardingPorts({ client, manifest: ISOLATED_DEVNET_MANIFEST,
      lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    let inspections = 0;
    const actors = buildEmptyActors();
    actors.onboarding = onboarding;
    actors.localUserAuthority = {
      cancel: () => undefined,
      initialize: () => ({ operationId: `inspect-${++inspections}` as OperationId,
        result: Promise.resolve(inspections > 1 && mode === 'changed custody'
          ? { code: 'INIT_LOCKED_USER' as const, safeIdentity: { alias: 'Competing identity', abbreviatedSigningAddress: '02aa…bb' } }
          : { code: 'INIT_NO_LOCAL_USER' as const }) }),
    };
    const root = createActor(authMachine, { input: { actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true } });
    root.start();
    try {
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true));
      root.send({ type: 'INTENT.RESTORE_CREDENTIAL_FILE' });
      await vi.waitFor(() => expect(currentFile().view.screen).toBe('picker'));
      const bytes = new Uint8Array(52); bytes.set([72, 85, 83, 72, 1]);
      const file = { size: bytes.length, slice: () => ({ stream: () => new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(bytes.slice()); controller.close(); },
      }) }) } as unknown as File;
      currentFile().onChooseFile(file);
      await vi.waitFor(() => expect(currentFile().view.screen).toBe('password'));
      if (mode !== 'source cleanup retry') {
        currentFile().onSubmitPassword('public-test-password');
        await vi.waitFor(() => expect(currentFile().view.screen).toBe('profileReview'));
      }
      root.send({ type: 'INTENT.BACK_FROM_ONBOARDING' });
      await vi.waitFor(() => expect(dispatch).toHaveBeenCalledWith(cleanupOperation, expectedCleanupPayload));
      expect(inspections).toBe(1);
      expect(resolveOnboardingChild('restoreCredentialFile')).toBeNull();
      expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(false);
      if (mode === 'cleanup retry' || mode === 'source cleanup retry') {
        release({ outcome: 'AUTHORITY_BUSY' });
        await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'blockedError' })).toBe(true));
        expect(inspections).toBe(1);
        expect(resolveOnboardingChild('restoreCredentialFile')).toBeNull();
        expect(dispatch.mock.calls.filter(([operation]) => operation === cleanupOperation)).toHaveLength(1);
        root.send({ type: 'INTENT.RETRY' });
        await vi.waitFor(() => expect(dispatch.mock.calls.filter(([operation]) => operation === cleanupOperation)).toHaveLength(2));
      }
      release({ outcome: 'OK' });
      if (mode === 'changed custody') {
        await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'locked' })).toBe(true));
        expect(resolveOnboardingChild('restoreCredentialFile')).toBeNull();
        expect(root.getSnapshot().context.safeIdentity?.alias).toBe('Competing identity');
        return;
      }
      await vi.waitFor(() => expect(inspections).toBe(2));
      if (mode === 'source cleanup retry') {
        await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true));
        expect(resolveOnboardingChild('restoreCredentialFile')).toBeNull();
        expect(dispatch.mock.calls.filter(([operation]) => operation === cleanupOperation)).toHaveLength(2);
        return;
      }
      await vi.waitFor(() => expect(resolveOnboardingChild('restoreCredentialFile')?.kind).toBe('credentialFile'));
      expect(currentFile().view.screen).toBe('picker');
      expect(currentFile().view.profile).toBeNull();
      expect(currentFile().view.passwordFieldState).toBeNull();
      expect(dispatch.mock.calls.filter(([operation]) => operation === 'destroyCandidate')).toHaveLength(mode === 'cleanup retry' ? 2 : 1);
    } finally { root.stop(); }
  });
});
