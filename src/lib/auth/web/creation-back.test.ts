import { afterEach, describe, expect, it, vi } from 'vitest';
import { createActor } from 'xstate';
import { CreateUserChildRuntime, createWebOnboardingPorts } from './child-bridge';
import { authMachine } from '../state/machine';
import { buildEmptyActors } from '../composition';
import type { CapabilityId, OperationId } from '../types';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

const words = [...Array<string>(23).fill('abandon'), 'art'];
afterEach(() => resetChildViews());
function creation() {
  const child = resolveOnboardingChild('createUser');
  if (child?.kind !== 'createUser') throw new Error('Expected creation child');
  return child.props;
}
function context(dispatch: unknown) {
  return { client: { dispatch, submitSecret: vi.fn(), issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' as const }), randomId: (prefix: string) => `${prefix}test` };
}
function success(operation: string) {
  if (operation === 'inspectStartup') return { outcome: 'OK', payload: { surface: 'verifiedAbsent' } };
  if (operation === 'createCandidate') return { outcome: 'OK', payload: { ref: 'candidate' } };
  if (operation === 'revealCandidateWords') return { outcome: 'OK', payload: { words } };
  if (operation === 'provisionFromValidatedBundle') return { outcome: 'OK', payload: { signingAddress: 's'.repeat(66), encryptionAddress: 'e'.repeat(66) } };
  return { outcome: 'OK' };
}

// EPIC-001 -> FEAT-007 cleanup portions (AC-007-055/060), Phase 3 Tasks 3.1–3.4;
// FEAT-010 AC-010-084 -> FEAT-002 Phase 3 Tasks 3.1/3.2. No cancellation-policy proof.
describe('HushVotingApp TwinTests — creation cleanup acknowledgement', () => {
  it.each(['candidate rejection', 'candidate transport', 'staged rejection', 'staged transport'] as const)('retains failed cleanup for explicit retry: %s', async boundary => {
    const staged = boundary.startsWith('staged');
    const operation = staged ? 'lockAll' : 'destroyCandidate';
    let fail = true;
    const dispatch = vi.fn(async (name: string) => {
      if (name === operation && fail) {
        if (boundary.endsWith('transport')) throw new Error('Controlled cleanup transport failure');
        return { outcome: 'AUTHORITY_BUSY' };
      }
      return success(name);
    });
    const runtime = new CreateUserChildRuntime(context(dispatch));
    try {
      await runtime.start();
      runtime.onProfileContinue('Alice', 'private');
      await runtime.onGenerate();
      if (staged) {
        runtime.onAcknowledge(true);
        runtime.onRecoveryContinue();
        runtime.onConfirmVerify(new Map(creation().confirmPositions.map(position => [position, words[position - 1]])));
        await runtime.onProtect('public-test-password');
        expect(creation().view.screen).toBe('review');
      }
      dispatch.mockClear();
      const first = runtime.cleanup();
      expect(runtime.cleanup()).toBe(first);
      expect(await first).toEqual({ kind: 'CHILD_CLEANUP_FAILED' });
      expect(resolveOnboardingChild('createUser')).toBeNull();
      expect(dispatch.mock.calls.map(([name]) => name)).toEqual([operation]);
      fail = false;
      expect(await runtime.cleanup()).toEqual({ kind: 'CHILD_CLEANUP_COMPLETE' });
      expect(dispatch.mock.calls.map(([name]) => name)).toEqual([operation, operation]);
      await runtime.cleanup();
      expect(dispatch.mock.calls).toHaveLength(2);
    } finally { fail = false; await runtime.cleanup().catch(() => undefined); }
  });

  it('root Retry reruns failed candidate destruction before inspecting custody', async () => {
    let release!: (value: { outcome: 'OK' | 'AUTHORITY_BUSY' }) => void;
    const dispatch = vi.fn((operation: string) => operation === 'destroyCandidate'
      ? new Promise(resolve => { release = resolve; }) : Promise.resolve(success(operation)));
    const actors = buildEmptyActors();
    actors.onboarding = createWebOnboardingPorts(context(dispatch));
    let inspections = 0;
    actors.localUserAuthority = { cancel: () => undefined, initialize: () => ({ operationId: `inspect-${++inspections}` as OperationId,
      result: Promise.resolve({ code: 'INIT_NO_LOCAL_USER' as const }) }) };
    const root = createActor(authMachine, { input: { actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true } });
    root.start();
    try {
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true));
      root.send({ type: 'INTENT.CREATE_USER' });
      await vi.waitFor(() => expect(creation().view.screen).toBe('profile'));
      creation().c.onProfileContinue('Alice', 'private');
      creation().c.onGenerate();
      await vi.waitFor(() => expect(revealedWordCount(creation())).toBe(24));
      root.send({ type: 'INTENT.BACK_FROM_ONBOARDING' });
      await vi.waitFor(() => expect(dispatch).toHaveBeenCalledWith('destroyCandidate', { candidateRef: 'candidate' }));
      release({ outcome: 'AUTHORITY_BUSY' });
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'blockedError' })).toBe(true));
      expect(inspections).toBe(1);
      expect(resolveOnboardingChild('createUser')).toBeNull();
      root.send({ type: 'INTENT.RETRY' });
      await vi.waitFor(() => expect(dispatch.mock.calls.filter(([name]) => name === 'destroyCandidate')).toHaveLength(2));
      expect(inspections).toBe(1);
      release({ outcome: 'OK' });
      await vi.waitFor(() => expect(root.getSnapshot().matches({ auth: 'noLocalUser' })).toBe(true));
      expect(inspections).toBe(2);
      expect(resolveOnboardingChild('createUser')).toBeNull();
    } finally { root.stop(); }
  });
});

function revealedWordCount(child: ReturnType<typeof creation>) {
  const target = document.createElement('ol');
  const detach = child.recoveryDisplay.attach(target);
  try { return target.children.length; } finally { detach(); }
}
