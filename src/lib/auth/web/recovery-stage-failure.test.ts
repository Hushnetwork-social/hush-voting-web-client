import { afterEach, describe, expect, it, vi } from 'vitest';
import { RecoveryWordsChildRuntime } from './child-bridge';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

afterEach(() => resetChildViews());
function recovery() {
  const child = resolveOnboardingChild('restoreRecoveryWords');
  if (child?.kind !== 'recoveryWords') throw new Error('Expected recovery child');
  return child.props;
}

// EPIC-001 -> FEAT-008 AC-008-037/078 -> Phase 3 Tasks 3.5/3.6, 3.9/3.10.
describe('HushVotingApp TwinTests — failed recovery staging disposal', () => {
  it.each(['rejected stage', 'stage transport', 'capability rejection', 'cleanup rejection', 'cleanup retry'] as const)('revokes derived material before completing failure: %s', async boundary => {
    let release!: (value: { outcome: string }) => void;
    const dispatch = vi.fn(async (operation: string) => {
      if (operation === 'inspectStartup') return { outcome: 'OK', payload: { surface: 'verifiedAbsent' } };
      if (operation === 'deriveRecoveryCandidates') return { outcome: 'OK', payload: { candidates: [{ ref: 'candidate', signingAddress: 'signing', encryptionAddress: 'encryption', producerIds: ['P-01'] }] } };
      if (operation === 'provisionFromValidatedBundle') {
        if (boundary === 'stage transport') throw new Error('Controlled transport failure');
        return { outcome: 'UNKNOWN_FAILURE' };
      }
      if (operation === 'lockAll') return new Promise(resolve => { release = resolve; });
      return { outcome: 'OK' };
    });
    const runtime = new RecoveryWordsChildRuntime({
      client: { dispatch, submitSecret: vi.fn(), issueCapability: async () => {
        if (boundary === 'capability rejection') throw new Error('Controlled capability rejection');
        return { capabilityId: 'cap' };
      } } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test`,
    });
    let protection: Promise<void> | undefined;
    try {
      await runtime.start();
      await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
      runtime.onSelectCandidate(0);
      await runtime.onConfirmExistingProfile();
      await runtime.onConfirmRecreate('Recovered', 'private');
      recovery().onAcknowledgeProtection();
      dispatch.mockClear();
      protection = runtime.onProtect('public-test-password');
      // Attach immediately so a buggy transport rejection cannot become unhandled.
      void protection.catch(() => undefined);
      await vi.waitFor(() => expect(dispatch).toHaveBeenCalledWith('lockAll'));
      expect(recovery().view.screen).toBe('staging');
      expect(dispatch.mock.calls.some(([op]) => ['verifyOnlineIdentity', 'submitIdentityTransaction', 'promoteLifecycle'].includes(op))).toBe(false);
      release({ outcome: boundary.startsWith('cleanup') ? 'AUTHORITY_BUSY' : 'OK' });
      await expect(protection).resolves.toBeUndefined();
      expect(recovery().view.screen).toBe('terminal');
      if (boundary === 'cleanup retry') {
        const inspections = dispatch.mock.calls.filter(([op]) => op === 'inspectStartup').length;
        const retry = runtime.start();
        await vi.waitFor(() => expect(dispatch.mock.calls.filter(([op]) => op === 'lockAll')).toHaveLength(2));
        expect(recovery().view.screen).toBe('terminal');
        expect(dispatch.mock.calls.filter(([op]) => op === 'inspectStartup')).toHaveLength(inspections);
        release({ outcome: 'OK' });
        await retry;
        expect(recovery().view.screen).toBe('wordEntry');
        expect(dispatch.mock.calls.filter(([op]) => op === 'inspectStartup')).toHaveLength(inspections + 1);
      }
      const cleanup = runtime.cleanup();
      if (boundary === 'cleanup rejection') {
        await vi.waitFor(() => expect(dispatch.mock.calls.filter(([op]) => op === 'lockAll')).toHaveLength(2));
        release({ outcome: 'OK' });
      }
      expect(await cleanup).toEqual({ kind: 'CHILD_CLEANUP_COMPLETE' });
      expect(dispatch.mock.calls.some(([op]) => op === 'destroyCandidate')).toBe(false);
      expect(resolveOnboardingChild('restoreRecoveryWords')).toBeNull();
    } finally {
      release?.({ outcome: 'OK' });
      await protection?.catch(() => undefined);
      dispatch.mockImplementation(async () => ({ outcome: 'OK' }));
      await runtime.cleanup().catch(() => undefined);
    }
  });
});
