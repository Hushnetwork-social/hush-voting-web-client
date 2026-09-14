// EPIC-001 -> FEAT-008 AC-008-057 -> Phase 3 Tasks 3.7/3.8.
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { RecoveryWordsChildRuntime } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

afterEach(() => { resetChildViews(); vi.useRealTimers(); vi.restoreAllMocks(); });
function view() {
  const child = resolveOnboardingChild('restoreRecoveryWords');
  if (child?.kind !== 'recoveryWords') throw new Error('Missing recovery view');
  return child.props;
}

async function staged(outcome: string) {
  vi.useFakeTimers();
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
  const dispatch = vi.fn(async (operation: string) => {
    if (operation === 'inspectStartup') return { outcome: 'OK', payload: { surface: 'verifiedAbsent' } };
    if (operation === 'deriveRecoveryCandidates') return { outcome: 'OK', payload: { candidates: [{ ref: 'candidate', signingAddress: 'signing', encryptionAddress: 'encryption', producerIds: ['P-01'] }] } };
    if (operation === 'verifyOnlineIdentity') return { outcome };
    if (operation === 'submitIdentityTransaction') return { outcome: 'OK', payload: { status: 'accepted' } };
    return { outcome: 'OK' };
  });
  const runtime = new RecoveryWordsChildRuntime({
    client: { submitSecret: vi.fn(), dispatch, issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST,
    lookupIdentity: async () => ({ kind: 'exact', signingAddress: 'signing', encryptionAddress: 'encryption', profileName: 'Old profile', isPublic: true }),
    randomId: prefix => `${prefix}test`,
  });
  await runtime.start();
  await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
  await runtime.onConfirmExistingProfile();
  view().onAcknowledgeProtection();
  await runtime.onProtect('device-password');
  return { runtime, dispatch };
}

describe('HushVotingApp TwinTests — profile disappears after recovery lookup', () => {
  it('requires fresh alias/visibility consent and reuses the protected stage without another provision', async () => {
    const { runtime, dispatch } = await staged('PROFILE_MISSING');
    try {
      expect(view().view.screen).toBe('recreateReview');
      expect(view().candidateReview?.entries.every(entry => entry.profileAlias === null && entry.visibility === null)).toBe(true);
      expect(dispatch.mock.calls.filter(([op]) => op === 'submitIdentityTransaction')).toHaveLength(0);
      await runtime.onConfirmRecreate('', 'private');
      expect(view().view.screen).toBe('recreateReview');
      await runtime.onConfirmRecreate('New reviewed alias', 'private');
      await runtime.onConfirmRecreate('Duplicate click', 'public');
      expect(view().view.screen).toBe('registration');
      expect(dispatch.mock.calls.filter(([op]) => op === 'provisionFromValidatedBundle')).toHaveLength(1);
      expect(dispatch.mock.calls.filter(([op]) => op === 'submitIdentityTransaction')).toHaveLength(1);
      expect(dispatch).toHaveBeenCalledWith('submitIdentityTransaction', { alias: 'New reviewed alias', visibility: 'private' });
      expect(dispatch.mock.calls.filter(([op]) => op === 'promoteLifecycle')).toHaveLength(0);
    } finally { await runtime.cleanup(); }
  });

  it.each(['NETWORK_UNAVAILABLE', 'VERIFY_TIMEOUT', 'ENCRYPTION_KEY_MISMATCH'])('does not turn %s into recreation consent', async outcome => {
    const { runtime, dispatch } = await staged(outcome);
    try {
      expect(view().view.screen).not.toBe('recreateReview');
      await runtime.onConfirmRecreate('Untrusted attempt', 'private');
      expect(dispatch.mock.calls.filter(([op]) => op === 'submitIdentityTransaction')).toHaveLength(0);
      expect(dispatch.mock.calls.filter(([op]) => op === 'promoteLifecycle')).toHaveLength(0);
    } finally { await runtime.cleanup(); }
  });
});
