// EPIC-001 -> FEAT-007 AC-007-016 -> Phase 2 Tasks 2.1/2.2,
// Phase 7 Tasks 7.1/7.2. Frontend Twin evidence; no EPIC acceptance claim.
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { CreateUserChildRuntime } from './child-bridge';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

const words = [...Array<string>(23).fill('abandon'), 'art']; // Public BIP-39 test vector.
afterEach(() => resetChildViews());

describe('HushVotingApp TwinTests — creation secret-free React projection', () => {
  it('keeps the complete recovery phrase out of the published React child props', async () => {
    const dispatch = vi.fn(async (operation: string) => {
      if (operation === 'inspectStartup') return { outcome: 'OK', payload: { surface: 'verifiedAbsent' } };
      if (operation === 'createCandidate') return { outcome: 'OK', payload: { ref: 'public-test-candidate' } };
      if (operation === 'revealCandidateWords') return { outcome: 'OK', payload: { words } };
      return { outcome: 'OK' };
    });
    const runtime = new CreateUserChildRuntime({
      client: { dispatch, submitSecret: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST,
      lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }),
      randomId: prefix => `${prefix}public-test`,
    });
    try {
      await runtime.start();
      runtime.onProfileContinue('Public test', 'private');
      await runtime.onGenerate();
      const child = resolveOnboardingChild('createUser');
      expect(child?.kind).toBe('createUser');
      if (child?.kind !== 'createUser') throw new Error('Expected creation child');
      expect(child.props.view.screen).toBe('recovery');
      // Report only a boolean; never serialize the secret-bearing publication on failure.
      const published = JSON.stringify(child.props);
      expect(published.includes(JSON.stringify(words)) || published.includes(words.join(' '))).toBe(false);
    } finally {
      await runtime.cleanup();
    }
  });
});
