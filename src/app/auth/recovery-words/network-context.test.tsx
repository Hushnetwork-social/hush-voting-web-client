import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RecoveryFlow } from './recovery-flow';
import { RecoveryWordsChildRuntime } from '../../../lib/auth/web/child-bridge';
import type { BrowserVaultClient } from '../../../lib/browser-vault/production/client';
import { ISOLATED_DEVNET_MANIFEST } from '../../../lib/runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../onboarding/onboarding-registry';

// EPIC-001 -> FEAT-008 AC-008-004 -> Phase 4 Tasks 4.1/4.2,
// Phase 5 Tasks 5.1/5.2. Network-change invalidation remains separate.
it('shows the bound canonical test network before any recovery verification or lookup', async () => {
  const dispatch = vi.fn(async () => ({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } }));
  const submitSecret = vi.fn();
  const lookupIdentity = vi.fn();
  const runtime = new RecoveryWordsChildRuntime({
    client: { dispatch, submitSecret } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity, randomId: prefix => `${prefix}network-context`,
  });
  try {
    await runtime.start();
    const child = resolveOnboardingChild('restoreRecoveryWords');
    if (child?.kind !== 'recoveryWords') throw new Error('Expected recovery child');
    render(<RecoveryFlow {...child.props} />);
    expect(screen.getByTestId('recovery-network')).toHaveTextContent('hushnetwork-devnet');
    expect(screen.getByTestId('recovery-network')).toHaveTextContent('Test network');
    expect(screen.getByRole('button', { name: 'Verify' })).toBeVisible();
    expect(screen.getByTestId('word-grid').querySelectorAll('input')).toHaveLength(24);
    expect(dispatch).toHaveBeenCalledExactlyOnceWith('inspectStartup');
    expect(submitSecret).not.toHaveBeenCalled();
    expect(lookupIdentity).not.toHaveBeenCalled();
  } finally { await runtime.cleanup(); resetChildViews(); }
});
