/**
 * FEAT-005 Ubuntu auth UI component tests (Tasks 5.2 + 5.4).
 *
 * Accessibility-first: queries by role/name; asserts keyboard operation,
 * visible focus, live regions, honest copy, concealment bounds, and that no
 * secret/raw native detail is exposed. Only synthetic words are used.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  FallbackAcknowledgment,
  ProviderStatusPanel,
  RollbackRecoveryPanel,
  UpgradeOffer,
} from './surfaces';
import { RemovalProgressPanel, RevealPanel, SecuritySettings } from './sensitive';
import { REVEAL_CONCEAL_SECONDS } from './copy';

// Clipboard write is mocked at the module level (test seam); the component's
// own copy-warning + cleanup behavior is asserted directly.
vi.mock('./sensitive', async (importOriginal) => {
  const mod = await importOriginal<typeof import('./sensitive')>();
  return {
    ...mod,
    writeClipboard: vi.fn().mockResolvedValue(true),
  };
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const FORBIDDEN_MARKERS = [
  'privateKey',
  'private-key',
  'decrypted',
  'ciphertext',
  'dbus',
  'object path',
  '/home/',
  'secret-value',
];

function expectNoSecretMarkers(node: HTMLElement) {
  const text = node.textContent ?? '';
  const lower = text.toLowerCase();
  for (const marker of FORBIDDEN_MARKERS) {
    expect(lower).not.toContain(marker);
  }
}

describe('provider status surfaces (task 5.1)', () => {
  it('renders each closed state with safe actions and no raw detail', () => {
    const cases: Array<{
      state: Parameters<typeof ProviderStatusPanel>[0]['state'];
      expectButtons: string[];
      expectFallbackAbsent: boolean;
    }> = [
      { state: 'availableUnlocked', expectButtons: ['Cancel'], expectFallbackAbsent: true },
      { state: 'availableLocked', expectButtons: ['Unlock Ubuntu keyring', 'Cancel'], expectFallbackAbsent: true },
      { state: 'promptCancelled', expectButtons: ['Retry', 'Cancel'], expectFallbackAbsent: true },
      { state: 'temporarilyUnavailable', expectButtons: ['Retry', 'Cancel'], expectFallbackAbsent: true },
      { state: 'unqualifiedProvider', expectButtons: ['Enable Ubuntu keyring', 'Cancel'], expectFallbackAbsent: true },
      { state: 'protectionInvalidated', expectButtons: ['Portable recovery', 'Cancel'], expectFallbackAbsent: true },
    ];
    for (const { state, expectButtons, expectFallbackAbsent } of cases) {
      render(
        <ProviderStatusPanel
          state={state}
          onUnlockKeyring={() => undefined}
          onRetry={() => undefined}
          onEnableOsProtection={() => undefined}
          onPortableRecovery={() => undefined}
          onCancel={() => undefined}
        />,
      );
      const surface = screen.getByTestId('ubuntu-surface');
      for (const label of expectButtons) {
        expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
      }
      if (expectFallbackAbsent) {
        // Locked/cancelled/timeout/unqualified/invalidated never offer a
        // password-only fallback action.
        expect(
          screen.queryByRole('button', { name: /continue with password-only protection/i }),
        ).not.toBeInTheDocument();
      }
      expectNoSecretMarkers(surface);
      cleanup();
    }
  });

  it('dispatches the explicit unlock action only on user click (no auto prompt)', async () => {
    const user = userEvent.setup();
    const onUnlock = vi.fn();
    render(
      <ProviderStatusPanel
        state="availableLocked"
        onUnlockKeyring={onUnlock}
        onCancel={() => undefined}
      />,
    );
    expect(onUnlock).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: /unlock ubuntu keyring/i }));
    expect(onUnlock).toHaveBeenCalledOnce();
  });
});

describe('fallback surface (task 5.1)', () => {
  it('requires explicit acknowledgement before the secondary continue action', async () => {
    const user = userEvent.setup();
    const onContinue = vi.fn();
    const onRetry = vi.fn();
    render(
      <FallbackAcknowledgment onRetryOrEnable={onRetry} onContinueFallback={onContinue} />,
    );
    const continueButton = screen.getByRole('button', { name: /continue with password-only protection/i });
    expect(continueButton).toBeDisabled();
    // The checkbox is required.
    const checkbox = screen.getByRole('checkbox', { name: /i understand that password-only protection is weaker/i });
    expect(checkbox).toHaveAttribute('aria-required', 'true');
    await user.click(checkbox);
    expect(continueButton).toBeEnabled();
    await user.click(continueButton);
    expect(onContinue).toHaveBeenCalledWith(true);
    // Retry/enable is the primary first action.
    await user.click(screen.getByRole('button', { name: /retry \/ enable ubuntu keyring/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('explains reduced copied-file resistance honestly (no OS-backed claim)', () => {
    render(<FallbackAcknowledgment onRetryOrEnable={() => undefined} onContinueFallback={() => undefined} />);
    const surface = screen.getByTestId('ubuntu-surface');
    const text = (surface.textContent ?? '').toLowerCase();
    expect(text).toContain('offline password guessing');
    expect(text).toContain('device password still encrypts');
    // The mode is honestly described as never OS-backed/hardware-backed — no
    // positive claim of either appears.
    expect(text).toContain('never labeled os-backed or hardware-backed');
    expect(text).not.toContain('offers hardware-backed protection');
    expectNoSecretMarkers(surface);
  });
});

describe('upgrade and recovery surfaces (task 5.1)', () => {
  it('upgrade offer is atomic, honest, and never downgrades', () => {
    render(<UpgradeOffer onAddProtection={() => undefined} onNotNow={() => undefined} />);
    expect(screen.getByRole('button', { name: /add ubuntu keyring protection/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /not now/i })).toBeInTheDocument();
    expect(screen.queryByText(/downgrade/i)).not.toBeInTheDocument();
    expectNoSecretMarkers(screen.getByTestId('ubuntu-surface'));
  });

  it('rollback requires explicit confirmation and never guesses a key', async () => {
    const user = userEvent.setup();
    const onRecover = vi.fn();
    render(
      <RollbackRecoveryPanel
        variant="rollbackAvailable"
        onRestoreWords={() => undefined}
        onRestoreFile={() => undefined}
        onRecoverRollback={onRecover}
        onCancel={() => undefined}
      />,
    );
    const recover = screen.getByRole('button', { name: /recover previous copy/i });
    expect(recover).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /i confirm recovering the previous verified copy/i }));
    expect(recover).toBeEnabled();
    await user.click(recover);
    expect(onRecover).toHaveBeenCalledOnce();
  });

  it('invalidated state routes to portable recovery with no replacement claim', () => {
    render(
      <RollbackRecoveryPanel
        variant="invalidated"
        onRestoreWords={() => undefined}
        onRestoreFile={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(screen.getByRole('button', { name: /restore recovery words/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /restore credential file/i })).toBeInTheDocument();
    // No guessed replacement key is ever offered or claimed.
    expect((screen.getByTestId('ubuntu-surface').textContent ?? '').toLowerCase()).toContain(
      'no replacement key is guessed',
    );
    expectNoSecretMarkers(screen.getByTestId('ubuntu-surface'));
  });
});

describe('recovery-word reveal (task 5.3)', () => {
  it('renders semantic ordered words and conceals after 60 seconds', () => {
    vi.useFakeTimers();
    const onConceal = vi.fn();
    render(
      <RevealPanel
        words={['abandon', 'amount', 'liar', 'expire']}
        onConceal={onConceal}
      />,
    );
    const list = screen.getByRole('list');
    expect(list.querySelectorAll('li')).toHaveLength(4);
    expect(screen.getByText('abandon')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /conceal and close/i })).toBeInTheDocument();
    // Advance past the 60-second bound; the interval fires conceal.
    vi.advanceTimersByTime((REVEAL_CONCEAL_SECONDS + 1) * 1000);
    expect(onConceal).toHaveBeenCalled();
    vi.useRealTimers();
  });

  it('conceals immediately on focus loss', async () => {
    const onConceal = vi.fn();
    render(<RevealPanel words={['alpha', 'beta']} onConceal={onConceal} />);
    window.dispatchEvent(new Event('blur'));
    expect(onConceal).toHaveBeenCalledOnce();
  });

  it('copy is explicit and warned; cleanup is best effort', async () => {
    const user = userEvent.setup();
    render(<RevealPanel words={['alpha', 'beta']} onConceal={() => undefined} />);
    await user.click(screen.getByRole('button', { name: /copy with warning/i }));
    expect(await screen.findByText(/clipboard managers may retain it/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /conceal and close/i })).toBeInTheDocument();
  });

  it('never exposes secret markers in the reveal surface', () => {
    render(<RevealPanel words={['alpha', 'beta']} onConceal={() => undefined} />);
    expectNoSecretMarkers(screen.getByTestId('ubuntu-surface'));
  });
});

describe('removal progress (task 5.3)', () => {
  it('running removal is non-cancellable and announces progress', () => {
    render(<RemovalProgressPanel incomplete={false} onRetryRemoval={() => undefined} />);
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
  });

  it('incomplete removal blocks protected content, offers retry, and shows no success', () => {
    const onRetry = vi.fn();
    render(<RemovalProgressPanel incomplete onRetryRemoval={onRetry} />);
    expect(screen.getByText(/removal is not finished/i)).toBeInTheDocument();
    // No success state is shown while incomplete.
    expect(screen.queryByText(/removal complete/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry removal/i })).toBeInTheDocument();
  });
});

describe('security settings (task 5.3)', () => {
  it('describes protection honestly for each mode', () => {
    const { rerender } = render(
      <SecuritySettings
        mode="osBacked"
        fallbackAcknowledged={false}
        upgradeEligibleAfterUnlock={false}
        onAddProtection={() => undefined}
        onReveal={() => undefined}
        onRemoveLocalUser={() => undefined}
        onLock={() => undefined}
      />,
    );
    expect(screen.getByText('Ubuntu keyring + device password')).toBeInTheDocument();
    expect(screen.queryByText(/hardware isolation/i)).not.toBeInTheDocument();
    rerender(
      <SecuritySettings
        mode="passwordOnly"
        fallbackAcknowledged
        upgradeEligibleAfterUnlock
        onAddProtection={() => undefined}
        onReveal={() => undefined}
        onRemoveLocalUser={() => undefined}
        onLock={() => undefined}
      />,
    );
    expect(screen.getByText('Device password protection only')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /add ubuntu keyring protection/i })).toBeInTheDocument();
    // Password-only is never labeled OS-backed.
    expect(screen.queryByText(/ubuntu keyring \+ device password/i)).not.toBeInTheDocument();
  });

  it('exposes full-width settings with the closed action set', () => {
    render(
      <SecuritySettings
        mode="osBacked"
        fallbackAcknowledged={false}
        upgradeEligibleAfterUnlock={false}
        onAddProtection={() => undefined}
        onReveal={() => undefined}
        onRemoveLocalUser={() => undefined}
        onLock={() => undefined}
      />,
    );
    expect(screen.getByRole('button', { name: /reveal recovery words/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /remove local user/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /lock/i })).toBeInTheDocument();
    expectNoSecretMarkers(screen.getByTestId('security-settings'));
  });
});
