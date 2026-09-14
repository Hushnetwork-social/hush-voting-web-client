/**
 * FEAT-017 Task 6.2 — top-bar licence surfaces (N0/N1) + clipboard adapter.
 *
 * N0 is reachable while the user works under the old indexed limits; N1 is
 * the one-shot polite notification with real View licence / Dismiss actions.
 * The clipboard adapter returns success/failure so the reference component
 * announces the exact canonical copy (never an uncaught rejection).
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TopBarLicenceSurfaces, createWebClipboardAdapter } from './top-bar-surfaces';
import { presentationInput, upgradeOperationOf, FIXTURE_TIME_ZONE } from './fixtures';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';

describe('TopBarLicenceSurfaces (N0/N1)', () => {
  it('shows N0 while a live operation exists and the user is not on its progress', () => {
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    render(
      <TopBarLicenceSurfaces
        input={input}
        currentSurface="workspace"
        onViewProgress={vi.fn()}
        onViewLicence={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );
    expect(screen.getByTestId('pending-upgrade-indicator')).toBeInTheDocument();
  });

  it('hides N0 while the user is already on the progress surface', () => {
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    render(
      <TopBarLicenceSurfaces
        input={input}
        currentSurface="licence-progress"
        onViewProgress={vi.fn()}
        onViewLicence={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );
    expect(screen.queryByTestId('pending-upgrade-indicator')).toBeNull();
  });

  it('routes N0 view-progress to the real reopen action', async () => {
    const user = userEvent.setup();
    const onViewProgress = vi.fn();
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    render(
      <TopBarLicenceSurfaces
        input={input}
        currentSurface="workspace"
        onViewProgress={onViewProgress}
        onViewLicence={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );
    await user.click(screen.getByTestId('pending-upgrade-indicator'));
    expect(onViewProgress).toHaveBeenCalledTimes(1);
  });

  it('N1 shows once for exact local success while elsewhere and its actions are real', async () => {
    const user = userEvent.setup();
    const onViewLicence = vi.fn();
    const onDismiss = vi.fn();
    const input = presentationInput({
      upgradeOperation: upgradeOperationOf('local-success'),
      upgradeNotificationEligible: true,
    });
    render(
      <TopBarLicenceSurfaces
        input={input}
        currentSurface="workspace"
        onViewProgress={vi.fn()}
        onViewLicence={onViewLicence}
        onDismiss={onDismiss}
      />,
    );
    expect(screen.getByTestId('licence-activation-notification')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: licenceUpgradeCopy('actionViewLicence') }));
    expect(onViewLicence).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: licenceUpgradeCopy('actionDismiss') }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('renders nothing without licence truth (no remembered N0/N1)', () => {
    const { container } = render(
      <TopBarLicenceSurfaces
        input={null}
        currentSurface="workspace"
        onViewProgress={vi.fn()}
        onViewLicence={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );
    expect(container.textContent).toBe('');
    void FIXTURE_TIME_ZONE;
  });
});

describe('Web clipboard adapter (integration-owned write)', () => {
  it('returns true on a successful write', async () => {
    vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
    const adapter = createWebClipboardAdapter();
    await expect(adapter('abc-123')).resolves.toBe(true);
  });

  it('returns false (never throws) when the write fails', async () => {
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    const adapter = createWebClipboardAdapter();
    await expect(adapter('abc-123')).resolves.toBe(false);
  });
});
