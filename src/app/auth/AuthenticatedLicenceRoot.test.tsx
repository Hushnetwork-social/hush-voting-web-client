/**
 * FEAT-017 Task 6.2 — AuthenticatedLicenceRoot composition tests.
 *
 * The root licence content region composes the N0/N1 top-bar surfaces and the
 * full-width LicenceWorkspace page (when open) while keeping the default
 * operational workspace children under the old indexed limits. Actions are
 * forwarded to the real root intent wiring (never page-owned authority).
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthenticatedLicenceRoot, currentSurfaceForOpen } from './AuthenticatedLicenceRoot';
import { presentationInput, upgradeOperationOf, FIXTURE_TIME_ZONE } from './licence/fixtures';
import { licenceUpgradeCopy } from '../../lib/licensing/upgrade-copy';

function actions() {
  return {
    onActivate: vi.fn(),
    onRetryExact: vi.fn(),
    onAcknowledgeOutcome: vi.fn(),
    onRefreshForEntry: vi.fn(),
  };
}

function renderRoot(input: Parameters<typeof presentationInput>[0] extends never ? never : ReturnType<typeof presentationInput> | null, open: boolean) {
  const callbacks = actions();
  const view = render(
    <AuthenticatedLicenceRoot input={input} actions={callbacks} open={open} onClose={() => undefined}>
      <div data-testid="default-workspace">Operational workspace</div>
    </AuthenticatedLicenceRoot>,
  );
  return { view, callbacks };
}

describe('currentSurfaceForOpen', () => {
  it('reports workspace when closed or without facts', () => {
    expect(currentSurfaceForOpen(false, presentationInput())).toBe('workspace');
    expect(currentSurfaceForOpen(true, null)).toBe('workspace');
  });

  it('reports progress/result/options surfaces while open', () => {
    expect(
      currentSurfaceForOpen(true, presentationInput({ upgradeOperation: upgradeOperationOf('pending') })),
    ).toBe('licence-progress');
    expect(
      currentSurfaceForOpen(true, presentationInput({ upgradeOperation: upgradeOperationOf('delayed') })),
    ).toBe('licence-progress');
    expect(
      currentSurfaceForOpen(true, presentationInput({ upgradeOperation: upgradeOperationOf('local-success') })),
    ).toBe('licence-result');
    expect(currentSurfaceForOpen(true, presentationInput())).toBe('licence-options');
  });
});

describe('AuthenticatedLicenceRoot', () => {
  it('keeps the default workspace children when the licence page is closed', () => {
    renderRoot(presentationInput(), false);
    expect(screen.getByTestId('default-workspace')).toBeInTheDocument();
    expect(screen.queryByTestId('licence-workspace-host')).toBeNull();
  });

  it('mounts the full-width licence workspace when open', () => {
    renderRoot(presentationInput(), true);
    expect(screen.getByTestId('licence-workspace-host')).toBeInTheDocument();
    expect(screen.queryByTestId('default-workspace')).toBeNull();
  });

  it('keeps the default workspace mounted while a pending op reconciles (D017-01)', () => {
    renderRoot(presentationInput({ upgradeOperation: upgradeOperationOf('pending') }), false);
    expect(screen.getByTestId('default-workspace')).toBeInTheDocument();
  });

  it('shows N0 over the workspace while a live operation exists', async () => {
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    const { callbacks } = renderRoot(input, false);
    expect(screen.getByTestId('pending-upgrade-indicator')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByTestId('pending-upgrade-indicator'));
    // N0 reopen is a workspace open (refresh-on-entry then the destination).
    expect(callbacks.onRefreshForEntry).toHaveBeenCalledTimes(1);
    void FIXTURE_TIME_ZONE;
    void licenceUpgradeCopy;
  });

  it('routes activate from C0 to the real activation action with the exact plan', async () => {
    const user = userEvent.setup();
    const { callbacks } = renderRoot(presentationInput(), true);
    await user.click(screen.getAllByRole('button', { name: licenceUpgradeCopy('actionReviewPlan') })[0]!);
    await user.click(screen.getByRole('button', { name: licenceUpgradeCopy('actionActivateLicence') }));
    expect(callbacks.onActivate).toHaveBeenCalledWith('hushvoting.veritas.500');
  });

  it('renders the default workspace when no licence facts exist (never a remembered page)', () => {
    renderRoot(null, true);
    expect(screen.getByTestId('default-workspace')).toBeInTheDocument();
    expect(screen.queryByTestId('licence-workspace-host')).toBeNull();
  });
});
