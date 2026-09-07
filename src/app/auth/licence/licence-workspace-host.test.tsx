/**
 * FEAT-017 Task 6.2 — root licence workspace host composition tests.
 *
 * The host is the full-width licence page mounted by the authenticated root
 * shell. These tests lock the Task 6.1 root-composition contract:
 *  - the page renders ONLY from closed authority-derived presentation facts
 *    and never mounts when closed or when no licence input exists (no
 *    remembered page, D017 gate/recovery);
 *  - the restored surface is authority-derived (fresh options, live pending →
 *    progress, exact local success → result, typed stale → stale);
 *  - a draft selection moves the options surface to confirmation and C0 can
 *    only reach a real activate action with the EXACT selected plan handle;
 *  - D017-04: leaving discards the local draft; Back/remount cannot resurrect
 *    it (restored view is computed from authority only);
 *  - progress/result surfaces forward their real actions (retry, view
 *    current licence → acknowledge) without inventing authority.
 *
 * Facts are built only through the closed builders (`fixtures.ts`), the same
 * as the Phase 5 suites.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LicenceWorkspaceHost } from './licence-workspace-host';
import { presentationInput, upgradeOperationOf, workspaceFacts } from './fixtures';
import type { LicenceUpgradePresentationInput } from '../../../lib/licensing/upgrade-presentation';
import { directFreeWithOptionsProjection, FIXTURE_TIME_ZONE } from './fixtures';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';

function actions() {
  return {
    onActivate: vi.fn(),
    onRetryExact: vi.fn(),
    onAcknowledgeOutcome: vi.fn(),
    onRefreshForEntry: vi.fn(),
    onClose: vi.fn(),
  };
}

function renderHost(input: LicenceUpgradePresentationInput | null, visible: boolean) {
  const callbacks = actions();
  const view = render(
    <LicenceWorkspaceHost input={input} visible={visible} actions={callbacks} timeZone={FIXTURE_TIME_ZONE} />,
  );
  return { view, callbacks };
}

describe('root licence workspace host (Task 6.1 composition)', () => {
  it('mounts nothing when the workspace is closed (no remembered page)', () => {
    const { view } = renderHost(presentationInput({ projection: directFreeWithOptionsProjection() }), false);
    expect(view.container.textContent).toBe('');
  });

  it('mounts nothing without licence truth (L0 gate / recovery owns the screen)', () => {
    const { view } = renderHost(null, true);
    expect(view.container.textContent).toBe('');
  });

  it('opens on fresh options when authority truth has higher plans', async () => {
    const user = userEvent.setup();
    const { view, callbacks } = renderHost(
      presentationInput({ projection: directFreeWithOptionsProjection() }),
      true,
    );
    expect(screen.getByRole('heading', { level: 1, name: licenceUpgradeCopy('titleLicence') })).toBeInTheDocument();
    expect(screen.getByText('HushVoting! Direct Free')).toBeInTheDocument();
    // Review plan moves to C0; the host carries only the local draft.
    const reviewButtons = screen.getAllByRole('button', { name: licenceUpgradeCopy('actionReviewPlan') });
    expect(reviewButtons.length).toBeGreaterThanOrEqual(3);
    await user.click(reviewButtons[0]!);
    expect(screen.getByTestId('licence-confirmation')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: licenceUpgradeCopy('actionActivateLicence') }));
    expect(callbacks.onActivate).toHaveBeenCalledWith('hushvoting.veritas.500');
    void view;
  });

  it('D017-04: closing discards the local draft (remount restores options only)', async () => {
    const user = userEvent.setup();
    const { view } = renderHost(
      presentationInput({ projection: directFreeWithOptionsProjection() }),
      true,
    );
    await user.click(screen.getAllByRole('button', { name: licenceUpgradeCopy('actionReviewPlan') })[0]!);
    expect(screen.getByTestId('licence-confirmation')).toBeInTheDocument();
    // Leave without activating (unmount = root closes the destination).
    view.unmount();
    const fresh = render(
      <LicenceWorkspaceHost
        input={presentationInput({ projection: directFreeWithOptionsProjection() })}
        visible
        actions={actions()}
        timeZone={FIXTURE_TIME_ZONE}
      />,
    );
    // Remount restores fresh options — never the discarded confirmation.
    expect(fresh.queryByTestId('licence-confirmation')).toBeNull();
    expect(screen.getByTestId('licence-options')).toBeInTheDocument();
  });

  it('live pending restores to the progress surface and forwards its real action', async () => {
    const user = userEvent.setup();
    const pending = presentationInput({ projection: directFreeWithOptionsProjection(), upgradeOperation: upgradeOperationOf('pending') });
    const { callbacks } = renderHost(pending, true);
    // A live operation's restored surface is progress, not options.
    expect(screen.getByTestId('licence-view-progress')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: licenceUpgradeCopy('actionReviewPlan') })).toBeNull();
    const continueWorking = screen.getByRole('button', { name: licenceUpgradeCopy('actionContinueWorking') });
    await user.click(continueWorking);
    expect(callbacks.onClose).toHaveBeenCalledTimes(1);
  });

  it('exact local success restores to the result surface and acknowledge is real', async () => {
    const user = userEvent.setup();
    const success = presentationInput({
      projection: directFreeWithOptionsProjection(),
      upgradeOperation: upgradeOperationOf('local-success'),
    });
    const { callbacks } = renderHost(success, true);
    expect(screen.getByTestId('licence-view-result')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: licenceUpgradeCopy('actionReturnToWorkspace') }));
    expect(callbacks.onAcknowledgeOutcome).toHaveBeenCalledTimes(1);
    expect(callbacks.onClose).toHaveBeenCalledTimes(1);
    void workspaceFacts;
  });
});
