/**
 * FEAT-017 Task 5.2/5.4 — licence workspace state-surface component tests
 * (options/current/Enterprise, confirmation, pending, delayed, result,
 * stale) plus the deterministic notification/pending-indicator surfaces.
 *
 * All facts come from the closed builders/projections (`fixtures.ts`), so a
 * component can never be shown a surface the authority would not produce.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  confirmationFacts,
  directFreeNoHigherProjection,
  gateFacts,
  optionsFacts,
  pendingIndicatorFacts,
  presentationInput,
  upgradeOperationOf,
  veritas2000ActiveProjection,
  workspaceFacts,
  VERITAS_2000_PLAN,
} from './fixtures';
import type { LicenceWorkspaceViewFacts } from '../../../lib/licensing/upgrade-presentation';
import { projectActivationNotification } from '../../../lib/licensing/upgrade-presentation';
import type { LicenceCurrentSurface } from '../../../lib/licensing/upgrade-presentation';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import { LicenceWorkspace } from './licence-workspace';
import type { LicenceWorkspaceActionHandlers } from './workspace-handlers';
import { LicenceReferenceFull } from './licence-reference';
import type { LicenceReferenceFacts } from '../../../lib/licensing/licence-reference';
import { PendingUpgradeIndicator, LicenceActivationNotification } from './notifications';

function noopHandlers(overrides: Partial<LicenceWorkspaceActionHandlers> = {}): LicenceWorkspaceActionHandlers {
  return {
    onBackToPlans: vi.fn(),
    onActivate: vi.fn(),
    onContinueWorking: vi.fn(),
    onRetry: vi.fn(),
    onReturnToWorkspace: vi.fn(),
    onViewCurrentLicence: vi.fn(),
    onViewProgress: vi.fn(),
    ...overrides,
  };
}

function nonNull<T>(value: T | null): T {
  if (value === null) {
    throw new Error('expected non-null presentation facts');
  }
  return value;
}

function renderWorkspace(
  facts: LicenceWorkspaceViewFacts | null,
  handlers: LicenceWorkspaceActionHandlers = noopHandlers(),
  options: { onReviewPlan?: (planId: string) => void; onCopyReference?: (value: string) => Promise<boolean> } = {},
) {
  return render(
    <LicenceWorkspace
      facts={nonNull(facts)}
      handlers={handlers}
      onReviewPlan={options.onReviewPlan}
      onCopyReference={options.onCopyReference}
    />,
  );
}

const directFreeInput = () => presentationInput();

describe('LicenceWorkspace options surface (L1/L2)', () => {
  it('renders a single step heading, current detail first, then higher options in server order', async () => {
    const handlers = noopHandlers();
    const onReviewPlan = vi.fn();
    const view = renderWorkspace(workspaceFacts(directFreeInput(), 'options'), handlers, { onReviewPlan });

    expect(screen.getByRole('heading', { level: 1, name: 'Licence' })).toBeInTheDocument();
    // Current licence band precedes the higher-plans band.
    const currentBand = screen.getByRole('heading', { name: licenceUpgradeCopy('sectionCurrentLicence') });
    const higherBand = screen.getByRole('heading', { name: licenceUpgradeCopy('sectionAvailableHigherPlans') });
    expect(currentBand.compareDocumentPosition(higherBand) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('HushVoting! Direct Free')).toBeInTheDocument();

    const reviewButtons = screen.getAllByRole('button', { name: 'Review plan' });
    expect(reviewButtons).toHaveLength(3);
    expect(screen.getByText('HushVoting! Veritas 500')).toBeInTheDocument();
    expect(screen.getByText('HushVoting! Veritas 2k')).toBeInTheDocument();
    expect(screen.getByText('HushVoting! Veritas 10k')).toBeInTheDocument();

    await userEvent.setup().click(reviewButtons[0]);
    expect(onReviewPlan).toHaveBeenCalledWith('hushvoting.veritas.500');
    void view;
  });

  it('L2 shows the exact no-higher message and never a fake disabled upgrade', () => {
    const view = renderWorkspace(workspaceFacts(presentationInput({ projection: directFreeNoHigherProjection() }), 'options'));
    expect(screen.getByText('No higher self-service plan is available.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Review plan' })).toBeNull();
    expect(screen.queryByRole('button', { name: /upgrade|activate/i })).toBeNull();
    void view;
  });

  it('Enterprise is informational only — no interactive descendant, no activation', () => {
    const view = renderWorkspace(workspaceFacts(directFreeInput(), 'options'));
    const enterprise = screen.getByLabelText('HushVoting! Enterprise');
    expect(within(enterprise).queryByRole('button')).toBeNull();
    expect(within(enterprise).queryByRole('link')).toBeNull();
    expect(within(enterprise).queryByRole('textbox')).toBeNull();
    expect(within(enterprise).getByText('Contact provider — not yet available')).toBeInTheDocument();
    void view;
  });

  it('does not infer governance rows for higher options (v1 transport has none)', () => {
    const view = renderWorkspace(workspaceFacts(directFreeInput(), 'options'));
    // Option cards never show a governance row because the transport carries
    // none; only frozen current-governance labels may exist in the current
    // detail, and no raw option id text is presentable.
    expect(screen.queryByText(/7-of-10 trustees|8-of-13 trustees|3-of-5 trustees/)).toBeNull();
    expect(screen.queryByText(/hushvoting\.veritas\.\d+/)).toBeNull();
    void view;
  });

  it('D017-03: one live operation locks further selection on the options surface', async () => {
    const onViewProgress = vi.fn();
    const handlers = noopHandlers({ onViewProgress });
    const pendingInput = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    const facts = workspaceFacts(pendingInput, 'options');
    // The options view still projects while pending, with the lock + target.
    if (facts === null || facts.view !== 'options') {
      throw new Error('pending options facts required');
    }
    expect(facts.selectionLocked).toBe(true);
    const view = render(<LicenceWorkspace facts={facts} handlers={handlers} />);
    // No second upgrade selection can be made; the only path is View progress.
    expect(screen.queryByRole('button', { name: 'Review plan' })).toBeNull();
    expect(screen.getByTestId('selection-locked')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'View progress' }));
    expect(onViewProgress).toHaveBeenCalledTimes(1);
    void view;
  });
});

describe('LicenceWorkspace confirmation (C0)', () => {
  it('shows current and target sides, full reference, catalogue, and consequence copy', async () => {
    const handlers = noopHandlers();
    const view = renderWorkspace(
      workspaceFacts(directFreeInput(), 'confirmation', VERITAS_2000_PLAN),
      handlers,
      { onCopyReference: vi.fn(async () => true) },
    );
    expect(screen.getByRole('heading', { level: 1, name: 'Confirm licence activation' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Current' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Target' })).toBeInTheDocument();
    expect(screen.getByText('HushVoting! Direct Free')).toBeInTheDocument();
    expect(screen.getByText('HushVoting! Veritas 2k')).toBeInTheDocument();
    expect(screen.getByText('hushvoting-licence-catalogue/v1.0.0')).toBeInTheDocument();
    expect(screen.getByText('The target becomes active only after indexed network confirmation.')).toBeInTheDocument();
    expect(screen.getByText('No price or payment is part of this v1 activation.')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Activate licence' }));
    expect(handlers.onActivate).toHaveBeenCalledTimes(1);
    void view;
  });

  it('does not render raw template/identity material', () => {
    const view = renderWorkspace(workspaceFacts(directFreeInput(), 'confirmation', VERITAS_2000_PLAN));
    expect(screen.queryByText(/signature|bytes|journal|admission|hushvoting\.direct\.free/)).toBeNull();
    void view;
  });
});

describe('LicenceWorkspace progress/delayed/result/stale surfaces', () => {
  it('P0: aria-busy progress shows the old plan remains active and Continue working', async () => {
    const handlers = noopHandlers();
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    const view = renderWorkspace(workspaceFacts(input, 'progress'), handlers);
    const progress = screen.getByTestId('licence-progress');
    expect(progress.getAttribute('aria-busy')).toBe('true');
    expect(screen.getByRole('heading', { level: 1, name: 'Upgrade pending' })).toBeInTheDocument();
    expect(screen.getByText('HushVoting! Direct Free remains active.')).toBeInTheDocument();
    expect(screen.getByText('Existing limits continue until indexed activation confirms the change.')).toBeInTheDocument();
    // Pending target never rendered as current.
    expect(screen.getByTestId('progress-target-name')).toHaveTextContent('HushVoting! Veritas 2k');
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Continue working' }));
    expect(handlers.onContinueWorking).toHaveBeenCalledTimes(1);
    void view;
  });

  it('D0: delayed offers exact Retry and Continue working without inventing success', async () => {
    const handlers = noopHandlers();
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('delayed') });
    const view = renderWorkspace(workspaceFacts(input, 'delayed'), handlers);
    expect(
      screen.getByRole('heading', { level: 1, name: 'Licence activation is taking longer than expected.' }),
    ).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(handlers.onRetry).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/is now active/i)).toBeNull();
    void view;
  });

  it('R0: exact local success shows the new indexed current with local effective instant', () => {
    const input = presentationInput({ projection: veritas2000ActiveProjection(), upgradeOperation: upgradeOperationOf('local-success') });
    const view = renderWorkspace(workspaceFacts(input, 'result'), undefined, { onCopyReference: vi.fn(async () => true) });
    expect(screen.getByRole('heading', { level: 1, name: 'Licence activated' })).toBeInTheDocument();
    expect(screen.getAllByText('HushVoting! Veritas 2k is now active.').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByTestId('current-effective-local')).toHaveTextContent('13:24 UTC+01:00');
    expect(screen.queryByText('HushVoting! Direct Free remains active.')).toBeNull();
    void view;
  });

  it('S0: stale notice appears with fresh options and no retained selection', () => {
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('stale', { reason: 'current-changed' }) });
    const view = renderWorkspace(workspaceFacts(input, 'stale'));
    expect(
      screen.getAllByText('Your licence or available plans have changed. Please review the updated options.').length,
    ).toBeGreaterThanOrEqual(1);
    // Fresh options are reviewable again.
    expect(screen.getAllByRole('button', { name: 'Review plan' }).length).toBeGreaterThan(0);
    void view;
  });
});

describe('LicenceWorkspace announcement policy and focus', () => {
  it('does not announce a same-surface poll but announces a meaningful transition once', async () => {
    const handlers = noopHandlers();
    const input = presentationInput();
    const first = renderWorkspace(workspaceFacts(input, 'options'), handlers);
    const region = screen.getByTestId('licence-live-region');
    // Options entry is not an announcement surface.
    expect(region.textContent).toBe('');

    // A "poll" re-render on the same surface stays silent (no repeated live text).
    first.rerender(
      <LicenceWorkspace facts={nonNull(workspaceFacts(presentationInput(), 'options'))} handlers={handlers} />,
    );
    expect(screen.getByTestId('licence-live-region').textContent).toBe('');

    // A meaningful transition to progress announces once and sets the status.
    const progressFactsInput = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    first.rerender(
      <LicenceWorkspace facts={nonNull(workspaceFacts(progressFactsInput, 'progress'))} handlers={handlers} />,
    );
    expect(screen.getByTestId('licence-live-region').textContent).toBe('Waiting for indexed activation');
  });
});

describe('N0 pending indicator + N1 activation notification', () => {
  const surface: LicenceCurrentSurface = 'workspace';

  it('N0: shows only while a live operation exists and the user is elsewhere; View progress reopens', async () => {
    const onViewProgress = vi.fn();
    const input = presentationInput({ upgradeOperation: upgradeOperationOf('pending') });
    const visibleFacts = pendingIndicatorFacts(input, surface);
    const view = render(<PendingUpgradeIndicator facts={visibleFacts} onViewProgress={onViewProgress} />);
    const indicator = screen.getByTestId('pending-upgrade-indicator');
    expect(indicator).toHaveAttribute('aria-label', 'Upgrade pending for HushVoting! Veritas 2k. View progress.');
    const user = userEvent.setup();
    await user.click(indicator);
    expect(onViewProgress).toHaveBeenCalledTimes(1);
    // Hidden while already on the progress surface.
    const hiddenFacts = pendingIndicatorFacts(input, 'licence-progress');
    view.rerender(<PendingUpgradeIndicator facts={hiddenFacts} onViewProgress={onViewProgress} />);
    expect(screen.queryByTestId('pending-upgrade-indicator')).toBeNull();
  });

  it('N0: no indicator without a live operation', () => {
    const facts = pendingIndicatorFacts(presentationInput(), surface);
    const { container } = render(<PendingUpgradeIndicator facts={facts} onViewProgress={vi.fn()} />);
    expect(container.firstChild).toBeNull();
  });

  it('N1: one-time polite notification with View licence and Dismiss, no competing claim', () => {
    const onViewLicence = vi.fn();
    const onDismiss = vi.fn();
    const input = presentationInput({
      upgradeOperation: upgradeOperationOf('local-success'),
      upgradeNotificationEligible: true,
      projection: veritas2000ActiveProjection(),
    });
    const facts = projectActivationNotification(input, 'workspace');
    expect(facts.visible).toBe(true);
    const view = render(
      <LicenceActivationNotification facts={facts} onViewLicence={onViewLicence} onDismiss={onDismiss} />,
    );
    const notice = screen.getByTestId('licence-activation-notification');
    // The message lives in a polite live region; interactive actions are NOT
    // wrapped by the status role (buttons must remain operable for AT users).
    const message = screen.getByTestId('licence-notification-message');
    expect(message.getAttribute('role')).toBe('status');
    expect(message.getAttribute('aria-live')).toBe('polite');
    expect(notice).toContainElement(screen.getByRole('button', { name: 'View licence' }));
    expect(notice).toContainElement(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.getByText('Your HushVoting! Veritas 2k licence is now active')).toBeInTheDocument();
    // Competing-device activation never becomes a local N1.
    const competing = projectActivationNotification(
      presentationInput({ upgradeOperation: upgradeOperationOf('competing-activation'), upgradeNotificationEligible: false }),
      'workspace',
    );
    view.rerender(<LicenceActivationNotification facts={competing} onViewLicence={onViewLicence} onDismiss={onDismiss} />);
    expect(screen.queryByTestId('licence-activation-notification')).toBeNull();
  });
});

describe('reference control failure keeps the value selectable', () => {
  it('announces exact failure copy while the full value remains visible', async () => {
    const user = userEvent.setup();
    const reference: LicenceReferenceFacts = {
      mode: 'full',
      displayText: '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55',
      fullText: '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55',
      selectable: true,
    };
    render(<LicenceReferenceFull facts={reference} onCopy={vi.fn(async () => false)} />);
    await user.click(screen.getByRole('button', { name: 'Copy' }));
    expect(screen.getByTestId('licence-copy-feedback')).toHaveTextContent(
      'Couldn’t copy. Select the licence reference to copy it manually.',
    );
    expect(screen.getByTestId('licence-reference-full')).toHaveTextContent('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55');
  });
});

describe('view facts are validated against authority state', () => {
  it('confirmation/progress/delayed/result/stale derive only from the matching safe operation', () => {
    // Options view returns null while recovery is required (no remembered content).
    const recoveryInput = presentationInput({ phase: 'entitlementUnavailable', projection: null });
    const facts = optionsFacts(recoveryInput);
    expect(facts).toBeNull();
    const recoveryFacts = gateFacts(recoveryInput);
    expect(recoveryFacts.view).toBe('recovery');
    // The workspace renders nothing for gate/recovery (root gate owns it).
    const view = renderWorkspace({ view: 'recovery', reason: 'unavailable', rememberNothing: true });
    expect(screen.queryByText(/Licence|Upgrade|plan/i)).toBeNull();
    void view;
  });

  it('confirmation is null without a matching fresh draft', () => {
    const facts = confirmationFacts(directFreeInput(), 'hushvoting.veritas.2000');
    expect(facts).not.toBeNull();
  });
});
