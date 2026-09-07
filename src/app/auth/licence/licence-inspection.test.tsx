/**
 * FEAT-017 Task 5.2 — Account (A0/A0P) and licence inspection surface tests:
 * account summary action precedence, current detail dates/reference, options
 * order/no-higher/Enterprise, and reference copy feedback.
 *
 * Facts always come from the closed builders/projections (`fixtures.ts`), so
 * a component can never be shown a surface the authority would not produce.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthenticatedUserMenu } from '../AuthenticatedUserMenu';
import { LicenceWorkspace } from './licence-workspace';
import type { LicenceWorkspaceActionHandlers } from './workspace-handlers';
import { LicenceReferenceFull } from './licence-reference';
import type { LicenceReferenceFacts } from '../../../lib/licensing/licence-reference';
import {
  accountFacts,
  directFreeNoHigherProjection,
  enterpriseActiveProjection,
  optionsFacts,
  presentationInput,
  upgradeOperationOf,
} from './fixtures';
import type { LicenceWorkspaceViewFacts } from '../../../lib/licensing/upgrade-presentation';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';

const identity = {
  alias: 'Alice',
  publicSigningKey: '02abcdef0123456789',
  publicEncryptionKey: '03abcdef0123456789',
};

function noopHandlers(): LicenceWorkspaceActionHandlers {
  return {
    onBackToPlans: vi.fn(),
    onActivate: vi.fn(),
    onContinueWorking: vi.fn(),
    onRetry: vi.fn(),
    onReturnToWorkspace: vi.fn(),
    onViewCurrentLicence: vi.fn(),
    onViewProgress: vi.fn(),
    onReviewPlan: vi.fn(),
  };
}

function nonNull<T>(value: T | null): T {
  if (value === null) {
    throw new Error('expected non-null presentation facts');
  }
  return value;
}

async function openAccountMenu() {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Alice' }));
  return user;
}

describe('Account licence summary (A0/A0P)', () => {
  it('shows the exact indexed plan, concise cap/validity, shortened reference, and Upgrade action', async () => {
    const facts = accountFacts(presentationInput());
    const onLicenceAction = vi.fn();
    const view = render(
      <AuthenticatedUserMenu identity={identity} onLock={() => undefined} licence={{ facts, onLicenceAction }} />,
    );
    await openAccountMenu();

    const dialog = screen.getByRole('dialog', { name: 'User information' });
    const block = within(dialog).getByLabelText('Licence');
    expect(within(block).getByText('HushVoting! Direct Free')).toBeInTheDocument();
    expect(within(block).getByText('Active')).toBeInTheDocument();
    expect(within(block).getByText('Up to 100 eligible voters')).toBeInTheDocument();
    expect(within(block).getByText('Perpetual')).toBeInTheDocument();
    expect(within(block).getByTestId('licence-short-reference')).toHaveTextContent('5f2d9e11…c9d3e');
    const action = within(block).getByRole('button', { name: 'Upgrade' });
    await userEvent.setup().click(action);
    expect(onLicenceAction).toHaveBeenCalledWith('upgrade');
    // A0 action closes the flyout (licence flow opens in the workspace).
    expect(screen.queryByRole('dialog', { name: 'User information' })).toBeNull();

    // Lock is part of the flyout while open.
    void view;
  });

  it('shows View licence when no higher plan is available (D017-05)', async () => {
    const facts = accountFacts(presentationInput({ projection: directFreeNoHigherProjection() }));
    const view = render(
      <AuthenticatedUserMenu identity={identity} onLock={() => undefined} licence={{ facts, onLicenceAction: vi.fn() }} />,
    );
    await openAccountMenu();
    expect(screen.getByRole('button', { name: 'View licence' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Upgrade' })).toBeNull();
    void view;
  });

  it('never offers self-service activation for a recognised active Enterprise current', async () => {
    const facts = accountFacts(presentationInput({ projection: enterpriseActiveProjection() }));
    const view = render(
      <AuthenticatedUserMenu identity={identity} onLock={() => undefined} licence={{ facts, onLicenceAction: vi.fn() }} />,
    );
    await openAccountMenu();
    expect(screen.getByText('HushVoting! Enterprise')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View licence' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /activate|upgrade/i })).toBeNull();
    void view;
  });

  it('A0P: pending keeps the old plan as current and shows the separate target + View progress', async () => {
    const facts = accountFacts(presentationInput({ upgradeOperation: upgradeOperationOf('pending') }));
    const onLicenceAction = vi.fn();
    const view = render(
      <AuthenticatedUserMenu identity={identity} onLock={() => undefined} licence={{ facts, onLicenceAction }} />,
    );
    await openAccountMenu();
    const block = within(screen.getByRole('dialog', { name: 'User information' })).getByLabelText('Licence');
    expect(within(block).getByText('HushVoting! Direct Free')).toBeInTheDocument();
    expect(within(block).getByTestId('account-pending-target')).toHaveTextContent('HushVoting! Veritas 2k');
    expect(within(block).getByTestId('account-pending-status')).toHaveTextContent('Waiting for indexed activation');
    expect(within(block).getByText('Current limits remain in effect')).toBeInTheDocument();
    const action = within(block).getByRole('button', { name: 'View progress' });
    await userEvent.setup().click(action);
    expect(onLicenceAction).toHaveBeenCalledWith('view-progress');
    void view;
  });

  it('renders no remembered licence block while the authority has no ready truth', async () => {
    const facts = accountFacts(presentationInput({ phase: 'resolving', projection: null }));
    const view = render(
      <AuthenticatedUserMenu identity={identity} onLock={() => undefined} licence={{ facts, onLicenceAction: vi.fn() }} />,
    );
    await openAccountMenu();
    expect(screen.queryByLabelText('Licence')).toBeNull();
    expect(screen.getByRole('dialog', { name: 'User information' })).toBeVisible();
    void view;
  });
});

describe('Licence inspection surfaces (L1/L2)', () => {
  function renderOptions(facts: LicenceWorkspaceViewFacts | null) {
    const view = render(<LicenceWorkspace facts={nonNull(facts)} handlers={noopHandlers()} />);
    return view;
  }

  it('renders one step heading, current first, then server-ordered higher options', async () => {
    const onReviewPlan = vi.fn();
    const facts = optionsFacts(presentationInput());
    const view = render(
      <LicenceWorkspace facts={nonNull(facts)} handlers={noopHandlers()} onReviewPlan={onReviewPlan} />,
    );
    expect(screen.getByRole('heading', { level: 1, name: 'Licence' })).toBeInTheDocument();
    const currentBand = screen.getByRole('heading', { name: licenceUpgradeCopy('sectionCurrentLicence') });
    const higherBand = screen.getByRole('heading', { name: licenceUpgradeCopy('sectionAvailableHigherPlans') });
    expect(currentBand.compareDocumentPosition(higherBand) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('HushVoting! Direct Free')).toBeInTheDocument();

    const buttons = screen.getAllByRole('button', { name: 'Review plan' });
    expect(buttons).toHaveLength(3);
    await userEvent.setup().click(buttons[1]);
    expect(onReviewPlan).toHaveBeenCalledWith('hushvoting.veritas.2000');
    void view;
  });

  it('L2 no-higher shows the exact message and never a disabled fake upgrade button', () => {
    const facts = optionsFacts(presentationInput({ projection: directFreeNoHigherProjection() }));
    const view = renderOptions(facts);
    expect(screen.getByText('No higher self-service plan is available.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Review plan' })).toBeNull();
    expect(screen.queryByRole('button', { name: /upgrade|activate/i })).toBeNull();
    void view;
  });

  it('Enterprise surface is informational only with no interactive descendant', () => {
    const facts = optionsFacts(presentationInput());
    const view = renderOptions(facts);
    const enterprise = screen.getByLabelText('HushVoting! Enterprise');
    expect(within(enterprise).queryByRole('button')).toBeNull();
    expect(within(enterprise).queryByRole('link')).toBeNull();
    expect(within(enterprise).getByText('Contact provider — not yet available')).toBeInTheDocument();
    void view;
  });

  it('current detail renders local effective instant, perpetual (no invented expiry), and full reference', async () => {
    const copyReference = vi.fn(async () => true);
    const facts = optionsFacts(presentationInput());
    const view = render(
      <LicenceWorkspace facts={nonNull(facts)} handlers={noopHandlers()} onCopyReference={copyReference} />,
    );
    const detail = screen.getByLabelText('HushVoting! Direct Free');
    expect(within(detail).getByText('Perpetual')).toBeInTheDocument();
    // Direct Free fixture is perpetual: no invented expiry text appears.
    expect(screen.queryByText(/expires/i)).toBeNull();
    expect(screen.getByTestId('current-effective-local')).toHaveTextContent(/UTC\+01:00/);
    expect(screen.getByTestId('licence-reference-full')).toHaveTextContent('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');

    await userEvent.setup().click(screen.getByRole('button', { name: 'Copy' }));
    expect(copyReference).toHaveBeenCalledWith('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    expect(screen.getByTestId('licence-copy-feedback')).toHaveTextContent('Copied licence reference.');
    void view;
  });

  it('reference copy failure announces exact feedback and keeps the full value visible/selectable', async () => {
    const reference: LicenceReferenceFacts = {
      mode: 'full',
      displayText: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
      fullText: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
      selectable: true,
    };
    const view = render(<LicenceReferenceFull facts={reference} onCopy={vi.fn(async () => false)} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Copy' }));
    expect(screen.getByTestId('licence-copy-feedback')).toHaveTextContent(
      'Couldn’t copy. Select the licence reference to copy it manually.',
    );
    expect(screen.getByTestId('licence-reference-full')).toHaveTextContent('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    void view;
  });

  it('never exposes governance rows or raw plan ids on higher option cards', () => {
    const facts = optionsFacts(presentationInput());
    const view = renderOptions(facts);
    // Higher option cards carry no governance (v1 transport); no raw plan-id
    // text leaks into the presented surface.
    expect(screen.queryByText(/7-of-10 trustees|8-of-13 trustees|3-of-5 trustees/)).toBeNull();
    expect(screen.queryByText(/hushvoting\.veritas\.\d+/)).toBeNull();
    void view;
  });
});
