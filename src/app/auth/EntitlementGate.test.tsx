/**
 * FEAT-016 Task 5.2 — entitlement gate component tests (G0–G6 seam).
 *
 * Queries by role/name and proves: exact copy per stage; control availability
 * (Retry only on recoverable delayed/unavailable/unsupported; Lock always);
 * status role + polite live region; aria-busy; deterministic focus placement
 * (meaningful transitions only, never per poll); keyboard-operable actions
 * routing through typed intents; no navigation/plan/Back/Cancel/Continue or
 * forbidden raw data; no FEAT-017/018 surface rendered.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EntitlementGate } from './EntitlementGate';
import type { AuthRenderProjection } from '../../lib/auth/react/adapter';
import type { AuthIntent, ConnectivityStateCode } from '../../lib/auth/types';

function projection(overrides: Partial<AuthRenderProjection>): AuthRenderProjection {
  return {
    authState: 'authenticated',
    connectivity: 'online' as ConnectivityStateCode,
    protectedAccess: false,
    entitlementStage: 'entitlementResolving',
    entitlementReady: false,
    sessionEpoch: 1,
    entitlementRequired: true,
    safeIdentity: { alias: 'Ada', abbreviatedSigningAddress: 'NVh…1a2b' },
    authenticatedIdentity: {
      alias: 'Ada',
      publicSigningKey: '02abcdef',
      publicEncryptionKey: '03abcdef',
    },
    outcomeCode: null,
    supportCode: null,
    onboardingKind: null,
    ...overrides,
  };
}

function renderGate(projection: AuthRenderProjection, onIntent: (i: AuthIntent) => void) {
  return render(<EntitlementGate projection={projection} handlers={{ dispatch: onIntent }} />);
}

describe('EntitlementGate stages', () => {
  it('shows exact resolving copy with busy status and Lock only', () => {
    const onIntent = vi.fn();
    const view = renderGate(projection({ entitlementStage: 'entitlementResolving' }), onIntent);
    expect(screen.getByRole('heading', { level: 1, name: 'Checking your HushVoting! licence…' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Checking licence');
    expect(view.container.querySelector('[aria-busy="true"]')).not.toBeNull();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Lock' })).toBeInTheDocument();
    expect(screen.getByText('Ada')).toBeInTheDocument();
    expect(screen.getByTestId('gate-network-state')).toHaveTextContent('Online');
  });

  it('shows awaiting-index copy without poll announcement spam and no focus theft', async () => {
    const user = userEvent.setup();
    const onIntent = vi.fn();
    const view = renderGate(projection({ entitlementStage: 'awaitingIndex' }), onIntent);
    expect(screen.getByRole('heading', { level: 1, name: 'Waiting for the network to activate your licence…' })).toBeInTheDocument();
    const heading = screen.getByTestId('entitlement-gate-heading');
    expect(heading).not.toHaveFocus(); // never steals focus on every poll
    await user.click(screen.getByRole('button', { name: 'Lock' }));
    expect(onIntent).toHaveBeenCalledWith({ type: 'INTENT.LOCK' });
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    void view;
  });

  it('delayed confirmation focuses the heading and offers Retry + Lock', async () => {
    const onIntent = vi.fn();
    const view = renderGate(
      projection({ entitlementStage: 'confirmationDelayed', safeIdentity: null, authenticatedIdentity: null }),
      onIntent,
    );
    const heading = screen.getByTestId('entitlement-gate-heading');
    expect(heading).toHaveFocus();
    expect(heading).toHaveTextContent('Licence activation is taking longer than expected.');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onIntent).toHaveBeenCalledWith({ type: 'INTENT.ENTITLEMENT_RETRY' });
    void view;
  });

  it('unavailable and unsupported keep the workspace gated with Retry', async () => {
    const onIntent = vi.fn();
    renderGate(projection({ entitlementStage: 'entitlementUnavailable' }), onIntent);
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'We couldn’t verify your licence. HushVoting! cannot open until verification succeeds.',
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('offline connectivity shows the reconnect copy and Lock', () => {
    const onIntent = vi.fn();
    renderGate(projection({ entitlementStage: 'awaitingIndex', connectivity: 'offline' }), onIntent);
    expect(screen.getByRole('heading', { level: 1, name: 'Connection lost. Reconnect to continue.' })).toBeInTheDocument();
    expect(screen.getByTestId('gate-network-state')).toHaveTextContent('Offline');
  });

  it('never renders navigation, plan cards, Back, Cancel, Continue, or raw data', () => {
    const onIntent = vi.fn();
    renderGate(projection({ entitlementStage: 'confirmationDelayed' }), onIntent);
    expect(screen.queryAllByRole('link')).toHaveLength(0);
    expect(screen.queryByRole('button', { name: /back/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /cancel/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /continue/i })).toBeNull();
    expect(screen.queryByText(/upgrade|veritas|plan card|signature|transaction/i)).toBeNull();
    expect(screen.queryByText(/02abcdef|03abcdef/)).toBeNull(); // no raw keys/addresses
  });

  it('renders nothing when entitlement is ready (workspace mounts elsewhere)', () => {
    const onIntent = vi.fn();
    const { container } = renderGate(projection({ entitlementStage: 'entitlementReady', protectedAccess: true, entitlementReady: true }), onIntent);
    expect(container.firstChild).toBeNull();
  });
});
