import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AuthRoot from './auth/AuthRoot';
import { createDevelopmentComposition } from '../lib/auth/testing/composition.dev';
import type { AuthMachineInput } from '../lib/auth/state/machine';

/**
 * FEAT-010: synthetic actors are test-harness-only (AC-010-002). This test
 * exercises the same root component through the explicitly named harness
 * machine-input provider; the ordinary `/` path uses real composition.
 */
async function harnessMachineInput(): Promise<AuthMachineInput> {
  const composition = createDevelopmentComposition(true);
  return {
    actors: composition.actors,
    registeredCapabilities: new Set(['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination']),
    safeCoordination: true,
  };
}

describe('HomePage (auth-gated root)', () => {
  it('never mounts protected/authenticated content before authentication', async () => {
    render(<AuthRoot machineInputProvider={harnessMachineInput} />);

    // The foundation hero/targets are gone; no authenticated shell initially.
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
    expect(screen.queryByRole('heading', { level: 1, name: /becoming its own application/i })).toBeNull();

    // Wait for the harness composition and initialization
    // to settle before Vitest tears down the module environment.
    expect(await screen.findByRole('button', { name: /create user/i })).toBeVisible();
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
  });

  it('shows verified identity in the top-right popup and Lock returns to the password gate', async () => {
    const user = userEvent.setup();
    render(<AuthRoot machineInputProvider={harnessMachineInput} />);

    await user.click(await screen.findByRole('button', { name: /create user/i }));
    const aliasTrigger = await screen.findByRole('button', { name: 'Demo User' });
    expect(screen.getByTestId('authenticated-shell')).toBeInTheDocument();

    // Browser Back/popstate is not an implicit Lock command.
    window.dispatchEvent(new PopStateEvent('popstate', { state: { hvToken: 'nav-prior-1' } }));
    expect(screen.getByTestId('authenticated-shell')).toBeInTheDocument();
    expect(screen.queryByLabelText('Device password')).toBeNull();

    await user.click(aliasTrigger);
    expect(screen.getByRole('dialog', { name: 'User information' })).toBeVisible();
    expect(screen.getByText('02abcdef…23456789')).toBeInTheDocument();
    expect(screen.getByText('03abcdef…23456789')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy public signing key' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy public encryption key' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Lock' }));
    expect(await screen.findByLabelText('Device password')).toBeInTheDocument();
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
  });
});
