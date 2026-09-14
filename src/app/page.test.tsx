import { act, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
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
    // Build-isolated auth-only harness (FEAT-016): no entitlement authority in
    // the dev composition; real compositions require the strict gate.
    entitlementRequired: false,
  };
}

/** FEAT-016 strict composition: entitlement gate required (no auth-only mode). */
async function strictHarnessMachineInput(): Promise<AuthMachineInput> {
  const composition = createDevelopmentComposition(true);
  return {
    actors: composition.actors,
    registeredCapabilities: new Set(['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination']),
    safeCoordination: true,
    entitlementRequired: true,
  };
}

describe('HomePage (auth-gated root)', () => {
  it('announces a completed credential restoration from the actual root', async () => {
    render(<AuthRoot machineInputProvider={harnessMachineInput} />);
    await userEvent.setup().click(await screen.findByRole('button', { name: /restore credential file/i }));
    await screen.findByTestId('authenticated-shell');
    expect(screen.getByTestId('restoration-announcement')).toHaveTextContent('Identity restored');
    expect(screen.getByTestId('backup-preservation-notice')).toHaveTextContent('HushVoting did not retain any recovery words');
  });
  it('Back from onboarding awaits child cleanup without rebuilding the authority', async () => {
    const base = await harnessMachineInput();
    const cleanup = vi.fn(() => ({
      operationId: 'cleanup-test' as never,
      result: Promise.resolve({ code: 'ONBOARDING_CLEANUP_COMPLETE' as const }),
      cancel: () => undefined,
    }));
    let inspection = 0;
    const initialize = vi.fn(() => ({ operationId: `inspect-empty-${++inspection}` as never,
      result: Promise.resolve({ code: 'INIT_NO_LOCAL_USER' as const }), cancel: () => undefined }));
    const provider = vi.fn(async () => ({ ...base, actors: { ...base.actors,
      localUserAuthority: { ...base.actors.localUserAuthority!, initialize }, onboarding: {
      ...base.actors.onboarding,
      createUser: { ...base.actors.onboarding.createUser!,
        start: () => ({ operationId: 'onboarding-test' as never, result: new Promise<never>(() => undefined), cancel: () => undefined }),
        cleanup,
      },
    } } }));
    const user = userEvent.setup();
    render(<AuthRoot machineInputProvider={provider} />);
    const create = await screen.findByRole('button', { name: /create user/i });
    const entryState: unknown = window.history.state;
    await user.click(create);
    await act(async () => window.dispatchEvent(new PopStateEvent('popstate', { state: entryState })));
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(provider).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('button', { name: /create user/i })).toBeVisible();
    expect(initialize).toHaveBeenCalledTimes(2);
  });

  it('preserves router-owned history fields through entry, onboarding and authentication', async () => {
    const routerState = { __NA: true, __PRIVATE_NEXTJS_INTERNALS_TREE: { segment: 'root' } };
    window.history.replaceState(routerState, '', '/');
    const user = userEvent.setup();
    render(<AuthRoot machineInputProvider={harnessMachineInput} />);
    const create = await screen.findByRole('button', { name: /create user/i });
    expect(window.history.state).toMatchObject(routerState);
    await user.click(create);
    await screen.findByTestId('authenticated-shell');
    expect(window.history.state).toMatchObject(routerState);
    await act(async () => window.dispatchEvent(new PopStateEvent('popstate', { state: routerState })));
    expect(window.history.state).toMatchObject(routerState);
    expect(screen.getByTestId('authenticated-shell')).toBeVisible();
  });

  it('Back keeps an authenticated entitlement gate and does not rebuild its authority', async () => {
    const provider = vi.fn(strictHarnessMachineInput);
    const user = userEvent.setup();
    render(<AuthRoot machineInputProvider={provider} />);
    const create = await screen.findByRole('button', { name: /create user/i });
    const entryState: unknown = window.history.state;
    await user.click(create);
    await screen.findByTestId('entitlement-gate');
    await act(async () => window.dispatchEvent(new PopStateEvent('popstate', { state: entryState })));
    expect(provider).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('entitlement-gate')).toBeVisible();
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
  });

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

  it('FEAT-016 strict composition keeps the entitlement gate mounted after login (no protected shell)', async () => {
    const user = userEvent.setup();
    render(<AuthRoot machineInputProvider={strictHarnessMachineInput} />);
    await user.click(await screen.findByRole('button', { name: /create user/i }));
    // Identity authenticates, but no entitlement coordinator produced ready
    // truth in this harness, so the blocking gate stays and nothing protected
    // mounts (AC-016-001 at the root seam; real ready flows are Phase 7 BDD).
    expect(await screen.findByTestId('entitlement-gate')).toBeVisible();
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
