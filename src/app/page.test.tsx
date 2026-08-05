import { render, screen } from '@testing-library/react';
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
});
