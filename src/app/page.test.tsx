import { render, screen } from '@testing-library/react';
import AuthRoot from './auth/AuthRoot';

describe('HomePage (auth-gated root)', () => {
  it('never mounts protected/authenticated content before authentication', async () => {
    render(<AuthRoot />);

    // The foundation hero/targets are gone; no authenticated shell initially.
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
    expect(screen.queryByRole('heading', { level: 1, name: /becoming its own application/i })).toBeNull();

    // Wait for the development composition's dynamic import and initialization
    // to settle before Vitest tears down the module environment.
    expect(await screen.findByRole('button', { name: /create user/i })).toBeVisible();
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
  });
});
