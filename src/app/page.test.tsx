import { render, screen } from '@testing-library/react';
import AuthRoot from './auth/AuthRoot';

describe('HomePage (auth-gated root)', () => {
  it('never mounts protected/authenticated content before authentication', () => {
    render(<AuthRoot />);

    // The foundation hero/targets are gone; no authenticated shell initially.
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
    expect(screen.queryByRole('heading', { level: 1, name: /becoming its own application/i })).toBeNull();
  });
});
