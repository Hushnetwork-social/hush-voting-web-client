import { render, screen } from '@testing-library/react';
import HomePage from './page';

describe('HomePage', () => {
  it('describes each supported delivery target without presenting live election actions', () => {
    render(<HomePage />);

    expect(screen.getByRole('heading', { level: 1, name: /becoming its own application/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'Web application' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'Ubuntu desktop' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'Android application' })).toBeInTheDocument();
    expect(screen.getByText(/does not yet expose live election actions/i)).toBeInTheDocument();
  });
});
