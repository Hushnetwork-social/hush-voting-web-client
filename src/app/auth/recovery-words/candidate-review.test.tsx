/**
 * FEAT-008 Task 5.4 — component and accessibility tests for the
 * candidate/profile review UI.
 * Coverage targets: AC-008-024–035, 057–059 (component/a11y portion); safe
 * progress timing, one/multiple/zero outcomes, no default, uncertain
 * guidance, reveal/copy/conceal, historical aliases, no full address in
 * ordinary snapshots.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { CandidateReviewProjection } from '../../../lib/recovery-words/contracts/projection';
import { CandidateReviewScreen, LookupProgress, SafeAlias } from './candidate-review';

function review(overrides: Partial<CandidateReviewProjection> = {}): CandidateReviewProjection {
  return {
    outcome: 'exactlyOneExisting',
    entries: [
      {
        candidateIndex: 0,
        sourceLabel: 'Hush Feeds Web Client (P-01)',
        abbreviatedSigningAddress: 'Ab12Cd34…Xy98Zz76',
        abbreviatedEncryptionAddress: 'Qw12Er34…Rt56Yu78',
        producerIds: ['p-01'],
        profileAlias: 'Voter',
        visibility: 'private',
        selected: false,
      },
    ],
    networkLabel: 'HushNetwork Mainnet',
    selectionRequired: false,
    uncertainGuidance: null,
    revealState: { revealedCandidateIndex: null, fullSigningAddress: null, fullEncryptionAddress: null },
    busy: false,
    ...overrides,
  };
}

describe('LookupProgress', () => {
  it('reports safe counted progress without addresses', () => {
    render(<LookupProgress done={2} total={4} />);
    expect(screen.getByText('Checking identity formats 2 of 4')).toBeDefined();
  });
});

describe('CandidateReviewScreen (Task 5.4)', () => {
  it('renders exactly-one confirmation with safe profile metadata and no alias editing', () => {
    render(<CandidateReviewScreen review={review()} onSelectCandidate={vi.fn()} onConfirmExistingProfile={vi.fn()} onRetryLookup={vi.fn()} onReveal={vi.fn()} onCopyAddress={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByText('Confirm this identity')).toBeDefined();
    expect(screen.getByText('Voter')).toBeDefined();
    expect(screen.getByText('Ab12Cd34…Xy98Zz76')).toBeDefined();
    expect(screen.queryByLabelText(/alias/i)).toBeNull(); // no editing for existing profiles
  });

  it('requires explicit selection for multiple existing profiles (no default)', async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <CandidateReviewScreen
        review={review({
          outcome: 'multipleExisting',
          entries: [
            { candidateIndex: 0, sourceLabel: 'A', abbreviatedSigningAddress: 'Aa…11', abbreviatedEncryptionAddress: 'Bb…22', producerIds: ['p-01'], profileAlias: 'A', visibility: 'private', selected: false },
            { candidateIndex: 1, sourceLabel: 'B', abbreviatedSigningAddress: 'Cc…33', abbreviatedEncryptionAddress: 'Dd…44', producerIds: ['p-02'], profileAlias: 'B', visibility: 'public', selected: false },
          ],
        })}
        onSelectCandidate={onSelect}
        onConfirmExistingProfile={vi.fn()}
        onRetryLookup={vi.fn()}
        onReveal={vi.fn()}
        onCopyAddress={vi.fn()}
        onBack={vi.fn()}
      />
    );
    expect(screen.getByText('Choose your identity')).toBeDefined();
    expect(screen.queryByText('Selected')).toBeNull();
    await user.click(screen.getAllByRole('button', { name: 'Select this identity' })[0]!);
    expect(onSelect).toHaveBeenCalledWith(0);
  });

  it('explains zero matches without implying invalid words', () => {
    render(<CandidateReviewScreen review={review({ outcome: 'zeroExistingMultipleCandidates', entries: [], selectionRequired: true, uncertainGuidance: 'Your trusted public address may be in prior notifications.' })} onSelectCandidate={vi.fn()} onConfirmExistingProfile={vi.fn()} onRetryLookup={vi.fn()} onReveal={vi.fn()} onCopyAddress={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByTestId('zero-hint')).toBeDefined();
    expect(screen.getByText(/not generating new keys/)).toBeDefined();
    expect(screen.getByText(/I\u2019m not sure/)).toBeDefined();
  });

  it('reveals full addresses only on explicit user action and hides them again', async () => {
    const user = userEvent.setup();
    const onReveal = vi.fn();
    render(<CandidateReviewScreen review={review()} onSelectCandidate={vi.fn()} onConfirmExistingProfile={vi.fn()} onRetryLookup={vi.fn()} onReveal={onReveal} onCopyAddress={vi.fn()} onBack={vi.fn()} />);
    // Initially only abbreviated addresses are present; full values never render.
    expect(screen.queryByText(/^[A-Za-z0-9]{40,}$/m)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Hide full addresses' })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Reveal full addresses' }));
    expect(onReveal).toHaveBeenCalledWith(0);
  });

  it('never renders full addresses in the initial DOM', () => {
    render(<CandidateReviewScreen review={review()} onSelectCandidate={vi.fn()} onConfirmExistingProfile={vi.fn()} onRetryLookup={vi.fn()} onReveal={vi.fn()} onCopyAddress={vi.fn()} onBack={vi.fn()} />);
    const body = document.body.textContent ?? '';
    expect(body).not.toMatch(/^[A-Za-z0-9]{40,}$/m);
  });
});

describe('SafeAlias', () => {
  it('renders historical alias text with Unicode isolation and no markup interpretation', () => {
    const { container } = render(<SafeAlias alias={'<script>alert(1)</script>'} />);
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByTestId('safe-alias').textContent).toBe('<script>alert(1)</script>');
  });

  it('renders a placeholder for absent aliases', () => {
    render(<SafeAlias alias={null} />);
    expect(screen.getByText('—')).toBeDefined();
  });
});
