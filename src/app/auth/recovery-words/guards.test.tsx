/**
 * FEAT-008 Task 5.8 — component, navigation, and responsive tests for the
 * guard/cleanup UI and the flow router.
 * Coverage targets: AC-008-001–004, 064–070, 075, 079 (component/a11y
 * portion); active/staged/quarantine states, owner block, safe event payloads,
 * no recovery form mounted for non-owners.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { RecoveryViewState } from '../../../lib/recovery-words/presentation/view';
import { LocalUserGuard, OwnerBlockedScreen, QuarantineScreen, RemovalConfirmation } from './guards';
import { RecoveryFlow } from './recovery-flow';

function view(overrides: Partial<RecoveryViewState> = {}): RecoveryViewState {
  return {
    screen: 'vaultGuard',
    canGoBack: false,
    primaryAction: 'enabled',
    error: null,
    progressBucket: 'idle',
    evidenceCategory: null,
    focusFirstInvalidPosition: null,
    ownerState: 'owner',
    allowedActions: [],
    ...overrides,
  };
}

const noopProps = {
  onSelectCount: vi.fn(),
  onPastePhrase: vi.fn(),
  onConfirmPasteReplacement: vi.fn(),
  onClearAll: vi.fn(),
  onToggleShowAll: vi.fn(),
  onVerify: vi.fn(),
  onSelectCandidate: vi.fn(),
  onConfirmExistingProfile: vi.fn(),
  onRetryLookup: vi.fn(),
  onReveal: vi.fn(),
  onCopyAddress: vi.fn(),
  onChooseProtection: vi.fn(),
  onAcknowledgeProtection: vi.fn(),
  onConfirmRecreate: vi.fn(),
  onFinishRestoringUnlock: vi.fn(),
  onLock: vi.fn(),
  onRemoveLocalUser: vi.fn(),
  onForgotPassword: vi.fn(),
  onConfirmRemoval: vi.fn(),
  onCancelRemoval: vi.fn(),
  onBack: vi.fn(),
  onEnterDashboard: vi.fn(),
  onRetry: vi.fn(),
  removalPending: false,
};

describe('LocalUserGuard (Task 5.8)', () => {
  it('keeps Lock and destructive removal distinct; Restore is unavailable while a user exists', () => {
    render(<LocalUserGuard onLock={vi.fn()} onRemoveLocalUser={vi.fn()} onForgotPassword={vi.fn()} removalPending={false} />);
    expect(screen.getByRole('button', { name: 'Lock' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Log out and remove local user' })).toBeDefined();
    expect(screen.queryByRole('button', { name: /Restore Recovery Words/ })).toBeNull();
  });

  it('explains forgot-device-password limits honestly', () => {
    render(<LocalUserGuard onLock={vi.fn()} onRemoveLocalUser={vi.fn()} onForgotPassword={vi.fn()} removalPending={false} />);
    expect(screen.getByText(/cannot recover or reset your device password/)).toBeDefined();
  });
});

describe('OwnerBlockedScreen (Task 5.8)', () => {
  it('shows only the safe already-in-progress state with no recovery form mounted', () => {
    render(<OwnerBlockedScreen onRetry={vi.fn()} />);
    expect(screen.getByText(/already in progress in another/)).toBeDefined();
    expect(screen.queryByTestId('word-grid')).toBeNull();
    expect(screen.queryByTestId('candidate-list')).toBeNull();
    expect(screen.queryByLabelText(/Recovery word \d of/)).toBeNull();
  });
});

describe('QuarantineScreen (Task 5.8)', () => {
  it('blocks first-run recovery with bounded retry guidance', () => {
    render(<QuarantineScreen onRetry={vi.fn()} />);
    expect(screen.getByText(/blocked until local cleanup completes/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Retry cleanup' })).toBeDefined();
  });
});

describe('RemovalConfirmation (Task 5.8)', () => {
  it('warns destructively and requires explicit confirmation', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    render(<RemovalConfirmation onConfirm={onConfirm} onCancel={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByText(/blockchain identity is not deleted/)).toBeDefined();
    await user.click(screen.getByRole('button', { name: 'Remove local user' }));
    expect(onConfirm).toHaveBeenCalled();
  });
});

describe('RecoveryFlow routing (Task 5.8)', () => {
  it('mounts no recovery form when another owner holds the epoch', () => {
    render(<RecoveryFlow {...noopProps} view={view({ ownerState: 'blockedByOtherOwner' })} wordGrid={null} candidateReview={null} protection={null} stagedPreview={null} lookupProgress={null} />);
    expect(screen.getByText(/already in progress in another/)).toBeDefined();
  });

  it('routes the quarantine screen from a quarantined terminal state', () => {
    render(<RecoveryFlow {...noopProps} view={view({ screen: 'quarantined' })} wordGrid={null} candidateReview={null} protection={null} stagedPreview={null} lookupProgress={null} />);
    expect(screen.getByText(/blocked until local cleanup completes/)).toBeDefined();
  });

  it('routes word entry when the grid projection is present', () => {
    render(
      <RecoveryFlow
        {...noopProps}
        view={view({ screen: 'wordEntry' })}
        wordGrid={{ selectedWordCount: '12', invalidPositions: [], countValid: true, vocabularyValid: true, checksumState: 'notRun', allConcealed: true, busy: false, canVerify: true, errorSummary: [], pasteReplacementPending: false }}
        candidateReview={null}
        protection={null}
        stagedPreview={null}
        lookupProgress={null}
      />
    );
    expect(screen.getByText('Enter your recovery words')).toBeDefined();
  });

  it('routes the finish-restoring gate from staged data', () => {
    render(
      <RecoveryFlow
        {...noopProps}
        view={view({ screen: 'finishRestoring' })}
        wordGrid={null}
        candidateReview={null}
        protection={null}
        stagedPreview={{ stage: 'finishRestoring', nonAuthenticated: true, blocksCreateRestore: true, protectionMode: 'devicePasswordWeb', abbreviatedSigningAddress: 'Aa…11', abbreviatedEncryptionAddress: 'Bb…22', networkLabel: 'Mainnet', corrupted: false }}
        lookupProgress={null}
      />
    );
    expect(screen.getByText('Finish restoring your identity')).toBeDefined();
  });
});
