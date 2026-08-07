/**
 * FEAT-007 Task 5.2/5.4/5.6 — component and accessibility tests for the
 * create-user surfaces. Coverage: AC-007-001–021, 032–060, 068–069
 * (component/a11y portion). Uses @testing-library/react; capture of secrets
 * is intentionally never enabled in these tests (no screenshots/traces).
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EntryScreen, PreflightScreen } from './entry';
import { ProfileScreen, GenerateScreen } from './profile';
import { ConfirmRecoveryScreen, RecoveryScreen } from './recovery';
import { ProtectScreen, ReviewScreen } from './protect';
import { CancellingScreen, ConnectionScreen, CorrectingScreen, DelayScreen, WaitingScreen } from './status';

describe('Entry (Task 5.2) — exactly three equal choices, no password', () => {
  it('renders Create User, Restore Credential File, Restore Recovery Words with no password field', () => {
    render(<EntryScreen onCreateUser={vi.fn()} onRestoreWords={vi.fn()} onRestoreFile={vi.fn()} />);
    expect(screen.getByRole('button', { name: /Create User/ })).toBeDefined();
    expect(screen.getByRole('button', { name: /Restore Recovery Words/ })).toBeDefined();
    expect(screen.getByRole('button', { name: /Restore Credential File/ })).toBeDefined();
    expect(screen.queryByLabelText(/password/i)).toBeNull();
    expect(screen.getAllByRole('button')).toHaveLength(3);
  });

  it('states that no server account password exists', () => {
    render(<EntryScreen onCreateUser={vi.fn()} onRestoreWords={vi.fn()} onRestoreFile={vi.fn()} />);
    expect(screen.getByText(/No HushVoting account password exists on a server/)).toBeDefined();
  });
});

describe('Preflight (Task 5.2)', () => {
  it('blocks generation with typed remediation when the platform is unsafe', () => {
    render(<PreflightScreen outcome={{ kind: 'unsupported', code: 'UNSUPPORTED_PLATFORM' }} onRetry={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByText(/This device cannot create an identity safely/)).toBeDefined();
    expect(screen.getByText(/Generation is blocked until the required protection is available/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  it('offers bounded Retry on temporary unavailability', async () => {
    const onRetry = vi.fn();
    render(<PreflightScreen outcome={{ kind: 'temporaryUnavailable' }} onRetry={onRetry} onBack={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledOnce();
  });
});

describe('Profile (Task 5.2)', () => {
  it('defaults to Private with no password field and validates alias', async () => {
    const onContinue = vi.fn();
    render(<ProfileScreen onContinue={onContinue} onBack={vi.fn()} />);
    expect(screen.getByRole('radio', { name: /Private — recommended/ })).toBeChecked();
    expect(screen.queryByLabelText(/password/i)).toBeNull();
    expect(screen.getByRole('button', { name: 'Continue' })).toHaveClass('button-default', 'w-full');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(screen.getByRole('alert')).toBeDefined();
    expect(onContinue).not.toHaveBeenCalled();
  });

  it('requires Public acknowledgement before continuing', async () => {
    const onContinue = vi.fn();
    render(<ProfileScreen onContinue={onContinue} onBack={vi.fn()} />);
    await userEvent.type(screen.getByLabelText('Profile name / alias'), 'Voter');
    await userEvent.click(screen.getByRole('radio', { name: /Public/ }));
    expect(screen.getByText(/cannot be changed later/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(screen.getByRole('alert').textContent).toMatch(/Acknowledge/);
    await userEvent.click(screen.getByRole('checkbox'));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(onContinue).toHaveBeenCalledWith('Voter', 'public');
  });
});

describe('Generate (Task 5.2)', () => {
  it('generates only on explicit action and shows progress after threshold', async () => {
    const onGenerate = vi.fn();
    const { rerender } = render(<GenerateScreen onGenerate={onGenerate} onBack={vi.fn()} progressVisible={false} progressComplete={false} />);
    await userEvent.click(screen.getByRole('button', { name: /Generate recovery words/ }));
    expect(onGenerate).toHaveBeenCalledOnce();
    rerender(<GenerateScreen onGenerate={onGenerate} onBack={vi.fn()} progressVisible={true} progressComplete={false} />);
    expect(screen.getByText(/Generating your identity securely/)).toBeDefined();
    expect(screen.getByTestId('create-action')).toBeDisabled();
  });
});

describe('Recovery (Task 5.4)', () => {
  const words = Array.from({ length: 24 }, (_, i) => `word${i + 1}`);

  it('renders a semantic ordered 24-word list only while revealed', () => {
    render(
      <RecoveryScreen words={words} onCopy={vi.fn()} onRegenerateRequest={vi.fn()} onContinue={vi.fn()} onBack={vi.fn()} acknowledged={true} onAcknowledge={vi.fn()} timeoutMessage={null} />,
    );
    const list = screen.getByTestId('recovery-list');
    expect(list.tagName).toBe('OL');
    expect(list.querySelectorAll('li')).toHaveLength(24);
  });

  it('copies the visible words only after the explicit Copy words action', async () => {
    const onCopy = vi.fn();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(
      <RecoveryScreen words={words} onCopy={onCopy} onRegenerateRequest={vi.fn()} onContinue={vi.fn()} onBack={vi.fn()} acknowledged={false} onAcknowledge={vi.fn()} timeoutMessage={null} />,
    );

    const copy = screen.getByRole('button', { name: 'Copy words' });
    expect(copy).toHaveClass('button-default');
    expect(copy).toBeEnabled();
    expect(writeText).not.toHaveBeenCalled();
    await userEvent.click(copy);

    expect(writeText).toHaveBeenCalledOnce();
    expect(writeText).toHaveBeenCalledWith(words.join(' '));
    expect(onCopy).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Copied' })).toBeEnabled();
    expect(screen.getByRole('status')).toHaveTextContent('Recovery words copied.');
  });

  it('keeps the words visible and reports a bounded message when clipboard access fails', async () => {
    const writeText = vi.fn().mockRejectedValue(new DOMException('Denied', 'NotAllowedError'));
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(
      <RecoveryScreen words={words} onCopy={vi.fn()} onRegenerateRequest={vi.fn()} onContinue={vi.fn()} onBack={vi.fn()} acknowledged={false} onAcknowledge={vi.fn()} timeoutMessage={null} />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Copy words' }));
    expect(screen.getByRole('status')).toHaveTextContent('Clipboard copy is unavailable. Save the visible words manually.');
    expect(screen.getByTestId('recovery-list')).toBeInTheDocument();
  });

  it('conceals visual AND accessibility content when words are not revealed', () => {
    render(
      <RecoveryScreen words={null} onCopy={vi.fn()} onRegenerateRequest={vi.fn()} onContinue={vi.fn()} onBack={vi.fn()} acknowledged={false} onAcknowledge={vi.fn()} timeoutMessage="Recovery words are hidden." />,
    );
    expect(screen.queryByTestId('recovery-list')).toBeNull();
    expect(screen.getByText(/Recovery words are hidden/)).toBeDefined();
  });

  it('keeps Continue disabled until acknowledged', () => {
    const onContinue = vi.fn();
    render(
      <RecoveryScreen words={words} onCopy={vi.fn()} onRegenerateRequest={vi.fn()} onContinue={onContinue} onBack={vi.fn()} acknowledged={false} onAcknowledge={vi.fn()} timeoutMessage={null} />,
    );
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  });
});

describe('Confirm recovery (Task 5.4)', () => {
  it('reports the mismatch position only and never echoes words', async () => {
    const onVerify = vi.fn();
    render(
      <ConfirmRecoveryScreen
        positions={[3, 17]}
        onVerify={onVerify}
        onReviewAll={vi.fn()}
        onBack={vi.fn()}
        mismatchPosition={3}
        attemptsRemaining={2}
        challengeClosed={false}
      />,
    );
    expect(screen.getByText(/Word 3 does not match/)).toBeDefined();
    expect(screen.getByText(/You have 2 attempts remaining/)).toBeDefined();
    expect(screen.queryByText(/word17/i)).toBeNull();
  });

  it('renders the closed challenge without inputs', () => {
    render(
      <ConfirmRecoveryScreen positions={[]} onVerify={vi.fn()} onReviewAll={vi.fn()} onBack={vi.fn()} mismatchPosition={null} attemptsRemaining={0} challengeClosed={true} />,
    );
    expect(screen.getByText(/This challenge is closed/)).toBeDefined();
    expect(screen.queryByRole('textbox')).toBeNull();
  });
});

describe('Protect this device (Task 5.4)', () => {
  it('transfers the password to the authority and clears local buffers', async () => {
    const onProtect = vi.fn();
    render(<ProtectScreen onProtect={onProtect} onBack={vi.fn()} submitting={false} />);
    await userEvent.type(screen.getByLabelText('Device password'), 'correct-horse-9');
    await userEvent.type(screen.getByLabelText('Confirm device password'), 'correct-horse-9');
    await userEvent.click(screen.getByRole('button', { name: /Protect this device and continue/ }));
    expect(onProtect).toHaveBeenCalledWith('correct-horse-9');
    expect(screen.getByLabelText('Device password')).toHaveValue('');
  });

  it('labels reveal controls with stateful accessible names', async () => {
    render(<ProtectScreen onProtect={vi.fn()} onBack={vi.fn()} submitting={false} />);
    const reveal = screen.getByRole('button', { name: 'Show device password' });
    await userEvent.click(reveal);
    expect(screen.getByRole('button', { name: 'Hide device password' })).toBeDefined();
  });
});

describe('Review (Task 5.4)', () => {
  it('shows safe public fields and abbreviated addresses only', () => {
    render(
      <ReviewScreen
        review={{
          normalizedAlias: 'Voter',
          visibility: 'private',
          abbreviatedSigningAddress: 'ABCDEFGH…456789',
          abbreviatedEncryptionAddress: 'QWERTY12…890XYZ',
          recoveryConfirmed: true,
          deviceProtectionReady: true,
          stage: 'review',
          progress: 1,
        }}
        onCreate={vi.fn()}
        onBack={vi.fn()}
        submitting={false}
      />,
    );
    expect(screen.getByText('Voter')).toBeDefined();
    expect(screen.getByText('ABCDEFGH…456789')).toBeDefined();
    expect(screen.getByText('24 words confirmed')).toBeDefined();
    expect(screen.queryByText(/private key|full address|mnemonic/i)).toBeNull();
  });
});

describe('Status surfaces (Task 5.6)', () => {
  it('waiting gate states mempool truth and offers safe exit', () => {
    render(<WaitingScreen onCheckAgain={vi.fn()} onLock={vi.fn()} abbreviatedSigningAddress={null} blockHeight={null} />);
    expect(screen.getByText(/Waiting for blockchain final approval/)).toBeDefined();
    expect(screen.getByText(/in the mempool/)).toBeDefined();
    expect(screen.getByText(/You can lock or close HushVoting! safely/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Check again' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Lock' })).toBeDefined();
  });

  it('delay screen offers lookup-only Check again and Lock (no resubmit wording)', () => {
    render(<DelayScreen onCheckAgain={vi.fn()} onLock={vi.fn()} />);
    expect(screen.getByText(/Blockchain confirmation delayed/)).toBeDefined();
    expect(screen.getByText(/remains safely stored/)).toBeDefined();
    expect(screen.queryByText(/retry|resubmit|submit/i)).toBeNull();
  });

  it('connection screen preserves the exact transaction message', () => {
    render(<ConnectionScreen onRetry={vi.fn()} onLock={vi.fn()} />);
    expect(screen.getByText(/exact transaction remains encrypted/)).toBeDefined();
  });

  it('correction reopens Profile only with a stable ref code', () => {
    render(<CorrectingScreen onContinueToProfile={vi.fn()} validationCode="ALIAS_INVALID" />);
    expect(screen.getByText(/Only the profile step is reopened/)).toBeDefined();
    expect(screen.getByText(/ALIAS_INVALID/)).toBeDefined();
  });

  it('cancellation warns that mempool creation cannot be cancelled', () => {
    render(<CancellingScreen onCancelLocal={vi.fn()} onKeepSettingUp={vi.fn()} />);
    expect(screen.getByText(/may still confirm on the blockchain/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Cancel local identity' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Keep setting up' })).toBeDefined();
  });
});
