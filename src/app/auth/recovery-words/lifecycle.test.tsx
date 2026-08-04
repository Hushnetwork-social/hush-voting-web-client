/**
 * FEAT-008 Task 5.6 — component and accessibility tests for protection and
 * lifecycle UI.
 * Coverage targets: AC-008-036–063, 071 (component/a11y portion); default
 * checked mode, session acknowledgement, recreation review, resume, success
 * announcement without extra Continue button.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ProtectionProjection, StagedPreviewProjection } from '../../../lib/recovery-words/contracts/projection';
import { FinishRestoringScreen, ProtectionScreen, RecreateScreen, StagingScreen, SuccessScreen } from './lifecycle';

function protection(overrides: Partial<ProtectionProjection> = {}): ProtectionProjection {
  return {
    defaultPasswordChecked: true,
    allowedModes: ['devicePasswordWeb', 'sessionOnly'],
    sessionOnlyAcknowledgementRequired: true,
    passwordlessQualified: false,
    platformHints: ['webauthn-platform-required'],
    busy: false,
    ...overrides,
  };
}

function stagedPreview(overrides: Partial<StagedPreviewProjection> = {}): StagedPreviewProjection {
  return {
    stage: 'finishRestoring',
    nonAuthenticated: true,
    blocksCreateRestore: true,
    protectionMode: 'devicePasswordWeb',
    abbreviatedSigningAddress: 'Ab12Cd34…Xy98Zz76',
    abbreviatedEncryptionAddress: 'Qw12Er34…Rt56Yu78',
    networkLabel: 'HushNetwork Mainnet',
    corrupted: false,
    ...overrides,
  };
}

describe('ProtectionScreen (Task 5.6)', () => {
  it('defaults Create a HushVoting vault password to checked', () => {
    render(<ProtectionScreen protection={protection()} onChooseMode={vi.fn()} onAcknowledge={vi.fn()} onBack={vi.fn()} />);
    const password = screen.getByTestId('mode-password') as HTMLInputElement;
    expect(password.checked).toBe(true);
  });

  it('requires the session-only acknowledgement before continuing', async () => {
    const user = userEvent.setup();
    const onAcknowledge = vi.fn();
    render(<ProtectionScreen protection={protection({ allowedModes: ['sessionOnly'] })} onChooseMode={vi.fn()} onAcknowledge={onAcknowledge} onBack={vi.fn()} />);
    await user.click(screen.getByTestId('mode-session'));
    const continueButton = screen.getByRole('button', { name: 'Continue' });
    expect(continueButton).toBeDisabled();
    await user.click(screen.getByTestId('session-ack'));
    expect(continueButton).not.toBeDisabled();
    await user.click(continueButton);
    expect(onAcknowledge).toHaveBeenCalled();
  });

  it('never offers an unqualified passwordless mode', () => {
    render(<ProtectionScreen protection={protection({ allowedModes: ['devicePasswordWeb'] })} onChooseMode={vi.fn()} onAcknowledge={vi.fn()} onBack={vi.fn()} />);
    expect(screen.queryByTestId('mode-passwordless-web')).toBeNull();
    expect(screen.queryByTestId('mode-passwordless-native')).toBeNull();
  });

  it('discloses synced-passkey and unlocked-device honesty when qualified', () => {
    render(<ProtectionScreen protection={protection({ allowedModes: ['devicePasswordWeb', 'passwordlessWeb', 'passwordlessNative'] })} onChooseMode={vi.fn()} onAcknowledge={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByText(/may synchronize the passkey/)).toBeDefined();
    expect(screen.getByText(/access to this unlocked device/)).toBeDefined();
  });
});

describe('RecreateScreen (Task 5.6)', () => {
  it('starts alias empty and visibility Private; Public requires acknowledgement', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    render(<RecreateScreen networkLabel="HushNetwork Testnet" onConfirm={onConfirm} onBack={vi.fn()} />);
    const create = screen.getByRole('button', { name: 'Create HushNetwork identity' });
    expect(create).toBeDisabled();
    const privateRadio = screen.getByTestId('visibility-private') as HTMLInputElement;
    expect(privateRadio.checked).toBe(true);

    await user.type(screen.getByTestId('recreate-alias'), 'Voter');
    expect(create).not.toBeDisabled();
    await user.click(screen.getByTestId('visibility-public'));
    expect(create).toBeDisabled(); // public ack required
    await user.click(screen.getByTestId('public-ack'));
    expect(create).not.toBeDisabled();
    await user.click(create);
    expect(onConfirm).toHaveBeenCalledWith('Voter', 'public');
  });
});

describe('StagingScreen (Task 5.6)', () => {
  it('shows progress or a fail-closed failure surface', () => {
    const { unmount } = render(<StagingScreen failed={false} onBack={vi.fn()} />);
    expect(screen.getByText(/Encrypted keys are being saved/)).toBeDefined();
    unmount();
    render(<StagingScreen failed={true} onBack={vi.fn()} />);
    expect(screen.getByText(/Nothing was saved/)).toBeDefined();
  });
});

describe('FinishRestoringScreen (Task 5.6)', () => {
  it('shows the resume gate with abbreviated addresses and no word reveal', () => {
    render(<FinishRestoringScreen preview={stagedPreview()} onUnlock={vi.fn()} onLock={vi.fn()} />);
    expect(screen.getByText('Finish restoring your identity')).toBeDefined();
    expect(screen.getByText('Ab12Cd34…Xy98Zz76')).toBeDefined();
    expect(document.body.textContent).not.toMatch(/abandon|ability|zoo/i);
  });

  it('fails closed on corrupted staged data', () => {
    render(<FinishRestoringScreen preview={stagedPreview({ corrupted: true })} onUnlock={vi.fn()} onLock={vi.fn()} />);
    expect(screen.getByText(/damaged or unsupported/)).toBeDefined();
  });
});

describe('SuccessScreen (Task 5.6)', () => {
  it('announces Identity restored and transitions automatically with NO extra Continue button', () => {
    const onEnter = vi.fn();
    render(<SuccessScreen onEnterDashboard={onEnter} />);
    expect(screen.getByText('Identity restored')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();
    expect(onEnter).toHaveBeenCalled();
  });
});
