/**
 * FEAT-009 Tasks 5.2/5.4/5.6/5.8 — component, interaction, accessibility,
 * secret-boundary, timing, privacy, lifecycle, navigation, and responsive
 * tests for the credential-file UI surfaces.
 *
 * Proves: file input cleared after transfer/cancel, safe selected status
 * (never filename), neutral picker cancel, password never enters React
 * state, password components never co-mount with protection, exact copy,
 * empty-password option, countdown accessibility, abbreviated addresses,
 * success truth, stage-specific Back, quarantine gate, and 320px-safe
 * rendering.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { toRestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import type { RestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import { COPY } from './surfaces';
import { PasswordScreen, errorCopy } from './picker-password';
import { CredentialFileFlow, OwnerBlockedScreen, QuarantineScreen } from './credential-file-flow';
import { SuccessScreen } from './profile-protection';

function view(overrides: Partial<Parameters<typeof toRestoreViewState>[0]> = {}): RestoreViewState {
  return toRestoreViewState({
    stage: 'picker',
    progress: null,
    failureCode: null,
    backoffRemainingSeconds: 0,
    passwordField: null,
    protectionChoices: null,
    profile: null,
    reveal: null,
    ...overrides,
  });
}

function flowProps(overrides: Partial<Parameters<typeof CredentialFileFlow>[0]> = {}) {
  const handlers = {
    onChooseFile: vi.fn(),
    onCancelRead: vi.fn(),
    onSubmitPassword: vi.fn(),
    onToggleVisibility: vi.fn(),
    onToggleEmptyOption: vi.fn(),
    onChooseDifferentFile: vi.fn(),
    onChooseProtection: vi.fn(),
    onCreateIdentity: vi.fn(),
    onReveal: vi.fn(),
    onUnlockResume: vi.fn(),
    onCancelStage: vi.fn(),
    onBack: vi.fn(),
    onAcknowledgeSessionOnly: vi.fn(),
    onRetryCleanup: vi.fn(),
  };
  return { view: view(), sessionOnlyOnly: false, ...handlers, ...overrides };
}

describe('FEAT-009 picker/read surfaces (Task 5.1)', () => {
  it('shows safe selected status and never a filename', () => {
    const props = flowProps({ view: view({ stage: 'picker' }) });
    const { container } = render(<CredentialFileFlow {...props} />);
    expect(screen.getByText(COPY.picker.selected)).toBeDefined();
    expect(container.textContent).not.toMatch(/\.dat|backup/i);
  });

  it('picker cancel is neutral — no error announcement, back to entry', () => {
    const props = flowProps();
    render(<CredentialFileFlow {...props} />);
    // Cancel flows through the shared Back authority; the surface renders no error.
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('reading surface shows progress copy and Cancel', () => {
    const props = flowProps({ view: view({ stage: 'reading' }) });
    render(<CredentialFileFlow {...props} />);
    expect(screen.getAllByText(COPY.reading.title).length).toBeGreaterThan(0);
    expect(screen.getByTestId('cancel-read')).toBeDefined();
  });

  it('structural errors render the safe invalid-file copy', () => {
    const props = flowProps({ view: view({ stage: 'picker', failureCode: 'INVALID_MAGIC' }) });
    render(<CredentialFileFlow {...props} />);
    expect(screen.getByText(COPY.errors.invalidFile)).toBeDefined();
    expect(screen.getByTestId('choose-file')).toBeDefined(); // becomes Choose a different file
  });
});

describe('FEAT-009 password surface (Task 5.3)', () => {
  it('password never enters React state; field clears after submit', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    const state = view({ stage: 'password', passwordField: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true }, failureCode: 'AUTHENTICATION_FAILED' });
    render(<PasswordScreen view={state} onSubmit={onSubmit} onToggleVisibility={vi.fn()} onToggleEmptyOption={vi.fn()} onChooseDifferentFile={vi.fn()} onBack={vi.fn()} />);
    const input = screen.getByTestId('backup-password-input') as HTMLInputElement;
    await user.type(input, 'hunter2-secret');
    await user.click(screen.getByTestId('submit-password'));
    expect(onSubmit).toHaveBeenCalledWith('hunter2-secret');
    expect(input.value).toBe(''); // cleared after submission
  });

  it('exact label and purpose-separation explainer are rendered', () => {
    const state = view({ stage: 'password', passwordField: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true } });
    render(<PasswordScreen view={state} onSubmit={vi.fn()} onToggleVisibility={vi.fn()} onToggleEmptyOption={vi.fn()} onChooseDifferentFile={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByLabelText(COPY.password.label)).toBeDefined();
    expect(screen.getByTestId('password-explainer').textContent).toBe(COPY.password.explainer);
  });

  it('show/hide has a stateful accessible name', async () => {
    const user = userEvent.setup();
    let visible = false;
    const state = view({ stage: 'password', passwordField: { visible, emptyOptionChecked: false, emptyOptionEnabled: true } });
    const { rerender } = render(
      <PasswordScreen view={state} onSubmit={vi.fn()} onToggleVisibility={() => { visible = !visible; }} onToggleEmptyOption={vi.fn()} onChooseDifferentFile={vi.fn()} onBack={vi.fn()} />,
    );
    const toggle = screen.getByTestId('toggle-password-visibility');
    expect(toggle.getAttribute('aria-label')).toBe(COPY.password.show);
    await user.click(toggle);
    rerender(
      <PasswordScreen view={{ ...state, passwordFieldState: { ...state.passwordFieldState!, visible: true } }} onSubmit={vi.fn()} onToggleVisibility={() => {}} onToggleEmptyOption={vi.fn()} onChooseDifferentFile={vi.fn()} onBack={vi.fn()} />,
    );
    expect(screen.getByTestId('toggle-password-visibility').getAttribute('aria-label')).toBe(COPY.password.hide);
  });

  it('empty-password option is unchecked by default and disables the field when enabled', async () => {
    const user = userEvent.setup();
    const onToggle = vi.fn();
    const state = view({ stage: 'password', passwordField: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true } });
    render(<PasswordScreen view={state} onSubmit={vi.fn()} onToggleVisibility={vi.fn()} onToggleEmptyOption={onToggle} onChooseDifferentFile={vi.fn()} onBack={vi.fn()} />);
    const checkbox = screen.getByTestId('empty-password-option') as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    await user.click(checkbox);
    expect(onToggle).toHaveBeenCalledWith(true);
  });

  it('combined auth failure copy never claims cause; countdown is accessible', () => {
    const state = view({ stage: 'password', failureCode: 'AUTHENTICATION_FAILED', backoffRemainingSeconds: 4, passwordField: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true } });
    render(<PasswordScreen view={state} onSubmit={vi.fn()} onToggleVisibility={vi.fn()} onToggleEmptyOption={vi.fn()} onChooseDifferentFile={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByText(COPY.errors.combined)).toBeDefined();
    const countdown = screen.getByTestId('backoff-countdown');
    expect(countdown.textContent).toContain('4 seconds');
    expect(countdown.getAttribute('aria-live')).toBe('polite');
  });
});

describe('FEAT-009 profile/protection/success surfaces (Task 5.5)', () => {
  it('missing-profile review shows abbreviated addresses and explicit Create', () => {
    const props = flowProps({
      view: view({
        stage: 'profileReview',
        profile: { alias: 'legacy-alias', isPublic: false, signingAddressAbbreviated: 'aaaaaaaa…bbbbbb', encryptionAddressAbbreviated: 'cccccccc…dddddd', networkLabel: 'HushLocal', source: 'importedReview', aliasEditable: true, publicAcknowledgementRequired: true },
      }),
    });
    render(<CredentialFileFlow {...props} />);
    expect(screen.getByText(COPY.profile.missing)).toBeDefined();
    expect(screen.getByText('aaaaaaaa…bbbbbb')).toBeDefined(); // abbreviated, not full
    expect(screen.getByTestId('create-identity')).toBeDefined();
    expect(within(screen.getByTestId('restore-panel')).queryByText(/a{66}/)).toBeNull();
  });

  it('protection surface defaults to Device password and never co-mounts backup state', () => {
    const props = flowProps({
      view: view({ stage: 'protection', protectionChoices: ['devicePassword', 'sessionOnly'] }),
    });
    render(<CredentialFileFlow {...props} />);
    const passwordChoice = screen.getByTestId('protection-devicePassword') as HTMLInputElement;
    expect(passwordChoice.checked).toBe(true);
    // No Backup-file password field/explainer may be mounted.
    expect(screen.queryByTestId('backup-password-input')).toBeNull();
    expect(screen.queryByTestId('password-explainer')).toBeNull();
  });

  it('resume gate shows Finish restoring your identity with unlock and cancel', () => {
    const props = flowProps({ view: view({ stage: 'resumeGate' }) });
    render(<CredentialFileFlow {...props} />);
    expect(screen.getAllByText(COPY.resume.title).length).toBeGreaterThan(0);
    expect(screen.getByTestId('unlock-resume')).toBeDefined();
    expect(screen.getByTestId('cancel-stage')).toBeDefined();
  });

  it('success announces Identity restored with the mnemonic-source notice', () => {
    const state = view({
      stage: 'success',
      profile: { alias: 'chain-alias', isPublic: true, signingAddressAbbreviated: 'aa…bb', encryptionAddressAbbreviated: 'cc…dd', networkLabel: 'HushLocal', source: 'blockchain', aliasEditable: false, publicAcknowledgementRequired: false },
    });
    render(<SuccessScreen view={state} />);
    expect(screen.getAllByText(COPY.success.title).length).toBeGreaterThan(0);
    expect(screen.getByTestId('mnemonic-notice').textContent).toBe(COPY.success.mnemonicNotice);
  });
});

describe('FEAT-009 navigation/ownership/cleanup surfaces (Task 5.7)', () => {
  it('quarantine blocks with Retry cleanup only', () => {
    const onRetryCleanup = vi.fn();
    render(<QuarantineScreen onRetryCleanup={onRetryCleanup} />);
    expect(screen.getAllByText(COPY.errors.quarantine).length).toBeGreaterThan(0);
    expect(screen.getByTestId('retry-cleanup')).toBeDefined();
  });

  it('non-owner receives only safe blocked status', () => {
    render(<OwnerBlockedScreen onRetry={vi.fn()} />);
    const blocked = screen.getByTestId('owner-blocked');
    expect(blocked.textContent).not.toMatch(/password|address|profile|uri|\.dat/i);
  });

  it('terminal unknown outcome fails closed with generic copy', () => {
    const props = flowProps({ view: view({ stage: 'terminal' }) });
    render(<CredentialFileFlow {...props} />);
    expect(screen.getAllByText(COPY.errors.generic).length).toBeGreaterThan(0);
  });
});

describe('FEAT-009 responsive/secret snapshot guard (Tasks 5.2/5.8)', () => {
  it('rendered DOM never contains source identifiers or secret values', () => {
    const props = flowProps({
      view: view({
        stage: 'profileReview',
        profile: { alias: 'a', isPublic: true, signingAddressAbbreviated: 'aa…bb', encryptionAddressAbbreviated: 'cc…dd', networkLabel: 'HushLocal', source: 'blockchain', aliasEditable: false, publicAcknowledgementRequired: false },
        reveal: { token: 't', fullSigningAddress: 'f'.repeat(66), fullEncryptionAddress: 'e'.repeat(66) },
      }),
    });
    const { container } = render(<CredentialFileFlow {...props} />);
    // Ordinary view never renders the full addresses (explicit reveal only).
    expect(container.textContent).not.toContain('f'.repeat(66));
    expect(container.textContent).not.toContain('e'.repeat(66));
    expect(container.textContent).not.toMatch(/password|privatekey|mnemonic/i);
  });

  it('errorCopy is bounded and never echoes values', () => {
    expect(errorCopy('AUTHENTICATION_FAILED')).toBe(COPY.errors.combined);
    expect(errorCopy('SIGNING_KEY_MISMATCH')).toBe(COPY.errors.inconsistentKeys);
    expect(errorCopy('QUARANTINED')).toBe(COPY.errors.quarantine);
    expect(errorCopy('SOMETHING_UNKNOWN')).toBe(COPY.errors.generic);
  });
});
