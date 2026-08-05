/**
 * FEAT-010 Tasks 5.4/5.6 — locked/home/settings surface component tests.
 *
 * Proves mode-specific copy/actions, direct-secret transfer + immediate
 * clearing, cooldown/progress states, home content bounds, FEAT-011 absence,
 * offline action availability, REMOVE gating, migration/quarantine/error
 * surfaces (normative: FeatureDescription "Returning Locked Screen",
 * "Authenticated Home", "Identity and Security Settings", "Errors and
 * Remediation"; AC-010-027…039, 044…062, 063…082, 088–090).
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HomeSurface, LockedSurface } from '../locked/LockedSurface';
import {
  LockPolicySurface,
  MigrationRemediationSurface,
  QuarantineSurface,
  RecoverySurface,
  SettingsSurface,
  UnknownErrorSurface,
} from '../settings/SettingsSurface';
import { projectLockedView, projectHome, type SafeIdentityPreview } from '../../../lib/auth/presentation';

const preview: SafeIdentityPreview = {
  alias: 'safe-alias',
  abbreviatedSigningAddress: 'AB12CD34…WXYZ90',
  networkContext: 'HushNetwork devnet',
};

describe('LockedSurface — Device-password mode', () => {
  it('shows the Device password field with current-password semantics and clears after transfer', async () => {
    const onSubmitSecret = vi.fn();
    const user = userEvent.setup();
    const projection = projectLockedView('device-password', preview);
    if ('kind' in projection) throw new Error('unexpected blocked projection');

    render(<LockedSurface projection={projection} progress={null} onSubmitSecret={onSubmitSecret} onUnlockDevice={vi.fn()} onRecovery={vi.fn()} onRemoveLocalUser={vi.fn()} />);

    const input = screen.getByLabelText('Device password');
    expect(input).toHaveAttribute('autoComplete', 'current-password');
    expect(input).toHaveAttribute('type', 'password');

    await user.type(input, 'super-secret-test-value');
    await user.click(screen.getByRole('button', { name: 'Unlock HushVoting!' }));
    expect(onSubmitSecret).toHaveBeenCalledWith('super-secret-test-value');
    expect(input).toHaveValue('');
  });

  it('uses the exact recovery and removal copy', () => {
    const projection = projectLockedView('device-password', preview);
    if ('kind' in projection) throw new Error('unexpected');
    render(<LockedSurface projection={projection} progress={null} onSubmitSecret={vi.fn()} onUnlockDevice={vi.fn()} onRecovery={vi.fn()} onRemoveLocalUser={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Forgot device password?' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove local user' })).toBeInTheDocument();
  });

  it('shows the cooldown deadline when throttled and disables the field', () => {
    const projection = projectLockedView('device-password', preview);
    if ('kind' in projection) throw new Error('unexpected');
    render(
      <LockedSurface
        projection={projection}
        progress={{ state: 'cooldown', retryAllowed: false, cooldownDeadlineMs: 1_700_000 }}
        onSubmitSecret={vi.fn()}
        onUnlockDevice={vi.fn()}
        onRecovery={vi.fn()}
        onRemoveLocalUser={vi.fn()}
      />,
    );
    expect(screen.getByText(/too many attempts/i)).toBeInTheDocument();
    expect(screen.getByLabelText('Device password')).toBeDisabled();
  });
});

describe('LockedSurface — passwordless modes', () => {
  it('never shows a Device-password field for passwordless modes', () => {
    for (const mode of ['webauthn-prf', 'ubuntu-secret-service', 'android-keystore'] as const) {
      const projection = projectLockedView(mode, preview);
      if ('kind' in projection) throw new Error('unexpected');
      const { unmount } = render(
        <LockedSurface projection={projection} progress={null} onSubmitSecret={vi.fn()} onUnlockDevice={vi.fn()} onRecovery={vi.fn()} onRemoveLocalUser={vi.fn()} />,
      );
      expect(screen.queryByLabelText('Device password')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: projection.unlockLabel })).toBeInTheDocument();
      unmount();
    }
  });

  it('discloses the unlocked-OS-session honestly on Ubuntu', () => {
    const projection = projectLockedView('ubuntu-secret-service', preview);
    if ('kind' in projection) throw new Error('unexpected');
    render(<LockedSurface projection={projection} progress={null} onSubmitSecret={vi.fn()} onUnlockDevice={vi.fn()} onRecovery={vi.fn()} onRemoveLocalUser={vi.fn()} />);
    expect(screen.getByText('Access follows the unlocked OS session.')).toBeInTheDocument();
  });
});

describe('HomeSurface', () => {
  it('mounts a minimal real home without fake downstream content', () => {
    const projection = projectHome(preview, 'online', false);
    render(<HomeSurface projection={projection} onLock={vi.fn()} onOpenSettings={vi.fn()} onRemoveLocalUser={vi.fn()} />);
    expect(screen.getByTestId('authenticated-home')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Lock HushVoting!' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Identity and security' })).toBeInTheDocument();
    expect(screen.queryByText(/export credential file/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/election|role|eligibility|feed/i)).not.toBeInTheDocument();
  });

  it('shows the session-only warning only when applicable', () => {
    const sessionOnly = projectHome(preview, 'offline', true);
    const { unmount } = render(<HomeSurface projection={sessionOnly} onLock={vi.fn()} onOpenSettings={vi.fn()} onRemoveLocalUser={vi.fn()} />);
    expect(screen.getByText(/session-only — lock or closing the app removes this local session/i)).toBeInTheDocument();
    unmount();

    const persistent = projectHome(preview, 'reconnecting', false);
    render(<HomeSurface projection={persistent} onLock={vi.fn()} onOpenSettings={vi.fn()} onRemoveLocalUser={vi.fn()} />);
    expect(screen.queryByText(/session-only/i)).not.toBeInTheDocument();
  });
});

describe('SettingsSurface', () => {
  it('exposes offline-exact actions', () => {
    const { unmount } = render(
      <SettingsSurface
        actions={{ available: ['removeLocalUser', 'lockPolicy'], blockedOffline: ['devicePasswordChange', 'protectionModeChange'] }}
        onLockPolicy={vi.fn()}
        onDevicePasswordChange={vi.fn()}
        onProtectionModeChange={vi.fn()}
        onRemoveLocalUser={vi.fn()}
      />,
    );
    expect(screen.getByRole('button', { name: 'Lock policy' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Change device password' })).not.toBeInTheDocument();
    expect(screen.getByText(/offline — password, protection, and export changes need an online check/i)).toBeInTheDocument();
    unmount();

    render(
      <SettingsSurface
        actions={{ available: ['removeLocalUser', 'lockPolicy', 'devicePasswordChange', 'protectionModeChange'], blockedOffline: [] }}
        onLockPolicy={vi.fn()}
        onDevicePasswordChange={vi.fn()}
        onProtectionModeChange={vi.fn()}
        onRemoveLocalUser={vi.fn()}
      />,
    );
    expect(screen.getByRole('button', { name: 'Change device password' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change device protection' })).toBeInTheDocument();
  });
});

describe('LockPolicySurface', () => {
  it('renders exact choices with warnings and commits the selection', async () => {
    const onChoose = vi.fn();
    const user = userEvent.setup();
    render(
      <LockPolicySurface
        projection={{ idleChoices: [1, 5, 15, 30, 60, 'until-restart'], backgroundChoices: ['immediate', 30, 120, 300, 900, 'until-restart'], weakerChoicesWarn: ['1'] }}
        onChoose={onChoose}
        onBack={vi.fn()}
      />,
    );
    expect(screen.getByLabelText('Lock after idle')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save lock policy' }));
    expect(onChoose).toHaveBeenCalledWith('5', '30');
  });
});

describe('RecoverySurface', () => {
  it('requires the exact REMOVE phrase before the destructive action', async () => {
    const onConfirmRemoval = vi.fn();
    const user = userEvent.setup();
    render(
      <RecoverySurface
        projection={{ noRemoteResetCopy: 'HushVoting cannot recover or reset your protection. Your blockchain identity is unaffected.', requiresPhrase: 'REMOVE', finalConfirmationRequired: true, restoreChoicesVisible: false }}
        onEnterPhrase={vi.fn()}
        onConfirmRemoval={onConfirmRemoval}
        onBack={vi.fn()}
      />,
    );
    const button = screen.getByRole('button', { name: 'Remove and recover' });
    expect(button).toBeDisabled();
    await user.type(screen.getByLabelText('Type REMOVE to continue'), 'remove');
    expect(button).toBeDisabled();
    await user.clear(screen.getByLabelText('Type REMOVE to continue'));
    await user.type(screen.getByLabelText('Type REMOVE to continue'), 'REMOVE');
    expect(button).toBeEnabled();
    await user.click(button);
    expect(onConfirmRemoval).toHaveBeenCalledTimes(1);
  });
});

describe('remediation surfaces', () => {
  it('renders network-mismatch, update, recovery/removal, and retry remediations', () => {
    const { unmount } = render(<MigrationRemediationSurface projection={{ kind: 'networkMismatch' }} />);
    expect(screen.getByText(/different HushNetwork network/i)).toBeInTheDocument();
    unmount();
    render(<MigrationRemediationSurface projection={{ kind: 'updateAvailable' }} />);
    expect(screen.getByText(/newer HushVoting version/i)).toBeInTheDocument();
    unmount();
    render(<MigrationRemediationSurface projection={{ kind: 'recoveryOrRemoval' }} />);
    expect(screen.getByText(/could not be read/i)).toBeInTheDocument();
    unmount();
    render(<MigrationRemediationSurface projection={{ kind: 'retry' }} />);
    expect(screen.getByText(/retry the migration/i)).toBeInTheDocument();
  });

  it('renders quarantine retry-only remediation', () => {
    render(<QuarantineSurface onRetry={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Retry cleanup' })).toBeInTheDocument();
    expect(screen.queryByText(/restore recovery words/i)).not.toBeInTheDocument();
  });

  it('renders the unknown-error surface with a support code', () => {
    render(<UnknownErrorSurface projection={{ genericCopy: 'Something went wrong. Please try again.', supportCode: 'ERR-ABCD1234' }} />);
    expect(screen.getByTestId('unknown-error')).toBeInTheDocument();
    expect(screen.getByText('ERR-ABCD1234')).toBeInTheDocument();
  });
});
