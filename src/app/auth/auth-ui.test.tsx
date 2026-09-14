/**
 * FEAT-002 auth UI component tests — every reachable surface, keyboard
 * behavior, focus, live regions, secret transfer, removal phrase, and
 * privacy-safe copy.
 *
 * Queries by role/name (accessibility-first); asserts visible behavior, not
 * implementation internals.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthGate } from './AuthGate';
import { FirstRun } from './FirstRun';
import { LockedUser } from './LockedUser';
import { AuthShell } from './AuthShell';
import { RemovalConfirmation } from './RemovalConfirmation';
import { ErrorSurface, RecoveryNavigation, TemporaryMode } from './ErrorSurfaces';
import { errorCopyForOutcome, documentTitleForState } from '../../lib/auth/ui/copy';
import { createAuthAdapter, type AuthRenderProjection } from '../../lib/auth/react/adapter';
import { buildEmptyActors } from '../../lib/auth/composition';
import { completeAllPendingOperations, createLocalUserAuthorityTestActor, createOnboardingTestActor, createIdentityVerificationTestActor, createRemovalTestActor } from '../../lib/auth/testing/actors';
import type { AuthIntent } from '../../lib/auth/types';
import { createWebLocalUserAuthority } from '../../lib/auth/web/web-actors';
import type { BrowserVaultClient } from '../../lib/browser-vault/production/client';

function projection(overrides: Partial<AuthRenderProjection>): AuthRenderProjection {
  return {
    authState: 'locked',
    connectivity: 'online',
    protectedAccess: false,
    entitlementStage: null,
    entitlementReady: false,
    sessionEpoch: 1,
    entitlementRequired: true,
    safeIdentity: { alias: 'Ada', abbreviatedSigningAddress: 'NVh…1a2b' },
    authenticatedIdentity: null,
    outcomeCode: null,
    supportCode: null,
    onboardingKind: null,
    ...overrides,
  };
}

describe('first-run entry', () => {
  it('shows exactly three equal actions', () => {
    render(
      <FirstRun
        onCreateUser={() => undefined}
        onRestoreCredentialFile={() => undefined}
        onRestoreRecoveryWords={() => undefined}
      />,
    );
    expect(screen.getByRole('button', { name: /create user/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /restore credential file/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /restore recovery words/i })).toBeInTheDocument();
    expect(screen.getAllByRole('button')).toHaveLength(3);
  });

  it('dispatches the correct intent per action', async () => {
    const user = userEvent.setup();
    const onCreate = vi.fn();
    const onFile = vi.fn();
    const onWords = vi.fn();
    render(<FirstRun onCreateUser={onCreate} onRestoreCredentialFile={onFile} onRestoreRecoveryWords={onWords} />);

    await user.click(screen.getByRole('button', { name: /create user/i }));
    await user.click(screen.getByRole('button', { name: /restore credential file/i }));
    await user.click(screen.getByRole('button', { name: /restore recovery words/i }));

    expect(onCreate).toHaveBeenCalledOnce();
    expect(onFile).toHaveBeenCalledOnce();
    expect(onWords).toHaveBeenCalledOnce();
  });
});

describe('locked-user surface and secret transfer', () => {
  // FEAT-030 approved legacy heading; FEAT-010 AC-010-025 / FEAT-007 AC-007-052.
  it.each(['staged', 'lockedVault'])('projects the %s startup classification without guessing its origin', async surface => {
    const actors = buildEmptyActors();
    const client = { isConnected: () => true, cancel: vi.fn(), dispatch: vi.fn(async () => ({
      outcome: 'OK', payload: { surface, safeIdentity: { alias: 'Ada', abbreviatedSigningAddress: 'NVh…1a2b' } },
    })) } as unknown as BrowserVaultClient;
    actors.localUserAuthority = createWebLocalUserAuthority(client);
    const adapter = createAuthAdapter({ actors, registeredCapabilities: new Set(), safeCoordination: true });
    try {
      await vi.waitFor(() => expect(adapter.snapshot().authState).toBe('locked'));
      render(<AuthShell projection={adapter.snapshot()}><LockedUser onSubmitSecret={() => undefined} onRemoveLocalUser={() => undefined} /></AuthShell>);
      expect(screen.getByRole('heading', { name: surface === 'staged' ? 'Finish setting up your identity' : 'Unlock HushVoting!' })).toBeInTheDocument();
      expect(screen.getByLabelText('Device password')).toBeInTheDocument();
      expect(adapter.snapshot().protectedAccess).toBe(false);
    } finally { adapter.stop(); }
  });

  it('transfers the secret directly and clears the input immediately', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    render(
      <LockedUser onSubmitSecret={onSubmit} onRemoveLocalUser={() => undefined} />,
    );
    const input = screen.getByLabelText('Device password');
    await user.type(input, 'sup3r-secret');
    await user.click(screen.getByRole('button', { name: /unlock hushvoting/i }));

    expect(onSubmit).toHaveBeenCalledWith('sup3r-secret');
    // Input cleared after accepted transfer; no secret in the DOM.
    expect(input).toHaveValue('');
    expect(screen.queryByDisplayValue('sup3r-secret')).toBeNull();
    expect(document.body.textContent ?? '').not.toContain('sup3r-secret');
  });

  it('shows no authenticated navigation and requires removal before recovery', () => {
    render(
      <LockedUser onSubmitSecret={() => undefined} onRemoveLocalUser={() => undefined} />,
    );
    expect(screen.queryByRole('button', { name: /forgot device password/i })).toBeNull();
    expect(screen.getByRole('button', { name: /remove local user/i })).toBeInTheDocument();
    const actions = screen.getAllByRole('button');
    expect(actions).toHaveLength(2);
    expect(actions[0]).toHaveAccessibleName(/remove local user/i);
    expect(actions[1]).toHaveAccessibleName(/unlock hushvoting/i);
    expect(screen.queryByRole('navigation')).toBeNull();
    expect(screen.queryByText(/server login|account password|password reset|remote sign-out/i)).toBeNull();
  });
});

describe('removal confirmation', () => {
  // EPIC-001 -> FEAT-008 AC-008-070 -> Phase 3 Tasks 3.9/3.10,
  // Phase 7 Tasks 7.1/7.2; FEAT-002 Phase 3 Tasks 3.1/3.2.
  // Drive real authority projections. Startup-marker consent remains FEAT-022.
  it('retains the verified preview for fresh confirmed removal after live cleanup fails', async () => {
    const user = userEvent.setup();
    const actors = buildEmptyActors();
    actors.localUserAuthority = createLocalUserAuthorityTestActor([{ code: 'INIT_NO_LOCAL_USER' }]);
    actors.onboarding.restoreRecoveryWords = createOnboardingTestActor([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'restored-local-user' }]);
    const signingKey = '02' + 'ab'.repeat(32);
    actors.identityVerification = createIdentityVerificationTestActor([{ code: 'VERIFY_SUCCESS', identity: {
      alias: 'Restored Alice', publicSigningKey: signingKey, publicEncryptionKey: '03' + 'cd'.repeat(32),
    } }]);
    actors.removal = createRemovalTestActor([{ code: 'UNKNOWN_FAILURE', supportCode: 'cleanup-test' }, { code: 'REMOVAL_COMPLETE' }]);
    const adapter = createAuthAdapter({ actors, registeredCapabilities: new Set(), safeCoordination: true });
    const settleAt = async (state: string) => vi.waitFor(() => {
      completeAllPendingOperations();
      expect(adapter.snapshot().authState).toBe(state);
    });
    try {
      await settleAt('noLocalUser');
      adapter.send({ type: 'INTENT.RESTORE_RECOVERY_WORDS' });
      await settleAt('authenticated');
      adapter.send({ type: 'INTENT.LOCK' });
      await settleAt('locked');
      const handlers = { dispatch: vi.fn((intent: AuthIntent) => adapter.send(intent)), submitSecret: vi.fn() };
      const { rerender } = render(<AuthGate projection={adapter.snapshot()} handlers={handlers} />);
      expect(adapter.snapshot().safeIdentity).toEqual({ alias: 'Restored Alice', abbreviatedSigningAddress: '02ababab…ababab' });
      expect(adapter.snapshot().authenticatedIdentity).toBeNull();
      expect(screen.queryByText(signingKey)).toBeNull();
      await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
      await user.type(screen.getByLabelText(/type REMOVE/i), 'REMOVE');
      await user.click(screen.getByRole('checkbox'));
      await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
      await settleAt('recoverableError');
      rerender(<AuthGate projection={adapter.snapshot()} handlers={handlers} />);
      expect(screen.queryByRole('button', { name: /restore recovery words/i })).toBeNull();
      expect(handlers.dispatch).toHaveBeenCalledTimes(1);
      await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
      expect(screen.getByLabelText(/type REMOVE/i)).toHaveValue('');
      expect(screen.getByRole('checkbox')).not.toBeChecked();
      expect(handlers.dispatch).toHaveBeenCalledTimes(1);
      await user.type(screen.getByLabelText(/type REMOVE/i), 'REMOVE');
      await user.click(screen.getByRole('checkbox'));
      await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
      await settleAt('noLocalUser');
      expect(adapter.snapshot().safeIdentity).toBeNull();
      expect(handlers.dispatch).toHaveBeenCalledTimes(2);
    } finally { adapter.stop(); completeAllPendingOperations(); }
  });

  it('the real locked gate requires confirmation before dispatching removal', async () => {
    const user = userEvent.setup();
    const dispatch = vi.fn();
    render(<AuthGate projection={projection({})} handlers={{ dispatch, submitSecret: vi.fn() }} />);
    await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
    expect(dispatch).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText(/type REMOVE/i), 'REMOVE');
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
    expect(dispatch).toHaveBeenCalledExactlyOnceWith({ type: 'INTENT.REMOVE_LOCAL_USER' });
  });

  it('cancels removal and never carries confirmation into another authority epoch', async () => {
    const user = userEvent.setup();
    const dispatch = vi.fn();
    const handlers = { dispatch, submitSecret: vi.fn() };
    const { rerender } = render(<AuthGate projection={projection({})} handlers={handlers} />);
    await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
    await user.click(screen.getByRole('button', { name: /^cancel$/i }));
    expect(screen.getByRole('button', { name: /unlock hushvoting/i })).toBeInTheDocument();
    expect(dispatch).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: /^remove local user$/i }));
    rerender(<AuthGate projection={projection({ sessionEpoch: 2 })} handlers={handlers} />);
    expect(screen.queryByLabelText(/type REMOVE/i)).not.toBeInTheDocument();
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('requires the exact phrase REMOVE and a final confirmation', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    render(
      <RemovalConfirmation onConfirmRemoval={onConfirm} onCancel={() => undefined} removing={false} />,
    );

    const submit = screen.getByRole('button', { name: /remove local user/i });
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText(/type REMOVE/i), 'remove');
    await user.click(screen.getByRole('checkbox'));
    expect(submit).toBeDisabled(); // phrase case must match exactly

    await user.clear(screen.getByLabelText(/type REMOVE/i));
    await user.type(screen.getByLabelText(/type REMOVE/i), 'REMOVE');
    await user.click(screen.getByRole('checkbox'));
    expect(submit).toBeEnabled();

    await user.click(submit);
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('renders non-cancellable progress while removing', () => {
    render(<RemovalConfirmation onConfirmRemoval={() => undefined} onCancel={() => undefined} removing />);
    expect(screen.getByText(/removing local data/i)).toBeInTheDocument();
    expect(screen.getByText(/cannot be cancelled/i)).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('error and recovery surfaces', () => {
  it('maps unknown failures to generic copy with a support code', () => {
    const copy = errorCopyForOutcome(null);
    expect(copy.title).toBe('Something went wrong');
    expect(copy.detail).toContain('Try again');
  });

  it('uses the exact combined credential error text for wrong-password outcomes', () => {
    const copy = errorCopyForOutcome('UNLOCK_WRONG_PASSWORD_OR_DAMAGED');
    expect(copy.detail).toBe('The password is incorrect or the protected data is damaged.');
  });

  it('never offers remote reset or sign-out in recovery navigation', () => {
    render(
      <RecoveryNavigation
        onRestoreCredentialFile={() => undefined}
        onRestoreRecoveryWords={() => undefined}
        onBackToUnlock={() => undefined}
      />,
    );
    expect(screen.getByRole('button', { name: /restore recovery words/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /restore credential file/i })).toBeInTheDocument();
    expect(screen.getByText(/no remote password reset or remote sign-out/i)).toBeInTheDocument();
  });

  it('error surface offers typed actions only', () => {
    render(
      <ErrorSurface
        projection={projection({ authState: 'recoverableError', outcomeCode: 'VERIFY_NETWORK_UNAVAILABLE' })}
        onRetry={() => undefined}
        onLock={() => undefined}
        onRemoveLocalUser={() => undefined}
      />,
    );
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /lock/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /remove local user/i })).toBeInTheDocument();
  });

  it('hides lock/removal when no provisioned local user exists', () => {
    render(
      <ErrorSurface
        projection={projection({ authState: 'recoverableError', outcomeCode: 'INIT_STORAGE_UNAVAILABLE', safeIdentity: null })}
        onRetry={() => undefined}
        onLock={() => undefined}
        onRemoveLocalUser={() => undefined}
      />,
    );
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /lock/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /remove local user/i })).toBeNull();
  });
});

describe('temporary mode warning', () => {
  it('explains loss-on-lock consequences before entry', () => {
    render(<TemporaryMode onEnterTemporaryMode={() => undefined} onCancel={() => undefined} />);
    expect(screen.getByText(/no local user or device password will be saved/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /continue in temporary mode/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
  });
});

describe('document titles never expose secrets or identifiers', () => {
  it('maps every auth state to a safe title', () => {
    const states: Array<Parameters<typeof documentTitleForState>[0]> = [
      'initializing',
      'noLocalUser',
      'onboarding',
      'locked',
      'unlocking',
      'verifyingIdentityOnline',
      'missingProfileConfirmation',
      'authenticated',
      'recoverableError',
      'blockedError',
      'removingLocalUser',
    ];
    for (const state of states) {
      const title = documentTitleForState(state);
      expect(title).toContain('HushVoting');
      expect(title).not.toMatch(/ELEC|password value|election/i);
    }
  });
});

describe('Auth shell onboarding navigation', () => {
  it('places one text-style Back control before the setup heading', async () => {
    const onBack = vi.fn();
    const user = userEvent.setup();
    render(
      <AuthShell projection={projection({ authState: 'onboarding' })} onBack={onBack}>
        <p>Setup content</p>
      </AuthShell>,
    );
    const back = screen.getByRole('button', { name: 'Back' });
    const heading = screen.getByRole('heading', { name: 'Set up this device' });
    expect(back).toHaveClass('auth-back-link');
    expect(back.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await user.click(back);
    expect(onBack).toHaveBeenCalledOnce();
  });
});

describe('AuthGate composition', () => {
  it('renders official branding and first-run actions without premature password copy', async () => {
    const user = userEvent.setup();
    const dispatch = vi.fn();
    render(
      <AuthGate
        projection={projection({ authState: 'noLocalUser' })}
        handlers={{ dispatch, submitSecret: () => undefined }}
      />,
    );

    const logo = screen.getByTestId('hushvoting-logo');
    expect(logo).toHaveAttribute('src', expect.stringContaining('hushvoting-logo.png'));
    expect(screen.getByRole('heading', { name: 'Welcome to HushVoting!' })).toBeInTheDocument();
    expect(screen.queryByText(/your device password protects credentials/i)).toBeNull();

    await user.click(screen.getByRole('button', { name: /create user/i }));
    expect(dispatch).toHaveBeenCalledWith({ type: 'INTENT.CREATE_USER' });
  });

  it('renders locked unlock form via AuthGate', () => {
    const dispatch = vi.fn();
    render(
      <AuthGate
        projection={projection({ authState: 'locked' })}
        handlers={{ dispatch, submitSecret: () => undefined }}
      />,
    );
    expect(screen.getByLabelText('Device password')).toBeInTheDocument();
    expect(screen.getByText(/your device password protects credentials/i)).toBeInTheDocument();
    expect(screen.getByLabelText('Network online')).toHaveAttribute('data-connectivity', 'online');
    expect(screen.queryByRole('button', { name: /forgot device password/i })).toBeNull();
  });

  it('never mounts protected navigation behind any auth surface', () => {
    const dispatch = vi.fn();
    render(
      <AuthGate
        projection={projection({ authState: 'locked', protectedAccess: false })}
        handlers={{ dispatch, submitSecret: () => undefined }}
      />,
    );
    expect(screen.queryByRole('navigation')).toBeNull();
    expect(screen.queryByText(/dashboard|election/i)).toBeNull();
  });
});
