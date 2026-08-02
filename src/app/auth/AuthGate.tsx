/**
 * FEAT-002 AuthGate — composition root for the Sovereign Shield surfaces.
 *
 * Consumes ONLY the render projection + typed intent callbacks. No transition
 * logic lives here; the machine owns transitions. Protected content never
 * mounts behind these surfaces; the authenticated application shell is
 * rendered by the page only when `projection.protectedAccess` is true.
 *
 * Surfaces: initializing, first-run (noLocalUser), onboarding placeholder
 * (child flows are downstream), locked, unlocking progress, verifying
 * progress, missing-profile confirmation, error (recoverable/blocked),
 * removal confirmation, and temporary-mode warning.
 */

import type { AuthRenderProjection } from '../../lib/auth/react/adapter';
import type { AuthIntent } from '../../lib/auth/types';
import { AuthShell } from './AuthShell';
import { FirstRun } from './FirstRun';
import { LockedUser } from './LockedUser';
import { RemovalConfirmation } from './RemovalConfirmation';
import { ErrorSurface, RecoveryNavigation, TemporaryMode } from './ErrorSurfaces';
import { useState } from 'react';

export interface AuthGateHandlers {
  readonly dispatch: (intent: AuthIntent) => void;
  readonly submitSecret: (secret: string) => void;
}

interface AuthGateProps {
  readonly projection: AuthRenderProjection;
  readonly handlers: AuthGateHandlers;
}

/** Pending surface shared by unlocking / verifying / removing states. */
function PendingSurface({ label }: { label: string }) {
  return (
    <div className="pending-surface" role="status" aria-live="polite">
      <p className="auth-lead">{label}</p>
    </div>
  );
}

export function AuthGate({ projection, handlers }: AuthGateProps) {
  const { authState } = projection;
  const [showRecovery, setShowRecovery] = useState(false);
  const [showTemporary, setShowTemporary] = useState(false);

  // Surface selection is purely a projection of machine state.
  let surface: React.ReactNode;
  switch (authState) {
    case 'initializing':
      surface = <PendingSurface label="Preparing…" />;
      break;
    case 'noLocalUser':
      surface = showTemporary ? (
        <TemporaryMode
          onEnterTemporaryMode={() => {
            setShowTemporary(false);
            handlers.dispatch({ type: 'INTENT.ENTER_TEMPORARY_MODE' });
          }}
          onCancel={() => setShowTemporary(false)}
        />
      ) : (
        <FirstRun
          onCreateUser={() => handlers.dispatch({ type: 'INTENT.CREATE_USER' })}
          onRestoreCredentialFile={() => handlers.dispatch({ type: 'INTENT.RESTORE_CREDENTIAL_FILE' })}
          onRestoreRecoveryWords={() => handlers.dispatch({ type: 'INTENT.RESTORE_RECOVERY_WORDS' })}
        />
      );
      break;
    case 'onboarding':
      // Child flows are implemented by downstream features; render a safe
      // placeholder that dispatches Back so cleanup always runs.
      surface = (
        <div className="onboarding-placeholder">
          <p className="auth-lead">Setting up…</p>
          <button
            type="button"
            className="link-button"
            onClick={() => handlers.dispatch({ type: 'INTENT.BACK_FROM_ONBOARDING' })}
          >
            Back
          </button>
        </div>
      );
      break;
    case 'locked':
      surface = showRecovery ? (
        <RecoveryNavigation
          onRestoreCredentialFile={() => handlers.dispatch({ type: 'INTENT.RESTORE_CREDENTIAL_FILE' })}
          onRestoreRecoveryWords={() => handlers.dispatch({ type: 'INTENT.RESTORE_RECOVERY_WORDS' })}
          onBackToUnlock={() => setShowRecovery(false)}
        />
      ) : (
        <LockedUser
          onSubmitSecret={handlers.submitSecret}
          onForgotPassword={() => setShowRecovery(true)}
          onRemoveLocalUser={() => handlers.dispatch({ type: 'INTENT.REMOVE_LOCAL_USER' })}
        />
      );
      break;
    case 'unlocking':
      surface = <PendingSurface label="Unlocking this device…" />;
      break;
    case 'verifyingIdentityOnline':
      surface = <PendingSurface label="Checking your identity with the network…" />;
      break;
    case 'missingProfileConfirmation':
      surface = (
        <div className="confirm-profile">
          <p className="auth-lead">No profile was found for this identity.</p>
          <button
            type="button"
            className="button-primary"
            onClick={() => handlers.dispatch({ type: 'INTENT.CONFIRM_MISSING_PROFILE' })}
          >
            Create the identity
          </button>
          <button
            type="button"
            className="link-button"
            onClick={() => handlers.dispatch({ type: 'INTENT.BACK_FROM_ONBOARDING' })}
          >
            Back
          </button>
        </div>
      );
      break;
    case 'recoverableError':
    case 'blockedError':
      surface = (
        <ErrorSurface
          projection={projection}
          onRetry={() => handlers.dispatch({ type: 'INTENT.RETRY' })}
          onLock={() => handlers.dispatch({ type: 'INTENT.LOCK' })}
          onRemoveLocalUser={() => handlers.dispatch({ type: 'INTENT.REMOVE_LOCAL_USER' })}
        />
      );
      break;
    case 'removingLocalUser':
      // Non-cancellable removal progress (confirmed at locked-time).
      surface = <RemovalConfirmation onConfirmRemoval={() => undefined} onCancel={() => undefined} removing />;
      break;
    default:
      surface = <PendingSurface label="Preparing…" />;
  }

  return (
    <AuthShell projection={projection}>{surface}</AuthShell>
  );
}
