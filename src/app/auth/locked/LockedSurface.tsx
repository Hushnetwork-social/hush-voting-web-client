/**
 * FEAT-010 UI — mode-specific locked surface + minimal authenticated home
 * (Task 5.3).
 *
 * Locked views are protection-mode-specific: Device-password shows the direct
 * secret-transfer field (cleared immediately after accepted transfer); every
 * passwordless mode shows its device action with NO password field or
 * fallback. Ubuntu honestly discloses that access follows the unlocked OS
 * session. The minimal home shows safe identity/network/connectivity, Lock,
 * Identity and security, and strongly confirmed removal — never mock
 * elections, roles, feeds, or a FEAT-011 export action.
 *
 * SECRET BOUNDARY: the password value is handed to `onSubmitSecret` and the
 * field clears immediately; no component state, log, or announcement keeps it.
 */

import { useRef, useState } from 'react';
import type { LockedViewProjection, HomeProjection, UnlockProgressProjection } from '../../../lib/auth/presentation';

/** Mode-scoped field error (never survives a mode change). */
interface FieldError {
  readonly mode: string;
  readonly message: string;
}

/** Mode-specific locked surface driven ONLY by the Phase 4 projection. */
export interface LockedSurfaceProps {
  readonly projection: LockedViewProjection;
  readonly progress: UnlockProgressProjection | null;
  readonly onSubmitSecret: (secret: string) => void;
  readonly onUnlockDevice: () => void;
  readonly onRecovery: () => void;
  readonly onRemoveLocalUser: () => void;
}

export function LockedSurface({ projection, progress, onSubmitSecret, onUnlockDevice, onRecovery, onRemoveLocalUser }: LockedSurfaceProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [fieldError, setFieldError] = useState<FieldError | null>(null);

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = inputRef.current;
    if (input === null || input.value.length === 0) {
      setFieldError({ mode: projection.mode, message: 'Enter your device password.' });
      return;
    }
    // Direct secret transfer → authority, then immediate clear (AC-010-029).
    onSubmitSecret(input.value);
    input.value = '';
  }

  const busy = progress?.state === 'unlocking' || progress?.state === 'verifying';
  const throttled = progress?.state === 'cooldown';
  const visibleError = fieldError !== null && fieldError.mode === projection.mode ? fieldError.message : null;

  return (
    <div className="locked-surface">
      <h1>Welcome back</h1>
      {projection.showDevicePasswordField ? (
        <form onSubmit={handleSubmit} className="unlock-form">
          <label htmlFor="device-password">Device password</label>
          <input
            id="device-password"
            ref={inputRef}
            type="password"
            autoComplete="current-password"
            aria-describedby={visibleError !== null ? 'device-password-error' : undefined}
            disabled={busy || throttled}
          />
          {visibleError !== null ? (
            <p id="device-password-error" role="alert">
              {visibleError}
            </p>
          ) : null}
          <button type="submit" className="button-primary" disabled={busy || throttled}>
            {projection.unlockLabel}
          </button>
        </form>
      ) : (
        <button type="button" className="button-primary" onClick={onUnlockDevice} disabled={busy || throttled}>
          {projection.unlockLabel}
        </button>
      )}
      {projection.disclosure !== undefined ? <p className="disclosure">{projection.disclosure}</p> : null}
      {throttled && progress?.cooldownDeadlineMs !== undefined ? (
        <p role="status" aria-live="polite" className="cooldown">
          Too many attempts. Try again after the cooldown.
        </p>
      ) : null}
      {busy ? (
        <p role="status" aria-live="polite" className="pending">
          {progress?.state === 'verifying' ? 'Checking your identity with the network…' : 'Unlocking this device…'}
        </p>
      ) : null}
      <div className="locked-actions">
        <button type="button" className="link-button" onClick={onRecovery}>
          {projection.recoveryLabel}
        </button>
        <button type="button" className="link-button danger" onClick={onRemoveLocalUser}>
          Remove local user
        </button>
      </div>
    </div>
  );
}

/** Minimal authenticated home (AC-010-044/045). */
export interface HomeSurfaceProps {
  readonly projection: HomeProjection;
  readonly onLock: () => void;
  readonly onOpenSettings: () => void;
  readonly onRemoveLocalUser: () => void;
}

export function HomeSurface({ projection, onLock, onOpenSettings, onRemoveLocalUser }: HomeSurfaceProps) {
  return (
    <div className="home-surface" data-testid="authenticated-home">
      <h1>HushVoting</h1>
      <p className="identity-summary">
        {projection.alias} · {projection.abbreviatedSigningAddress}
      </p>
      <p className="network-context">{projection.networkContext}</p>
      {projection.showSessionOnlyWarning ? (
        <p role="note" className="session-only-warning">
          Session-only — Lock or closing the app removes this local session.
        </p>
      ) : null}
      <p className="connectivity" role="status" aria-live="polite">
        {projection.connectivity === 'online'
          ? 'Online'
          : projection.connectivity === 'reconnecting'
            ? 'Reconnecting…'
            : 'Offline — local access only'}
      </p>
      <div className="home-actions">
        <button type="button" className="button-primary" onClick={onLock}>
          {projection.lockLabel}
        </button>
        <button type="button" className="button-secondary" onClick={onOpenSettings}>
          Identity and security
        </button>
        <button type="button" className="link-button danger" onClick={onRemoveLocalUser}>
          Remove local user
        </button>
      </div>
    </div>
  );
}
