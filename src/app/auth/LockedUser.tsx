/**
 * FEAT-002 locked-user surface — safe metadata + device-password unlock.
 *
 * SECRET BOUNDARY: the password input value is transferred DIRECTLY to the
 * secret authority through `onSubmitSecret` and cleared immediately after
 * accepted transfer. React never stores the password in state, and no
 * machine event, render projection, log, title, or accessible announcement
 * ever receives it.
 *
 * Shows only: alias, abbreviated signing address, device-password entry,
 * Unlock, Forgot device password? (recovery navigation), and a separate
 * Remove local user action. No avatar, full-address copy, server-login
 * language, or authenticated navigation is mounted.
 *
 * Normative source: FeatureDescription "Locked-user screen",
 * "Secret submission boundary".
 */

import { useRef, useState } from 'react';

interface LockedUserProps {
  readonly onSubmitSecret: (password: string) => void;
  readonly onForgotPassword: () => void;
  readonly onRemoveLocalUser: () => void;
  readonly disabled?: boolean;
}

export function LockedUser({ onSubmitSecret, onForgotPassword, onRemoveLocalUser, disabled = false }: LockedUserProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = inputRef.current;
    if (input === null || input.value.length === 0) {
      setError('Enter your device password.');
      return;
    }
    // Direct secret transfer: hand the value to the authority, then clear.
    onSubmitSecret(input.value);
    input.value = '';
    setError(null);
  }

  return (
    <form className="locked-user" onSubmit={handleSubmit} noValidate>
      <div className="field">
        <label htmlFor="device-password">{'Device password'}</label>
        <input
          id="device-password"
          name="devicePassword"
          type="password"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          ref={inputRef}
          aria-invalid={error !== null}
          aria-describedby={error !== null ? 'device-password-error' : undefined}
          disabled={disabled}
        />
        {error !== null && (
          <p id="device-password-error" className="field-error" role="alert">
            {error}
          </p>
        )}
      </div>

      <div className="locked-actions">
        <button type="submit" className="button-primary" disabled={disabled}>
          {'Unlock HushVoting'}
        </button>
        <button type="button" className="link-button" onClick={onForgotPassword} disabled={disabled}>
          {'Forgot device password?'}
        </button>
      </div>

      <hr className="separator" />

      <button type="button" className="button-danger-ghost" onClick={onRemoveLocalUser} disabled={disabled}>
        {'Remove local user'}
      </button>
    </form>
  );
}
