/**
 * FEAT-004 browser-vault UI — direct password transfer boundary.
 *
 * Password fields are UNCONTROLLED DOM inputs. The value never enters React
 * state, XState, global stores, persisted form state, URL/history, logs, or
 * telemetry. On submission the value is read once and handed directly to the
 * authenticated channel via `onSubmitSecret`, then cleared immediately.
 * Standards-based paste and password-manager autofill remain available with
 * `current-password`/`new-password` autocomplete semantics. Duplicate
 * submissions are disabled while an operation is active.
 *
 * Normative source: FEAT-004 FeatureDescription "Password Boundary".
 */
import { useRef, useState } from 'react';

export interface DirectPasswordFieldProps {
  readonly onSubmitSecret: (password: string) => void;
  readonly kind: 'current-password' | 'new-password';
  readonly label: string;
  readonly disabled?: boolean;
  readonly busy?: boolean;
}

/**
 * Uncontrolled password input that transfers the value directly and clears it.
 * The component holds NO React state for the password value.
 */
export function DirectPasswordField({ onSubmitSecret, kind, label, disabled = false, busy = false }: DirectPasswordFieldProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = inputRef.current;
    if (input === null || input.value.length === 0) {
      setError('Enter the device password.');
      return;
    }
    setError(null);
    // Read once, hand directly to the authority, clear immediately.
    const value = input.value;
    input.value = '';
    onSubmitSecret(value);
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <label htmlFor={kind}>
        {label}
        <input
          id={kind}
          ref={inputRef}
          type="password"
          name={kind}
          autoComplete={kind}
          disabled={disabled || busy}
          aria-invalid={error !== null}
        />
      </label>
      {error !== null && (
        <p role="alert">{error}</p>
      )}
      <button type="submit" disabled={disabled || busy}>
        {busy ? 'Processing…' : 'Continue'}
      </button>
    </form>
  );
}
