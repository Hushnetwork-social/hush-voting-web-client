/**
 * FEAT-002 removal confirmation surface — exact phrase + final confirmation.
 *
 * A locked user may remove local credentials WITHOUT the password. The user
 * must enter the exact fixed phrase `REMOVE`, then activate a final
 * destructive confirmation. Removal is global and follows FEAT-010's cleanup
 * contract; it never modifies the blockchain identity. During removal the
 * surface shows non-cancellable completion progress.
 *
 * Normative source: FeatureDescription "Removal confirmation".
 */

import { useRef, useState } from 'react';

const REMOVE_PHRASE = 'REMOVE';

interface RemovalConfirmationProps {
  readonly onConfirmRemoval: () => void;
  readonly onCancel: () => void;
  readonly removing: boolean;
}

export function RemovalConfirmation({ onConfirmRemoval, onCancel, removing }: RemovalConfirmationProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [phrase, setPhrase] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const phraseMatches = phrase === REMOVE_PHRASE;

  function handleRemove(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!phraseMatches || !confirmed) {
      return;
    }
    onConfirmRemoval();
  }

  if (removing) {
    return (
      <div className="removal-progress" role="status" aria-live="polite">
        <p className="auth-lead">Removing local data…</p>
        <p>This cannot be cancelled.</p>
      </div>
    );
  }

  return (
    <form className="removal-confirmation" onSubmit={handleRemove} noValidate>
      <p className="auth-lead">Remove local credentials from this device? This cannot be undone.</p>
      <div className="field">
        <label htmlFor="removal-phrase">Type {REMOVE_PHRASE} to continue</label>
        <input
          id="removal-phrase"
          name="removalPhrase"
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={phrase}
          ref={inputRef}
          onChange={(event) => setPhrase(event.target.value)}
          aria-describedby="removal-hint"
        />
        <p id="removal-hint" className="field-hint">
          The exact phrase must match.
        </p>
      </div>

      <label className="confirm-row">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(event) => setConfirmed(event.target.checked)}
          disabled={!phraseMatches}
        />
        <span>I understand this removes local data only; it does not delete my on-chain identity.</span>
      </label>

      <div className="removal-actions">
        <button type="submit" className="button-danger" disabled={!phraseMatches || !confirmed}>
          Remove local user
        </button>
        <button type="button" className="link-button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
