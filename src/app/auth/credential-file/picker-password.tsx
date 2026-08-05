/**
 * FEAT-009 credential-file UI — entry, picker, read, and password surfaces
 * (Tasks 5.1, 5.3).
 *
 * Verified-empty entry wiring (the three-choice entry itself lives in the
 * FEAT-002 auth shell), capability disclosure, one-source picker with
 * neutral cancellation, safe selected status, bounded-read progress with
 * Cancel, purpose-specific Backup-file password with accessible show/hide
 * and explicit empty option, and structural/authentication error surfaces.
 *
 * SECRET BOUNDARY: the password field is uncontrolled and submits directly
 * to the authority sink; React never holds the value. File input value/
 * name never reaches rendered text, state, or logs.
 */
import { useRef, useState } from 'react';
import type { RestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import { BackoffCountdown, COPY, RestoreBackButton, RestoreErrorRegion, RestorePanel, RestorePrimaryButton, RestoreStatusRegion } from './surfaces';

export interface EntryAndPickerProps {
  readonly view: RestoreViewState;
  readonly sessionOnlyOnly: boolean;
  readonly onChooseFile: () => void;
  readonly onCancelRead: () => void;
  readonly onBack: () => void;
  readonly onAcknowledgeSessionOnly: () => void;
}

/** Picker + read surfaces (safe selected status; cancel neutral). */
export function PickerReadScreen({ view, sessionOnlyOnly, onChooseFile, onCancelRead, onBack, onAcknowledgeSessionOnly }: EntryAndPickerProps) {
  const [sessionAcknowledged, setSessionAcknowledged] = useState(false);
  if (view.screen === 'reading') {
    return (
      <RestorePanel title={COPY.reading.title}>
        <RestoreStatusRegion>{COPY.reading.title}</RestoreStatusRegion>
        <div className="mt-4 flex items-center gap-3">
          <RestorePrimaryButton testId="cancel-read" onClick={onCancelRead}>
            {COPY.reading.cancel}
          </RestorePrimaryButton>
          <RestoreBackButton onBack={onBack} />
        </div>
      </RestorePanel>
    );
  }

  const sessionOnlyGate = sessionOnlyOnly && !sessionAcknowledged;
  return (
    <RestorePanel title={COPY.picker.title}>
      {sessionOnlyGate ? (
        <>
          <RestoreStatusRegion>{COPY.protection.sessionOnlyWarning}</RestoreStatusRegion>
          <div className="mt-4 flex items-center gap-3">
            <RestorePrimaryButton testId="ack-session-only" onClick={() => { setSessionAcknowledged(true); onAcknowledgeSessionOnly(); }}>
              Continue session-only
            </RestorePrimaryButton>
            <RestoreBackButton onBack={onBack} />
          </div>
        </>
      ) : (
        <>
          <RestoreStatusRegion>{view.copyKey === 'credentialFileSelected' ? COPY.picker.selected : COPY.picker.detail}</RestoreStatusRegion>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <RestorePrimaryButton testId="choose-file" onClick={onChooseFile}>
              {view.failureCode !== null ? COPY.picker.different : COPY.picker.choose}
            </RestorePrimaryButton>
            <RestoreBackButton onBack={onBack} />
          </div>
          {view.failureCode !== null && <RestoreErrorRegion>{errorCopy(view.failureCode)}</RestoreErrorRegion>}
        </>
      )}
    </RestorePanel>
  );
}

export interface PasswordScreenProps {
  readonly view: RestoreViewState;
  readonly onSubmit: (password: string) => void;
  readonly onToggleVisibility: () => void;
  readonly onToggleEmptyOption: (enabled: boolean) => void;
  readonly onChooseDifferentFile: () => void;
  readonly onBack: () => void;
}

/** Backup-file password surface — uncontrolled field, direct secret sink. */
export function PasswordScreen({ view, onSubmit, onToggleVisibility, onToggleEmptyOption, onChooseDifferentFile, onBack }: PasswordScreenProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [emptyEnabled, setEmptyEnabled] = useState(false);
  const visible = view.passwordFieldState?.visible ?? false;

  const submit = () => {
    const value = emptyEnabled ? '' : (inputRef.current?.value ?? '');
    onSubmit(value);
    if (inputRef.current) {
      inputRef.current.value = ''; // clear the field after submission
    }
  };

  const toggleEmpty = () => {
    const next = !emptyEnabled;
    setEmptyEnabled(next);
    onToggleEmptyOption(next);
    if (inputRef.current) {
      inputRef.current.value = '';
      inputRef.current.disabled = next;
    }
  };

  return (
    <RestorePanel title={COPY.password.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]" data-testid="password-explainer">
        {COPY.password.explainer}
      </p>

      <label className="block text-sm font-medium text-[var(--text)]" htmlFor="backup-file-password">
        {COPY.password.label}
      </label>
      <div className="mt-2 flex items-center gap-2">
        <input
          ref={inputRef}
          id="backup-file-password"
          type={visible ? 'text' : 'password'}
          disabled={emptyEnabled}
          autoComplete="off"
          data-testid="backup-password-input"
          className="min-h-11 flex-1 rounded-xl bg-[var(--surface)] px-3 text-sm text-[var(--text)]"
        />
        <button
          type="button"
          onClick={() => { onToggleVisibility(); }}
          aria-pressed={visible}
          aria-label={visible ? COPY.password.hide : COPY.password.show}
          className="min-h-11 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)]"
          data-testid="toggle-password-visibility"
        >
          {visible ? 'Hide' : 'Show'}
        </button>
      </div>

      <label className="mt-3 flex items-start gap-2 text-sm text-[var(--text)]">
        <input type="checkbox" checked={emptyEnabled} onChange={toggleEmpty} data-testid="empty-password-option" className="mt-1" />
        <span>
          <span className="font-medium">{COPY.password.noPassword}</span>
          <span className="block text-xs text-[var(--text-muted)]">{COPY.password.noPasswordWarning}</span>
        </span>
      </label>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <RestorePrimaryButton testId="submit-password" onClick={submit} disabled={!view.canSubmitPassword && !emptyEnabled}>
          {COPY.password.submit}
        </RestorePrimaryButton>
        <button type="button" onClick={onChooseDifferentFile} className="min-h-11 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)]" data-testid="choose-different-file">
          {COPY.picker.different}
        </button>
        <RestoreBackButton onBack={onBack} />
      </div>

      {view.backoff !== null && <BackoffCountdown remainingSeconds={view.backoff.remainingSeconds} />}
      {view.failureCode !== null && <RestoreErrorRegion>{errorCopy(view.failureCode)}</RestoreErrorRegion>}
    </RestorePanel>
  );
}

/** Structural/authentication/semantic error copy (bounded; never echoes values). */
export function errorCopy(code: string): string {
  switch (code) {
    case 'AUTHENTICATION_FAILED':
    case 'BACKOFF_ACTIVE':
      return COPY.errors.combined;
    case 'SIGNING_KEY_MISMATCH':
    case 'ENCRYPTION_KEY_MISMATCH':
    case 'KEY_PROOF_FAILED':
    case 'MNEMONIC_KEY_MISMATCH':
    case 'UNSUPPORTED_KEY_ENCODING':
    case 'PAYLOAD_DUPLICATE_FIELD':
    case 'PAYLOAD_UNKNOWN_FIELD':
    case 'PAYLOAD_MISSING_FIELD':
    case 'PAYLOAD_INVALID_FIELD':
      return COPY.errors.inconsistentKeys;
    case 'ENVELOPE_TOO_SHORT':
    case 'ENVELOPE_OVERSIZE':
    case 'INVALID_MAGIC':
    case 'UNSUPPORTED_VERSION':
      return COPY.errors.invalidFile;
    case 'SERVER_PROOF_REJECTED':
      return COPY.errors.serverProof;
    case 'CLEANUP_FAILURE':
    case 'QUARANTINED':
      return COPY.errors.quarantine;
    default:
      return COPY.errors.generic;
  }
}
