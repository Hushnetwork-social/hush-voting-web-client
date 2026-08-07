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
 * to the authority sink; React never holds the value. Only a sanitized,
 * bounded basename is shown transiently for user confirmation; no path, URI,
 * provider identifier, input value, or filename reaches logs/worker/server.
 */
import { useRef, useState } from 'react';
import type { RestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import { BackoffCountdown, COPY, RestoreBackButton, RestoreErrorRegion, RestorePanel, RestorePrimaryButton, RestoreStatusRegion } from './surfaces';

export interface EntryAndPickerProps {
  readonly view: RestoreViewState;
  readonly sessionOnlyOnly: boolean;
  readonly onChooseFile: (file: File) => void;
  readonly onCancelRead: () => void;
  readonly onBack: () => void;
  readonly onAcknowledgeSessionOnly: () => void;
}

/** Picker + read surfaces (safe selected status; cancel neutral). */
export function PickerReadScreen({ view, sessionOnlyOnly, onChooseFile, onCancelRead, onBack, onAcknowledgeSessionOnly }: EntryAndPickerProps) {
  const [sessionAcknowledged, setSessionAcknowledged] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const openFilePicker = () => {
    fileInputRef.current?.click();
  };

  const handleFileSelection = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.item(0) ?? null;
    // Clear the native input immediately so selecting the same file again
    // after a failed attempt still produces a change event.
    event.currentTarget.value = '';
    if (file !== null) {
      onChooseFile(file);
    }
  };
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
          <RestoreStatusRegion>{COPY.picker.detail}</RestoreStatusRegion>
          <input
            ref={fileInputRef}
            type="file"
            accept=".dat,application/octet-stream"
            className="sr-only"
            tabIndex={-1}
            aria-hidden="true"
            data-testid="credential-file-input"
            onChange={handleFileSelection}
          />
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <RestorePrimaryButton testId="choose-file" onClick={openFilePicker} fullWidth>
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
  readonly selectedFileName?: string | null;
  readonly onSubmit: (password: string) => void;
  readonly onToggleVisibility: () => void;
  readonly onToggleEmptyOption: (enabled: boolean) => void;
  readonly onChooseDifferentFile: () => void;
  readonly onBack: () => void;
}

/** Backup-file password surface — uncontrolled field, direct secret sink. */
export function PasswordScreen({ view, selectedFileName, onSubmit, onToggleVisibility, onToggleEmptyOption, onChooseDifferentFile, onBack }: PasswordScreenProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  // React tracks only whether bytes were entered, never the password value.
  const [hasPassword, setHasPassword] = useState(false);
  // Empty-password state is view-driven (the authority projection owns it).
  const emptyEnabled = view.passwordFieldState?.emptyOptionChecked ?? false;
  const visible = view.passwordFieldState?.visible ?? false;
  const canSubmit = view.backoff === null && (emptyEnabled || hasPassword);

  const submit = () => {
    if (!canSubmit) return;
    const value = emptyEnabled ? '' : (inputRef.current?.value ?? '');
    onSubmit(value);
    if (inputRef.current) {
      inputRef.current.value = ''; // clear the field after submission
    }
    setHasPassword(false);
  };

  const toggleEmpty = () => {
    const next = !emptyEnabled;
    onToggleEmptyOption(next);
    setHasPassword(false);
    if (inputRef.current) {
      inputRef.current.value = '';
      inputRef.current.disabled = next;
    }
  };

  return (
    <RestorePanel title={COPY.password.title}>
      <div
        role="status"
        className="selection-display mb-4 flex items-center gap-3 px-4 text-sm font-semibold text-[var(--text)]"
        data-testid="selected-file-status"
      >
        <svg aria-hidden="true" viewBox="0 0 24 24" className="h-5 w-5 shrink-0 text-[var(--accent)]" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h5l2 2h9.5v8.5a2 2 0 0 1-2 2H5.75a2 2 0 0 1-2-2V6.75Z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="m9.25 14 1.75 1.75L15.5 11" />
        </svg>
        <span className="min-w-0">
          <span className="block text-xs font-medium text-[var(--text-muted)]">{COPY.picker.selectedLabel}</span>
          <span className="block truncate" data-testid="selected-file-name">
            {selectedFileName ?? COPY.picker.selectedFallback}
          </span>
        </span>
      </div>

      <p className="mb-4 text-sm leading-6 text-[var(--text-muted)]" data-testid="password-explainer">
        {COPY.password.explainer}
      </p>

      <form onSubmit={(event) => { event.preventDefault(); submit(); }}>
        <label className="block text-sm font-medium text-[var(--text)]" htmlFor="backup-file-password">
          {COPY.password.label}
        </label>
        <div className="relative mt-2">
          <input
            ref={inputRef}
            id="backup-file-password"
            type={visible ? 'text' : 'password'}
            disabled={emptyEnabled}
            autoComplete="off"
            autoFocus
            placeholder="Enter backup-file password"
            onInput={(event) => { setHasPassword(event.currentTarget.value.length > 0); }}
            data-testid="backup-password-input"
            className="text-input pr-20 text-sm"
          />
          <button
            type="button"
            onClick={() => { onToggleVisibility(); }}
            aria-pressed={visible}
            aria-label={visible ? COPY.password.hide : COPY.password.show}
            className="absolute inset-y-0 right-1 min-h-11 rounded-[0.35rem] px-3 text-sm font-semibold text-[var(--primary)] focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-[var(--focus)]"
            data-testid="toggle-password-visibility"
          >
            {visible ? 'Hide' : 'Show'}
          </button>
        </div>

        <label className="mt-3 flex items-start gap-2 text-sm text-[var(--text)]">
          <input type="checkbox" checked={emptyEnabled} onChange={toggleEmpty} data-testid="empty-password-option" className="mt-1 accent-[var(--accent)]" />
          <span>
            <span className="font-medium">{COPY.password.noPassword}</span>
            <span className="block text-xs text-[var(--text-muted)]">{COPY.password.noPasswordWarning}</span>
          </span>
        </label>

        <div className="mt-5">
          <RestorePrimaryButton testId="submit-password" type="submit" disabled={!canSubmit} fullWidth>
            {COPY.password.submit}
          </RestorePrimaryButton>
        </div>
      </form>

      <div className="mt-3 flex flex-wrap items-center justify-center gap-3">
        <button type="button" onClick={onChooseDifferentFile} className="min-h-11 rounded-xl px-3 text-sm font-medium text-[var(--primary)]" data-testid="choose-different-file">
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
      return COPY.errors.combined;
    case 'BACKOFF_ACTIVE':
      return COPY.errors.wait;
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
