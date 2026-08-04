/**
 * FEAT-008 recovery-words UI — protection, staging, recreation, resume, and
 * success surfaces (Task 5.5).
 *
 * Non-retention acknowledgement, default-checked Device-password choice,
 * WebAuthn/native passwordless flows, session-only warning, stage progress,
 * existing-profile verification, missing-profile alias/visibility review,
 * FEAT-007 registration status, staged resume, and automatic success
 * transition. No password or platform prompt appears before the selected
 * option requires it; no silent fallback is offered.
 */
import { useEffect, useRef, useState } from 'react';
import type { ProtectionMode } from '../../../lib/recovery-words/contracts/envelope';
import type { ProtectionProjection, StagedPreviewProjection } from '../../../lib/recovery-words/contracts/projection';
import { RecoveryActionButton, RecoveryBackButton, RecoveryFieldError, RecoveryPanel, RecoveryStatusRegion } from './surfaces';
import { PROTECTION, RECREATE, RESUME, STAGING, SUCCESS } from './copy';

export interface ProtectionProps {
  readonly protection: ProtectionProjection;
  readonly onChooseMode: (mode: ProtectionMode) => void;
  readonly onAcknowledge: () => void;
  readonly onBack: () => void;
}

export function ProtectionScreen({ protection, onChooseMode, onAcknowledge, onBack }: ProtectionProps) {
  const [mode, setMode] = useState<ProtectionMode | null>(protection.defaultPasswordChecked ? 'devicePasswordWeb' : null);
  const [sessionAcknowledged, setSessionAcknowledged] = useState(false);

  const choose = (next: ProtectionMode) => {
    setMode(next);
    onChooseMode(next);
  };

  return (
    <RecoveryPanel title={PROTECTION.title}>
      <p className="mb-4 rounded-xl bg-[var(--surface-strong)] p-3 text-sm font-medium text-[var(--text)]" data-testid="no-retention">
        {PROTECTION.acknowledgement}
      </p>

      <fieldset className="flex flex-col gap-3">
        <legend className="mb-1 text-sm font-medium text-[var(--text)]">Choose how this device is protected</legend>

        <label className="flex min-h-11 items-start gap-2 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text)]">
          <input type="radio" name="protection" checked={mode === 'devicePasswordWeb'} onChange={() => choose('devicePasswordWeb')} data-testid="mode-password" />
          <span>
            <span className="font-medium">{PROTECTION.defaultPasswordLabel}</span>
            <span className="block text-xs font-normal text-[var(--text-muted)]">{PROTECTION.defaultPasswordDetail}</span>
          </span>
        </label>

        {protection.allowedModes.includes('passwordlessWeb') && (
          <label className="flex min-h-11 items-start gap-2 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text)]">
            <input type="radio" name="protection" checked={mode === 'passwordlessWeb'} onChange={() => choose('passwordlessWeb')} data-testid="mode-passwordless-web" />
            <span>
              <span className="font-medium">{PROTECTION.passwordlessWebLabel}</span>
              <span className="block text-xs font-normal text-[var(--text-muted)]">{PROTECTION.syncedPasskeyNote}</span>
            </span>
          </label>
        )}

        {protection.allowedModes.includes('passwordlessNative') && (
          <label className="flex min-h-11 items-start gap-2 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text)]">
            <input type="radio" name="protection" checked={mode === 'passwordlessNative'} onChange={() => choose('passwordlessNative')} data-testid="mode-passwordless-native" />
            <span>
              <span className="font-medium">{PROTECTION.passwordlessNativeLabel}</span>
              <span className="block text-xs font-normal text-[var(--text-muted)]">{PROTECTION.unlockedDeviceWarning}</span>
            </span>
          </label>
        )}

        {protection.allowedModes.includes('sessionOnly') && (
          <label className="flex min-h-11 items-start gap-2 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text)]">
            <input type="radio" name="protection" checked={mode === 'sessionOnly'} onChange={() => choose('sessionOnly')} data-testid="mode-session" />
            <span>
              <span className="font-medium">{PROTECTION.sessionOnlyLabel}</span>
              <span className="block text-xs font-normal text-[var(--text-muted)]">{PROTECTION.sessionOnlyDetail}</span>
            </span>
          </label>
        )}
      </fieldset>

      {mode === 'sessionOnly' && (
        <label className="mt-3 flex items-center gap-2 text-sm text-[var(--text)]">
          <input type="checkbox" checked={sessionAcknowledged} onChange={(event) => setSessionAcknowledged(event.target.checked)} data-testid="session-ack" />
          {PROTECTION.sessionOnlyAck}
        </label>
      )}

      {mode === 'sessionOnly' && !sessionAcknowledged && (
        <RecoveryFieldError id="rw-session-ack">Please acknowledge that nothing will be saved on this device.</RecoveryFieldError>
      )}

      <div className="mt-4 flex items-center justify-between gap-3">
        <RecoveryBackButton onClick={onBack} />
        <RecoveryActionButton
          variant="primary"
          disabled={mode === null || (mode === 'sessionOnly' && !sessionAcknowledged)}
          onClick={() => {
            if (mode !== null) {
              onAcknowledge();
            }
          }}
        >
          {PROTECTION.continue}
        </RecoveryActionButton>
      </div>
    </RecoveryPanel>
  );
}

export interface StagingProps {
  readonly failed: boolean;
  readonly onBack: () => void;
}

export function StagingScreen({ failed, onBack }: StagingProps) {
  return (
    <RecoveryPanel title={failed ? STAGING.failTitle : STAGING.title}>
      <RecoveryStatusRegion>{failed ? STAGING.failDetail : STAGING.detail}</RecoveryStatusRegion>
      {failed && (
        <div className="mt-4">
          <RecoveryBackButton onClick={onBack} label="Back" />
        </div>
      )}
    </RecoveryPanel>
  );
}

export interface RecreateProps {
  readonly networkLabel: string;
  readonly onConfirm: (alias: string, visibility: 'private' | 'public') => void;
  readonly onBack: () => void;
}

export function RecreateScreen({ networkLabel, onConfirm, onBack }: RecreateProps) {
  const [alias, setAlias] = useState('');
  const [visibility, setVisibility] = useState<'private' | 'public'>('private');
  const [publicAcknowledged, setPublicAcknowledged] = useState(false);

  return (
    <RecoveryPanel title={RECREATE.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{RECREATE.detail}</p>
      <p className="mb-4 text-sm font-medium text-[var(--text)]">{RECREATE.networkNote(networkLabel)}</p>

      <label htmlFor="rw-alias" className="flex flex-col gap-1 text-sm text-[var(--text)]">
        {RECREATE.aliasLabel}
        <input
          id="rw-alias"
          value={alias}
          onChange={(event) => setAlias(event.target.value)}
          placeholder={RECREATE.aliasPlaceholder}
          className="mt-1 min-h-11 rounded-xl border border-transparent bg-[var(--surface-strong)] px-3 py-2 text-sm text-[var(--text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
          data-testid="recreate-alias"
        />
      </label>

      <fieldset className="mt-4">
        <legend className="text-sm font-medium text-[var(--text)]">Visibility</legend>
        <div className="mt-2 flex gap-3">
          <label className="flex min-h-11 items-center gap-2 rounded-xl bg-[var(--surface-strong)] px-3 text-sm text-[var(--text)]">
            <input type="radio" name="visibility" checked={visibility === 'private'} onChange={() => setVisibility('private')} data-testid="visibility-private" />
            {RECREATE.visibilityPrivate}
          </label>
          <label className="flex min-h-11 items-center gap-2 rounded-xl bg-[var(--surface-strong)] px-3 text-sm text-[var(--text)]">
            <input type="radio" name="visibility" checked={visibility === 'public'} onChange={() => setVisibility('public')} data-testid="visibility-public" />
            {RECREATE.visibilityPublic}
          </label>
        </div>
      </fieldset>

      {visibility === 'public' && (
        <label className="mt-3 flex items-center gap-2 text-sm text-[var(--text)]">
          <input type="checkbox" checked={publicAcknowledged} onChange={(event) => setPublicAcknowledged(event.target.checked)} data-testid="public-ack" />
          {RECREATE.publicAcknowledgement}
        </label>
      )}

      <div className="mt-4 flex items-center justify-between gap-3">
        <RecoveryBackButton onClick={onBack} />
        <RecoveryActionButton
          variant="primary"
          disabled={alias.trim().length === 0 || (visibility === 'public' && !publicAcknowledged)}
          onClick={() => onConfirm(alias.trim(), visibility)}
        >
          {RECREATE.create}
        </RecoveryActionButton>
      </div>
    </RecoveryPanel>
  );
}

export interface ResumeProps {
  readonly preview: StagedPreviewProjection;
  readonly onUnlock: () => void;
  readonly onLock: () => void;
}

export function FinishRestoringScreen({ preview, onUnlock, onLock }: ResumeProps) {
  if (preview.corrupted) {
    return (
      <RecoveryPanel title={RESUME.title}>
        <RecoveryFieldError id="rw-corrupt">The saved restore is damaged or unsupported.</RecoveryFieldError>
      </RecoveryPanel>
    );
  }
  return (
    <RecoveryPanel title={RESUME.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{RESUME.detail}</p>
      <dl className="mb-4 grid grid-cols-1 gap-1 text-xs text-[var(--text-muted)] sm:grid-cols-2">
        <div>
          <dt className="font-medium">Signing address</dt>
          <dd className="break-all">{preview.abbreviatedSigningAddress}</dd>
        </div>
        <div>
          <dt className="font-medium">Encryption address</dt>
          <dd className="break-all">{preview.abbreviatedEncryptionAddress}</dd>
        </div>
      </dl>
      <p className="mb-4 text-xs text-[var(--text-muted)]">Network: {preview.networkLabel}</p>
      <div className="flex items-center justify-between gap-3">
        <RecoveryActionButton variant="secondary" onClick={onLock}>
          Lock
        </RecoveryActionButton>
        <RecoveryActionButton variant="primary" onClick={onUnlock}>
          {RESUME.unlock}
        </RecoveryActionButton>
      </div>
    </RecoveryPanel>
  );
}

export interface SuccessProps {
  readonly onEnterDashboard: () => void;
}

/**
 * Identity restored — announced once, then the dashboard transition is
 * automatic (no extra Continue button, per the spec).
 */
export function SuccessScreen({ onEnterDashboard }: SuccessProps) {
  const announcedRef = useRef(false);
  useEffect(() => {
    if (!announcedRef.current) {
      announcedRef.current = true;
      // Announcement is complete; the authority drives the automatic
      // transition (no user-facing Continue button).
      onEnterDashboard();
    }
  }, [onEnterDashboard]);
  return (
    <RecoveryPanel title={SUCCESS.title}>
      <p className="text-sm text-[var(--text-muted)]" role="status">
        {SUCCESS.detail}
      </p>
    </RecoveryPanel>
  );
}
