/**
 * FEAT-009 credential-file UI — profile review, protection, staging,
 * resume, and success surfaces (Task 5.5).
 *
 * Existing-profile progress, missing-profile explanation/review with
 * abbreviated/revealable addresses, separate protection choice (Device
 * password default; qualified alternatives; session-only warning), stage
 * progress, staged resume gate, server-proof rejection, exact success, and
 * the mnemonic-source notice. No Backup-file password or source state is
 * mounted here.
 */
import { useRef, useState } from 'react';
import type { RestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import type { RestoreProtectionChoice } from '../../../lib/credential-file-restore/contracts/projection';
import { COPY, RestoreBackButton, RestoreErrorRegion, RestorePanel, RestorePrimaryButton, RestoreStatusRegion } from './surfaces';
import { SafeAlias } from '../SafeAlias';

export interface ProfileProtectionProps {
  readonly onAcknowledgeSessionOnly?: (acknowledged?: boolean) => void;
  readonly view: RestoreViewState;
  readonly onChooseProtection: (mode: RestoreProtectionChoice, devicePassword?: string) => void;
  readonly onCreateIdentity: () => void;
  readonly onUpdateProfile?: (alias: string, visibility: 'private' | 'public') => void;
  readonly onAcknowledgePublic?: (acknowledged: boolean) => void;
  readonly publicAcknowledged?: boolean;
  readonly canCreateProfile?: boolean;
  readonly onReveal: () => void;
  readonly onUnlockResume: () => void;
  readonly onCancelStage: () => void;
  readonly onBack: () => void;
}

/** Missing-profile review (explicit Create only; abbreviated addresses). */
export function ProfileReviewScreen({ view, onCreateIdentity, onReveal, onBack, onUpdateProfile, onAcknowledgePublic, publicAcknowledged, canCreateProfile }: ProfileProtectionProps) {
  const profile = view.profile;
  const [revealRequested, setRevealRequested] = useState(false);
  const revealed = revealRequested ? view.reveal : null;
  return (
    <RestorePanel title={COPY.profile.missing}>
      <p className="mt-3 text-sm text-[var(--text-muted)]">This may happen after a blockchain reset or if the identity was never registered. Creating its profile uses the same recovered keys.</p>
      {profile?.aliasEditable && <div className="mt-4 space-y-3">
        <label htmlFor="file-profile-alias" className="block text-sm">Profile name</label>
        <input id="file-profile-alias" data-testid="file-profile-alias" className="text-input" maxLength={256} value={profile.alias}
          onChange={event => onUpdateProfile?.(event.currentTarget.value, profile.isPublic ? 'public' : 'private')} />
        <fieldset className="flex gap-4"><legend className="text-sm">Visibility</legend>
          <label><input type="radio" name="file-profile-visibility" checked={!profile.isPublic} onChange={() => onUpdateProfile?.(profile.alias, 'private')} /> Private</label>
          <label><input type="radio" name="file-profile-visibility" checked={profile.isPublic} onChange={() => onUpdateProfile?.(profile.alias, 'public')} /> Public</label>
        </fieldset>
        {profile.isPublic && <label className="flex items-start gap-2 text-sm"><input type="checkbox" data-testid="file-profile-public-ack" checked={publicAcknowledged ?? false}
          onChange={event => onAcknowledgePublic?.(event.currentTarget.checked)} /> I understand this profile will be publicly discoverable.</label>}
      </div>}
      {profile !== null && (
        <dl className="mt-3 space-y-2 text-sm text-[var(--text)]">
          <div className="flex items-center justify-between gap-3">
            <dt className="text-[var(--text-muted)]">{COPY.profile.signing}</dt>
            <dd className="font-mono">{profile.signingAddressAbbreviated}</dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-[var(--text-muted)]">{COPY.profile.encryption}</dt>
            <dd className="font-mono">{profile.encryptionAddressAbbreviated}</dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-[var(--text-muted)]">{COPY.profile.network}</dt>
            <dd>{profile.networkLabel}</dd>
          </div>
        </dl>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <RestorePrimaryButton testId="create-identity" disabled={canCreateProfile === false} onClick={onCreateIdentity}>
          {COPY.profile.create}
        </RestorePrimaryButton>
        <button type="button" onClick={() => { setRevealRequested(!revealRequested); onReveal(); }} className="min-h-11 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)]" data-testid="reveal-addresses">
          {revealed ? 'Hide full addresses' : COPY.profile.reveal}
        </button>
        <RestoreBackButton onBack={onBack} />
      </div>
      {revealed && <div className="mt-4 space-y-3 text-sm">
        <p>Signing address</p><code className="block break-all" data-testid="file-full-signing-address">{revealed.fullSigningAddress}</code>
        <p>Encryption address</p><code className="block break-all" data-testid="file-full-encryption-address">{revealed.fullEncryptionAddress}</code>
      </div>}
      {view.failureCode !== null && <RestoreErrorRegion>Enter a valid profile name before continuing.</RestoreErrorRegion>}
    </RestorePanel>
  );
}

/** Separate protection choice — Device password default; no co-mounted backup state. */
export function ProtectionScreen({ view, onChooseProtection, onBack, onAcknowledgeSessionOnly }: ProfileProtectionProps) {
  const choices = view.protectionChoices ?? [];
  const [sessionAcknowledged, setSessionAcknowledged] = useState(false);
  const [selectedMode, setSelectedMode] = useState<RestoreProtectionChoice>(choices[0] ?? 'devicePassword');
  const [confirmationError, setConfirmationError] = useState<string | null>(null);
  const [canSubmitPassword, setCanSubmitPassword] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);

  const updatePasswordReadiness = () => {
    const password = passwordRef.current?.value ?? '';
    const confirmation = confirmationRef.current?.value ?? '';
    setCanSubmitPassword(password.length >= 8 && password === confirmation);
    setConfirmationError(null);
  };

  const submitProtection = () => {
    if (selectedMode !== 'devicePassword') {
      if (selectedMode !== 'sessionOnly' || !sessionAcknowledged) return;
      onChooseProtection(selectedMode);
      return;
    }
    const password = passwordRef.current?.value ?? '';
    const confirmation = confirmationRef.current?.value ?? '';
    if (password.length < 8 || password !== confirmation) {
      setConfirmationError(password.length < 8 ? 'Use at least 8 characters.' : 'Device passwords do not match.');
      (password.length < 8 ? passwordRef.current : confirmationRef.current)?.focus();
      return;
    }
    onChooseProtection(selectedMode, password);
    if (passwordRef.current) passwordRef.current.value = '';
    if (confirmationRef.current) confirmationRef.current.value = '';
    setConfirmationError(null);
  };

  return (
    <RestorePanel title={COPY.protection.title}>
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-1 text-sm font-medium text-[var(--text)]">{COPY.protection.createVaultPassword}</legend>
        {choices.map((mode) => (
          <label key={mode} className="flex min-h-11 items-center gap-3 rounded-[0.85rem] bg-[var(--surface)] p-3 text-sm text-[var(--text)]">
            <input
              type="radio"
              name="restore-protection"
              checked={selectedMode === mode}
              onChange={() => { setSelectedMode(mode); setSessionAcknowledged(false); onAcknowledgeSessionOnly?.(false); }}
              data-testid={`protection-${mode}`}
            />
            <span>{protectionLabel(mode)}</span>
            {mode === 'sessionOnly' && <span className="ml-auto text-xs text-[var(--text-muted)]">{COPY.protection.sessionOnlyWarning}</span>}
          </label>
        ))}
      </fieldset>
      <form onSubmit={(event) => { event.preventDefault(); submitProtection(); }}>
        {selectedMode === 'devicePassword' && (
          <div className="mt-4 space-y-3">
            <label className="block text-sm font-medium text-[var(--text)]" htmlFor="restore-device-password">
              Device password
            </label>
            <input
              ref={passwordRef}
              id="restore-device-password"
              type="password"
              autoComplete="new-password"
              onInput={updatePasswordReadiness}
              className="text-input text-sm"
              data-testid="restore-device-password"
            />
            <label className="block text-sm font-medium text-[var(--text)]" htmlFor="restore-device-password-confirmation">
              Confirm device password
            </label>
            <input
              ref={confirmationRef}
              id="restore-device-password-confirmation"
              type="password"
              autoComplete="new-password"
              onInput={updatePasswordReadiness}
              aria-invalid={confirmationError !== null}
              aria-describedby={confirmationError !== null ? 'restore-device-password-error' : undefined}
              className="text-input text-sm"
              data-testid="restore-device-password-confirmation"
            />
            {confirmationError !== null && <div id="restore-device-password-error"><RestoreErrorRegion>{confirmationError}</RestoreErrorRegion></div>}
          </div>
        )}
        {selectedMode === 'sessionOnly' && <label className="mt-3 flex min-h-11 items-center gap-2 text-sm">
          <input type="checkbox" checked={sessionAcknowledged} onChange={event => {
            setSessionAcknowledged(event.target.checked);
            onAcknowledgeSessionOnly?.(event.target.checked);
          }} data-testid="file-session-ack" />
          I understand that nothing is saved on this device and I must restore my identity again after this session ends.
        </label>}
        <div className="mt-5">
          <RestorePrimaryButton testId="submit-protection" type="submit" disabled={selectedMode === 'devicePassword' ? !canSubmitPassword : !sessionAcknowledged} fullWidth>
            Protect this device and continue
          </RestorePrimaryButton>
        </div>
      </form>
      <div className="mt-3 flex justify-center">
        <RestoreBackButton onBack={onBack} />
      </div>
    </RestorePanel>
  );
}

/** Resume gate (Finish restoring your identity) and staging progress. */
export function ResumeAndStagingScreen({ view, onUnlockResume, onCancelStage, onBack }: ProfileProtectionProps) {
  if (view.screen === 'resumeGate') {
    return (
      <RestorePanel title={COPY.resume.title}>
        <RestoreStatusRegion>{COPY.resume.title}</RestoreStatusRegion>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <RestorePrimaryButton testId="unlock-resume" onClick={onUnlockResume}>
            {COPY.resume.unlock}
          </RestorePrimaryButton>
          <button type="button" onClick={onCancelStage} className="min-h-11 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)]" data-testid="cancel-stage">
            {COPY.resume.cancelStage}
          </button>
          <RestoreBackButton onBack={onBack} />
        </div>
      </RestorePanel>
    );
  }
  return (
    <RestorePanel title={view.copyKey === 'savingEncryptedIdentity' ? COPY.progress.saving : COPY.progress.waiting}>
      <RestoreStatusRegion>{view.copyKey === 'savingEncryptedIdentity' ? COPY.progress.saving : COPY.progress.waiting}</RestoreStatusRegion>
      <div className="mt-4">
        <RestoreBackButton onBack={onBack} />
      </div>
    </RestorePanel>
  );
}

/** Exact success surface — announced once; automatic dashboard transition. */
export function SuccessScreen({ view }: { readonly view: RestoreViewState }) {
  const profile = view.profile;
  return (
    <RestorePanel title={COPY.success.title}>
      <RestoreStatusRegion role="status">{COPY.success.title}</RestoreStatusRegion>
      {profile !== null && <p className="mt-2 text-sm text-[var(--text)]"><SafeAlias alias={profile.alias} /></p>}
      <p className="mt-4 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text-muted)]" data-testid="mnemonic-notice">
        {COPY.success.mnemonicNotice}
      </p>
    </RestorePanel>
  );
}

function protectionLabel(mode: RestoreProtectionChoice): string {
  switch (mode) {
    case 'devicePassword':
      return COPY.protection.devicePasswordLabel;
    case 'webAuthnPasswordless':
    case 'nativePasswordless':
      return COPY.protection.passwordless;
    case 'sessionOnly':
      return COPY.protection.sessionOnly;
  }
}
