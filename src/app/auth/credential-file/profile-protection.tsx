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
import type { RestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import type { RestoreProtectionChoice } from '../../../lib/credential-file-restore/contracts/projection';
import { COPY, RestoreBackButton, RestoreErrorRegion, RestorePanel, RestorePrimaryButton, RestoreStatusRegion } from './surfaces';

export interface ProfileProtectionProps {
  readonly view: RestoreViewState;
  readonly onChooseProtection: (mode: RestoreProtectionChoice) => void;
  readonly onCreateIdentity: () => void;
  readonly onReveal: () => void;
  readonly onUnlockResume: () => void;
  readonly onCancelStage: () => void;
  readonly onBack: () => void;
}

/** Missing-profile review (explicit Create only; abbreviated addresses). */
export function ProfileReviewScreen({ view, onCreateIdentity, onReveal, onBack }: ProfileProtectionProps) {
  const profile = view.profile;
  return (
    <RestorePanel title={COPY.profile.missing}>
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
        <RestorePrimaryButton testId="create-identity" onClick={onCreateIdentity}>
          {COPY.profile.create}
        </RestorePrimaryButton>
        <button type="button" onClick={onReveal} className="min-h-11 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)]" data-testid="reveal-addresses">
          {COPY.profile.reveal}
        </button>
        <RestoreBackButton onBack={onBack} />
      </div>
      {view.failureCode !== null && <RestoreErrorRegion>{errorCopyForProfile(view.failureCode)}</RestoreErrorRegion>}
    </RestorePanel>
  );
}

/** Separate protection choice — Device password default; no co-mounted backup state. */
export function ProtectionScreen({ view, onChooseProtection, onBack }: ProfileProtectionProps) {
  const choices = view.protectionChoices ?? [];
  return (
    <RestorePanel title={COPY.protection.title}>
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-1 text-sm font-medium text-[var(--text)]">{COPY.protection.createVaultPassword}</legend>
        {choices.map((mode) => (
          <label key={mode} className="flex min-h-11 items-center gap-3 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text)]">
            <input
              type="radio"
              name="restore-protection"
              defaultChecked={mode === 'devicePassword'}
              onChange={() => onChooseProtection(mode)}
              data-testid={`protection-${mode}`}
            />
            <span>{protectionLabel(mode)}</span>
            {mode === 'sessionOnly' && <span className="ml-auto text-xs text-[var(--text-muted)]">{COPY.protection.sessionOnlyWarning}</span>}
          </label>
        ))}
      </fieldset>
      <div className="mt-4">
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
      {profile !== null && <p className="mt-2 text-sm text-[var(--text)]">{profile.alias}</p>}
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

function errorCopyForProfile(code: string): string {
  if (code === 'SERVER_PROOF_REJECTED') {
    return COPY.errors.serverProof;
  }
  return COPY.errors.generic;
}
