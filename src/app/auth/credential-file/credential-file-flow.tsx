/**
 * FEAT-009 credential-file UI — flow router and navigation/ownership/
 * cleanup surfaces (Tasks 5.7).
 *
 * Renders exactly one surface from the closed `RestoreViewState` produced
 * by the Phase 4 presentation mapping. The router is a thin renderer: it
 * never decides policy, never holds secret state, and dispatches only the
 * actions the view state allows. Non-owner/quarantine states short-circuit
 * before any sensitive surface mounts. Visible URL stays `/`.
 */
import type { RestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import type { RestoreProtectionChoice } from '../../../lib/credential-file-restore/contracts/projection';
import { COPY, RestoreBackButton, RestoreErrorRegion, RestorePanel, RestorePrimaryButton, RestoreStatusRegion } from './surfaces';
import { PickerReadScreen, PasswordScreen } from './picker-password';
import { ProfileReviewScreen, ProtectionScreen, ResumeAndStagingScreen, SuccessScreen } from './profile-protection';

export interface CredentialFileFlowProps {
  readonly view: RestoreViewState;
  readonly sessionOnlyOnly: boolean;
  readonly onChooseFile: () => void;
  readonly onCancelRead: () => void;
  readonly onSubmitPassword: (password: string) => void;
  readonly onToggleVisibility: () => void;
  readonly onToggleEmptyOption: (enabled: boolean) => void;
  readonly onChooseDifferentFile: () => void;
  readonly onChooseProtection: (mode: RestoreProtectionChoice) => void;
  readonly onCreateIdentity: () => void;
  readonly onReveal: () => void;
  readonly onUnlockResume: () => void;
  readonly onCancelStage: () => void;
  readonly onBack: () => void;
  readonly onAcknowledgeSessionOnly: () => void;
  readonly onRetryCleanup: () => void;
}

/** Thin renderer — screen routing only; policy stays in the authority. */
export function CredentialFileFlow(props: CredentialFileFlowProps) {
  const { view } = props;

  switch (view.screen) {
    case 'entry':
    case 'vaultGuard':
      // Three-choice entry is rendered by the FEAT-002 auth shell; guard
      // remediation surfaces come from the auth shell too.
      return null;
    case 'capabilityPreflight':
    case 'picker':
    case 'reading':
      return <PickerReadScreen {...props} />;
    case 'password':
    case 'decrypting':
      return <PasswordScreen view={view} onSubmit={props.onSubmitPassword} onToggleVisibility={props.onToggleVisibility} onToggleEmptyOption={props.onToggleEmptyOption} onChooseDifferentFile={props.onChooseDifferentFile} onBack={props.onBack} />;
    case 'validating':
    case 'lookup':
      return <ProgressScreen view={view} onBack={props.onBack} />;
    case 'profileReview':
      return <ProfileReviewScreen view={view} onChooseProtection={props.onChooseProtection} onCreateIdentity={props.onCreateIdentity} onReveal={props.onReveal} onUnlockResume={props.onUnlockResume} onCancelStage={props.onCancelStage} onBack={props.onBack} />;
    case 'protection':
      return <ProtectionScreen view={view} onChooseProtection={props.onChooseProtection} onCreateIdentity={props.onCreateIdentity} onReveal={props.onReveal} onUnlockResume={props.onUnlockResume} onCancelStage={props.onCancelStage} onBack={props.onBack} />;
    case 'staging':
    case 'activating':
    case 'resumeGate':
      return <ResumeAndStagingScreen view={view} onChooseProtection={props.onChooseProtection} onCreateIdentity={props.onCreateIdentity} onReveal={props.onReveal} onUnlockResume={props.onUnlockResume} onCancelStage={props.onCancelStage} onBack={props.onBack} />;
    case 'success':
      return <SuccessScreen view={view} />;
    case 'quarantined':
      return <QuarantineScreen onRetryCleanup={props.onRetryCleanup} />;
    case 'locked':
      return null; // auth shell renders LockedUser
    case 'terminal':
      return <TerminalScreen onBack={props.onBack} />;
  }
}

/** Validating/lookup progress (accurate copy; never premature success). */
function ProgressScreen({ view, onBack }: { readonly view: RestoreViewState; readonly onBack: () => void }) {
  const copy = view.copyKey === 'validatingIdentityKeys' ? COPY.progress.validating : COPY.progress.checking;
  return (
    <RestorePanel title={copy}>
      <RestoreStatusRegion>{copy}</RestoreStatusRegion>
      {view.failureCode !== null && <RestoreErrorRegion>{COPY.errors.generic}</RestoreErrorRegion>}
      <div className="mt-4">
        <RestoreBackButton onBack={onBack} />
      </div>
    </RestorePanel>
  );
}

/** Non-owner safe blocked state (no sensitive data broadcast). */
export function OwnerBlockedScreen({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <RestorePanel title="Restore in progress">
      <RestoreStatusRegion>{COPY.errors.generic}</RestoreStatusRegion>
      <p className="mt-2 text-sm text-[var(--text-muted)]" data-testid="owner-blocked">
        {COPY.picker.selected}
      </p>
      <div className="mt-4">
        <RestorePrimaryButton testId="owner-retry" onClick={onRetry}>
          Retry
        </RestorePrimaryButton>
      </div>
    </RestorePanel>
  );
}

/** Quarantine gate — blocks Create/Restore until verified cleanup. */
export function QuarantineScreen({ onRetryCleanup }: { readonly onRetryCleanup: () => void }) {
  return (
    <RestorePanel title={COPY.errors.quarantine}>
      <RestoreErrorRegion>{COPY.errors.quarantine}</RestoreErrorRegion>
      <div className="mt-4">
        <RestorePrimaryButton testId="retry-cleanup" onClick={onRetryCleanup}>
          Retry cleanup
        </RestorePrimaryButton>
      </div>
    </RestorePanel>
  );
}

/** Fail-closed terminal screen (unknown/contradictory outcome). */
export function TerminalScreen({ onBack }: { readonly onBack: () => void }) {
  return (
    <RestorePanel title={COPY.errors.generic}>
      <RestoreErrorRegion>{COPY.errors.generic}</RestoreErrorRegion>
      <div className="mt-4">
        <RestoreBackButton onBack={onBack} />
      </div>
    </RestorePanel>
  );
}
