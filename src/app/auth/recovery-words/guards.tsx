/**
 * FEAT-008 recovery-words UI — entry guards, root-only navigation, ownership,
 * and cleanup surfaces (Task 5.7).
 *
 * Presents lock versus destructive logout/reset, forgot-device-password
 * warning, verified cleanup/quarantine, owner-in-another-tab state, Back
 * behavior, screenshot/recents guidance, and the responsive platform shell.
 * No recovery form is mounted while another owner holds the epoch.
 */
import { RecoveryActionButton, RecoveryBackButton, RecoveryFieldError, RecoveryPanel, RecoveryStatusRegion } from './surfaces';
import { GUARDS } from './copy';

export interface GuardProps {
  readonly alreadyInProgress: boolean;
  readonly quarantined: boolean;
  readonly onRetry: () => void;
  readonly onBack: () => void;
}

export function OwnerBlockedScreen({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <RecoveryPanel title={GUARDS.alreadyInProgress}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{GUARDS.alreadyInProgressDetail}</p>
      <RecoveryActionButton variant="secondary" onClick={onRetry}>
        Retry
      </RecoveryActionButton>
    </RecoveryPanel>
  );
}

export function QuarantineScreen({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <RecoveryPanel title="Recovery blocked">
      <RecoveryFieldError id="rw-quarantine">{GUARDS.quarantine}</RecoveryFieldError>
      <div className="mt-4">
        <RecoveryActionButton variant="secondary" onClick={onRetry}>
          {GUARDS.quarantineRetry}
        </RecoveryActionButton>
      </div>
    </RecoveryPanel>
  );
}

export interface LocalUserGuardProps {
  readonly onLock: () => void;
  readonly onRemoveLocalUser: () => void;
  readonly onForgotPassword: () => void;
  readonly removalPending: boolean;
}

/** Valid local identity exists: Lock retains; destructive removal is distinct. */
export function LocalUserGuard({ onLock, onRemoveLocalUser, onForgotPassword, removalPending }: LocalUserGuardProps) {
  return (
    <RecoveryPanel title="A local identity exists">
      <p className="mb-4 text-sm text-[var(--text-muted)]">Locking keeps your identity on this device. Removing the local user exposes Create and Restore.</p>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <RecoveryActionButton variant="primary" onClick={onLock}>
          Lock
        </RecoveryActionButton>
        <RecoveryActionButton variant="danger" onClick={onRemoveLocalUser} busy={removalPending}>
          {GUARDS.removeLocalUser}
        </RecoveryActionButton>
      </div>
      <div className="mt-4 rounded-xl bg-[var(--surface-strong)] p-3">
        <button type="button" onClick={onForgotPassword} className="text-sm font-medium text-[var(--accent)] hover:underline">
          {GUARDS.forgotPassword}
        </button>
        <p className="mt-1 text-xs text-[var(--text-muted)]">{GUARDS.forgotDetail}</p>
      </div>
      <RecoveryStatusRegion>{GUARDS.screenshotNote}</RecoveryStatusRegion>
    </RecoveryPanel>
  );
}

export interface RemovalConfirmProps {
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
  readonly onBack: () => void;
}

/** Destructive verified local cleanup with explicit warning. */
export function RemovalConfirmation({ onConfirm, onCancel, onBack }: RemovalConfirmProps) {
  return (
    <RecoveryPanel title="Remove local user?">
      <p className="mb-4 text-sm text-[var(--text-muted)]">
        This removes the local identity from this device. Your blockchain identity is not deleted. You will need your external recovery words or a backup
        file to regain access.
      </p>
      <div className="flex flex-wrap gap-3">
        <RecoveryActionButton variant="danger" onClick={onConfirm}>
          Remove local user
        </RecoveryActionButton>
        <RecoveryActionButton variant="secondary" onClick={onCancel}>
          Cancel
        </RecoveryActionButton>
      </div>
      <div className="mt-4">
        <RecoveryBackButton onClick={onBack} />
      </div>
    </RecoveryPanel>
  );
}
