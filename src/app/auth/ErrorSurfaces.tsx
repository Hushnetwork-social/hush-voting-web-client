/**
 * FEAT-002 error, recovery-navigation, and temporary-mode surfaces.
 *
 * - recoverable/blocked errors map to privacy-safe copy and typed actions;
 * - unknown failures show generic text + a random per-occurrence support code;
 * - recovery navigation offers restore-words / restore-file reprovisioning,
 *   never remote password reset or sign-out;
 * - temporary memory-only mode explains consequences before entry and is
 *   never offered without safe coordination.
 *
 * Normative source: FeatureDescription "Errors", "Recovery, Removal,
 * Temporary Mode, and Error Surfaces" task spec.
 */

import type { AuthRenderProjection } from '../../lib/auth/react/adapter.js';
import { errorCopyForOutcome } from '../../lib/auth/ui/copy.js';

interface ErrorSurfaceProps {
  readonly projection: AuthRenderProjection;
  readonly onRetry: () => void;
  readonly onLock: () => void;
  readonly onRemoveLocalUser: () => void;
}

export function ErrorSurface({ projection, onRetry, onLock, onRemoveLocalUser }: ErrorSurfaceProps) {
  const { outcomeCode } = projection;
  const copy = errorCopyForOutcome(outcomeCode);
  const blocked = projection.authState === 'blockedError';
  // Removal is only meaningful when a provisioned local user exists (e.g., a
  // storage-unavailable initialization error has no user to remove).
  const canRemove = projection.safeIdentity !== null;

  return (
    <div className="error-surface" role="alert">
      <h2 className="error-title">{copy.title}</h2>
      <p className="error-detail">{copy.detail}</p>

      {projection.supportCode !== null && (
        <p className="support-code" role="status">
          Support code: {projection.supportCode}
        </p>
      )}

      <div className="error-actions">
        <button type="button" className="button-primary" onClick={onRetry}>
          {blocked ? 'Retry' : 'Try again'}
        </button>
        {canRemove && (
          <button type="button" className="link-button" onClick={onLock}>
            Lock
          </button>
        )}
        {canRemove && (
          <button type="button" className="button-danger-ghost" onClick={onRemoveLocalUser}>
            Remove local user
          </button>
        )}
      </div>
    </div>
  );
}

interface RecoveryNavigationProps {
  readonly onRestoreCredentialFile: () => void;
  readonly onRestoreRecoveryWords: () => void;
  readonly onBackToUnlock: () => void;
}

export function RecoveryNavigation({
  onRestoreCredentialFile,
  onRestoreRecoveryWords,
  onBackToUnlock,
}: RecoveryNavigationProps) {
  return (
    <div className="recovery-navigation">
      <p className="auth-lead">Restore access by reprovisioning this device:</p>
      <div className="recovery-actions">
        <button type="button" className="entry-action" onClick={onRestoreRecoveryWords}>
          <span className="entry-action-title">Restore Recovery Words</span>
          <span className="entry-action-detail">Use your recovery phrase</span>
        </button>
        <button type="button" className="entry-action" onClick={onRestoreCredentialFile}>
          <span className="entry-action-title">Restore Credential File</span>
          <span className="entry-action-detail">Import an encrypted HUSH file</span>
        </button>
      </div>
      <p className="recovery-note">There is no remote password reset or remote sign-out.</p>
      <button type="button" className="link-button" onClick={onBackToUnlock}>
        Back to unlock
      </button>
    </div>
  );
}

interface TemporaryModeProps {
  readonly onEnterTemporaryMode: () => void;
  readonly onCancel: () => void;
}

export function TemporaryMode({ onEnterTemporaryMode, onCancel }: TemporaryModeProps) {
  return (
    <div className="temporary-mode">
      <h2 className="error-title">Temporary mode</h2>
      <p className="error-detail">
        This browser cannot save a local user. In temporary mode, nothing is saved on this device:
      </p>
      <ul className="temp-consequences">
        <li>No local user or device password will be saved.</li>
        <li>Locking, reloading, closing the final tab, or losing the process requires creation or recovery again.</li>
        <li>Recovery-word confirmation remains required for new identity creation.</li>
      </ul>
      <div className="error-actions">
        <button type="button" className="button-primary" onClick={onEnterTemporaryMode}>
          Continue in temporary mode
        </button>
        <button type="button" className="link-button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
