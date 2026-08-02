/**
 * FEAT-002 first-run entry surface — exactly three equal actions.
 *
 * Create User, Restore Credential File, and Restore Recovery Words appear
 * together with equal visual weight; no path is preselected, hidden,
 * demoted, or platform-varied. Back from a child flow returns to this
 * unchanged entry screen after secret cleanup.
 *
 * Normative source: FeatureDescription "First-run entry".
 */

interface FirstRunProps {
  readonly onCreateUser: () => void;
  readonly onRestoreCredentialFile: () => void;
  readonly onRestoreRecoveryWords: () => void;
}

export function FirstRun({ onCreateUser, onRestoreCredentialFile, onRestoreRecoveryWords }: FirstRunProps) {
  return (
    <div className="first-run" data-testid="first-run">
      <p className="auth-lead">Choose how to set up this device.</p>
      <div className="entry-actions">
        <button type="button" className="entry-action" onClick={onCreateUser}>
          <span className="entry-action-title">Create User</span>
          <span className="entry-action-detail">Create a new HushNetwork identity</span>
        </button>
        <button type="button" className="entry-action" onClick={onRestoreCredentialFile}>
          <span className="entry-action-title">Restore Credential File</span>
          <span className="entry-action-detail">Import an encrypted HUSH credential file</span>
        </button>
        <button type="button" className="entry-action" onClick={onRestoreRecoveryWords}>
          <span className="entry-action-title">Restore Recovery Words</span>
          <span className="entry-action-detail">Restore from your recovery phrase</span>
        </button>
      </div>
    </div>
  );
}
