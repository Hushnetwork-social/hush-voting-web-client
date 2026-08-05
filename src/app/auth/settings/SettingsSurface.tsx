/**
 * FEAT-010 UI — identity/security settings, recovery/removal, migration, and
 * quarantine surfaces (Task 5.5).
 *
 * Thin components driven by Phase 4 projections: settings status with exact
 * offline availability, fresh-authorization prompts, Lock-policy choices with
 * one-time warnings, protection-change flow, removal-first recovery (exact
 * REMOVE phrase + final confirmation), migration/quarantine remediation, and
 * the closed unknown-error surface with a random support code. No action
 * implies a remote reset; nothing changes identity keys.
 */

import { useState } from 'react';
import type {
  LockPolicyProjection,
  RecoveryProjection,
  UnknownErrorProjection,
  MigrationRemediationProjection,
  SettingsActionProjection,
} from '../../../lib/auth/presentation';

/** Settings landing (safe status view). */
export interface SettingsSurfaceProps {
  readonly actions: SettingsActionProjection;
  readonly onLockPolicy: () => void;
  readonly onDevicePasswordChange: () => void;
  readonly onProtectionModeChange: () => void;
  readonly onRemoveLocalUser: () => void;
}

export function SettingsSurface({ actions, onLockPolicy, onDevicePasswordChange, onProtectionModeChange, onRemoveLocalUser }: SettingsSurfaceProps) {
  return (
    <div className="settings-surface" data-testid="settings-landing">
      <h1>Identity and security</h1>
      <ul className="settings-actions">
        {actions.available.includes('lockPolicy') ? (
          <li>
            <button type="button" className="button-secondary" onClick={onLockPolicy}>
              Lock policy
            </button>
          </li>
        ) : null}
        {actions.available.includes('devicePasswordChange') ? (
          <li>
            <button type="button" className="button-secondary" onClick={onDevicePasswordChange}>
              Change device password
            </button>
          </li>
        ) : null}
        {actions.available.includes('protectionModeChange') ? (
          <li>
            <button type="button" className="button-secondary" onClick={onProtectionModeChange}>
              Change device protection
            </button>
          </li>
        ) : null}
        {actions.available.includes('export') ? (
          <li>
            <button type="button" className="button-secondary">
              Export credential file
            </button>
          </li>
        ) : null}
      </ul>
      {actions.blockedOffline.length > 0 ? (
        <p role="status" aria-live="polite" className="offline-note">
          Offline — password, protection, and export changes need an online check.
        </p>
      ) : null}
      <div className="danger-zone">
        <button type="button" className="link-button danger" onClick={onRemoveLocalUser}>
          Remove local user
        </button>
      </div>
    </div>
  );
}

/** Lock-policy controls with exact choices and one-time warnings. */
export interface LockPolicySurfaceProps {
  readonly projection: LockPolicyProjection;
  readonly onChoose: (idle: string, background: string) => void;
  readonly onBack: () => void;
}

export function LockPolicySurface({ projection, onChoose, onBack }: LockPolicySurfaceProps) {
  const [idle, setIdle] = useState('5');
  const [background, setBackground] = useState('30');
  return (
    <div className="settings-surface">
      <h1>Lock policy</h1>
      <label htmlFor="idle-choice">Lock after idle</label>
      <select id="idle-choice" value={idle} onChange={(event) => setIdle(event.target.value)}>
        {projection.idleChoices.map((choice) => (
          <option key={String(choice)} value={String(choice)}>
            {choice === 'until-restart' ? 'Until restart' : `${choice} minute${choice === 1 ? '' : 's'}`}
          </option>
        ))}
      </select>
      <label htmlFor="background-choice">Lock in background</label>
      <select id="background-choice" value={background} onChange={(event) => setBackground(event.target.value)}>
        {projection.backgroundChoices.map((choice) => (
          <option key={String(choice)} value={String(choice)}>
            {choice === 'immediate' ? 'Immediately' : choice === 'until-restart' ? 'Until restart' : `${choice} seconds`}
          </option>
        ))}
      </select>
      {projection.weakerChoicesWarn.length > 0 ? (
        <p role="alert" className="warning">
          Weaker choices lock sooner or later than the default. Locking sooner is safer.
        </p>
      ) : null}
      <button type="button" className="button-primary" onClick={() => onChoose(idle, background)}>
        Save lock policy
      </button>
      <button type="button" className="link-button" onClick={onBack}>
        Back
      </button>
    </div>
  );
}

/** Removal-first recovery (AC-010-073/074). */
export interface RecoverySurfaceProps {
  readonly projection: RecoveryProjection;
  readonly onEnterPhrase: (phrase: string) => void;
  readonly onConfirmRemoval: () => void;
  readonly onBack: () => void;
}

export function RecoverySurface({ projection, onEnterPhrase, onConfirmRemoval, onBack }: RecoverySurfaceProps) {
  const [phrase, setPhrase] = useState('');
  const phraseExact = phrase === projection.requiresPhrase;
  return (
    <div className="settings-surface">
      <h1>Recover your local identity</h1>
      <p className="consequence">{projection.noRemoteResetCopy}</p>
      <p className="consequence">Recovery removes this local user from this device. Your blockchain identity is not affected.</p>
      <label htmlFor="remove-phrase">Type {projection.requiresPhrase} to continue</label>
      <input
        id="remove-phrase"
        type="text"
        autoComplete="off"
        value={phrase}
        onChange={(event) => {
          setPhrase(event.target.value);
          onEnterPhrase(event.target.value);
        }}
      />
      <button type="button" className="button-danger" disabled={!phraseExact} onClick={onConfirmRemoval}>
        Remove and recover
      </button>
      {projection.restoreChoicesVisible ? (
        <p role="status" aria-live="polite" className="restore-available">
          Cleanup verified — you can now restore recovery words or a credential file.
        </p>
      ) : null}
      <button type="button" className="link-button" onClick={onBack}>
        Back
      </button>
    </div>
  );
}

/** Migration/quarantine remediation surfaces. */
export function MigrationRemediationSurface({ projection }: { readonly projection: MigrationRemediationProjection }) {
  if (projection.kind === 'networkMismatch') {
    return (
      <div role="alert" className="blocking-error">
        <h1>This local identity was configured for a different HushNetwork network.</h1>
        <p>Return to the bound network, or remove this local user before creating a new identity here.</p>
      </div>
    );
  }
  if (projection.kind === 'updateAvailable') {
    return (
      <div role="alert" className="blocking-error">
        <h1>This local identity needs a newer HushVoting version.</h1>
        <p>Update the app to continue. Your local data is intact.</p>
      </div>
    );
  }
  if (projection.kind === 'recoveryOrRemoval') {
    return (
      <div role="alert" className="blocking-error">
        <h1>This local identity could not be read.</h1>
        <p>You can recover with your protection details or remove this local user.</p>
      </div>
    );
  }
  return (
    <div role="status" className="blocking-error">
      <h1>Finishing the local upgrade…</h1>
      <p>Retry the migration to continue.</p>
    </div>
  );
}

/** Closed unknown-error surface with random support code. */
export function UnknownErrorSurface({ projection }: { readonly projection: UnknownErrorProjection }) {
  return (
    <div role="alert" className="blocking-error" data-testid="unknown-error">
      <h1>{projection.genericCopy}</h1>
      <p>
        Support code: <code>{projection.supportCode}</code>
      </p>
    </div>
  );
}

/** Quarantine remediation (cleanup failed; retry only). */
export function QuarantineSurface({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <div role="alert" className="blocking-error">
      <h1>Local cleanup could not finish.</h1>
      <button type="button" className="button-primary" onClick={onRetry}>
        Retry cleanup
      </button>
    </div>
  );
}
