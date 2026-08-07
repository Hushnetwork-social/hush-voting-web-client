/**
 * FEAT-007 create-user UI — profile and generation surfaces (Task 5.1).
 *
 * Alias/visibility form with no password field; Private is default; Public
 * requires explicit acknowledgement. Generation starts only after explicit
 * user action with accessible progress after 150 ms and no secret exposure.
 */

import { useState } from 'react';
import { validateAlias } from '../../../lib/identity-creation/profile';
import { CONFIRM, GENERATE, PROFILE } from './copy';
import { ActionButton, BackButton, FieldError, StatusRegion, SurfacePanel } from './surfaces';

export interface ProfileProps {
  readonly onContinue: (alias: string, visibility: 'private' | 'public') => void;
  readonly onBack: () => void;
}

/** Wireframe 1 — Profile (no password, Private default). */
export function ProfileScreen({ onContinue, onBack }: ProfileProps) {
  const [alias, setAlias] = useState('');
  const [visibility, setVisibility] = useState<'private' | 'public'>('private');
  const [publicAck, setPublicAck] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = () => {
    if (alias.trim().length === 0) {
      setError(PROFILE.aliasRequired);
      return;
    }
    const validation = validateAlias(alias);
    if (!validation.ok) {
      setError(validation.code === 'TOO_MANY_GRAPHEMES' || validation.code === 'TOO_MANY_BYTES' ? PROFILE.aliasTooLong : PROFILE.aliasInvalid);
      return;
    }
    if (visibility === 'public' && !publicAck) {
      setError(PROFILE.publicAckRequired);
      return;
    }
    setError(null);
    onContinue(validation.normalizedNfc, visibility);
  };

  return (
    <SurfacePanel title={PROFILE.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{PROFILE.detail}</p>
      <label htmlFor="create-alias" className="mb-1 block text-sm font-medium text-[var(--text)]">
        {PROFILE.aliasLabel}
      </label>
      <input
        id="create-alias"
        value={alias}
        onChange={(e) => setAlias(e.target.value)}
        autoComplete="off"
        spellCheck={false}
        aria-describedby={error ? 'create-alias-error' : undefined}
        className="min-h-11 w-full rounded-[0.85rem] border border-transparent bg-[var(--surface)] px-3 text-sm text-[var(--text)] focus:border-[var(--accent)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
      />
      {error ? <FieldError id="create-alias-error">{error}</FieldError> : null}
      <fieldset className="mt-4">
        <legend className="mb-2 text-sm font-medium text-[var(--text)]">{PROFILE.visibilityLabel}</legend>
        <label className="mb-2 flex items-start gap-2 text-sm text-[var(--text)]">
          <input
            type="radio"
            name="create-visibility"
            checked={visibility === 'private'}
            onChange={() => {
              setVisibility('private');
              setError(null);
            }}
            className="mt-1 h-5 w-5 accent-[var(--accent)]"
          />
          <span>{PROFILE.private}</span>
        </label>
        <label className="flex items-start gap-2 text-sm text-[var(--text)]">
          <input
            type="radio"
            name="create-visibility"
            checked={visibility === 'public'}
            onChange={() => setVisibility('public')}
            className="mt-1 h-5 w-5 accent-[var(--accent)]"
          />
          <span>{PROFILE.public}</span>
        </label>
      </fieldset>
      {visibility === 'public' ? (
        <div className="mt-3 rounded-[0.85rem] bg-[var(--warning-surface)] px-4 py-3" role="region" aria-label={PROFILE.publicWarningTitle}>
          <p className="text-sm font-semibold text-[var(--warning)]">{PROFILE.publicWarningTitle}</p>
          <p className="mt-1 text-sm text-[var(--text-muted)]">{PROFILE.publicWarningDetail}</p>
          <label className="mt-2 flex items-start gap-2 text-sm text-[var(--text)]">
            <input
              type="checkbox"
              checked={publicAck}
              onChange={(e) => setPublicAck(e.target.checked)}
              className="mt-1 h-5 w-5 accent-[var(--accent)]"
            />
            <span>{PROFILE.publicAcknowledge}</span>
          </label>
        </div>
      ) : null}
      <div className="mt-4 flex items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton onClick={submit} fullWidth>{PROFILE.continue}</ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface GenerateProps {
  readonly onGenerate: () => void;
  readonly onBack: () => void;
  readonly progressVisible: boolean;
  readonly progressComplete: boolean;
}

/** Wireframe 2 — Generate recovery words (explicit action, no password). */
export function GenerateScreen({ onGenerate, onBack, progressVisible, progressComplete }: GenerateProps) {
  return (
    <SurfacePanel title={GENERATE.title}>
      <p className="text-sm text-[var(--text-muted)]">{GENERATE.detail}</p>
      <p className="mt-2 text-sm font-medium text-[var(--text)]">{GENERATE.noPassword}</p>
      <p className="mt-1 text-sm text-[var(--warning)]">{GENERATE.warning}</p>
      {progressVisible ? (
        <StatusRegion>{progressComplete ? CONFIRM.challengeClosed : GENERATE.progress}</StatusRegion>
      ) : null}
      <div className="mt-4 flex items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton onClick={onGenerate} disabled={progressVisible && !progressComplete} busy={progressVisible && !progressComplete}>
          {GENERATE.action}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}
