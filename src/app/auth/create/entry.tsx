/**
 * FEAT-007 create-user UI — entry and preflight surfaces (Task 5.1).
 *
 * The no-local-user entry offers exactly three equal primary choices with no
 * password field. Create User immediately runs the platform security/
 * persistence preflight; unsupported or temporarily unavailable capabilities
 * block generation with typed remediation and bounded Retry.
 */

import type { PreflightOutcome } from '../../../lib/identity-creation/authority';
import { ENTRY, PREF_LIGHT } from './copy';
import { ActionButton, StatusRegion, SurfacePanel } from './surfaces';

export interface EntryProps {
  readonly onCreateUser: () => void;
  readonly onRestoreWords: () => void;
  readonly onRestoreFile: () => void;
}

/** Wireframe 0 — exactly three equal primary choices. */
export function EntryScreen({ onCreateUser, onRestoreWords, onRestoreFile }: EntryProps) {
  const rows = [
    { label: ENTRY.createUser, detail: ENTRY.createUserDetail, action: onCreateUser },
    { label: ENTRY.restoreWords, detail: ENTRY.restoreWordsDetail, action: onRestoreWords },
    { label: ENTRY.restoreFile, detail: ENTRY.restoreFileDetail, action: onRestoreFile },
  ];
  return (
    <SurfacePanel title={ENTRY.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{ENTRY.subtitle}</p>
      <div className="flex flex-col gap-3" role="list">
        {rows.map((row) => (
          <div key={row.label} role="listitem">
            <ActionButton variant="secondary" onClick={row.action}>
              <span className="flex flex-col items-start text-left">
                <span className="font-semibold">{row.label}</span>
                <span className="text-xs font-normal text-[var(--text-muted)]">{row.detail}</span>
              </span>
            </ActionButton>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-[var(--text-muted)]">{ENTRY.privacy}</p>
      <p className="mt-1 text-xs text-[var(--text-muted)]">{ENTRY.footnote}</p>
    </SurfacePanel>
  );
}

export interface PreflightProps {
  readonly outcome: PreflightOutcome;
  readonly onRetry: () => void;
  readonly onBack: () => void;
}

/** Wireframe-gated preflight — generation blocked when unsafe. */
export function PreflightScreen({ outcome, onRetry, onBack }: PreflightProps) {
  if (outcome.kind === 'passed') {
    return (
      <SurfacePanel title={PREF_LIGHT.title}>
        <StatusRegion>Ready to create your identity.</StatusRegion>
      </SurfacePanel>
    );
  }
  const title = outcome.kind === 'unsupported' ? PREF_LIGHT.unsupportedTitle : PREF_LIGHT.temporaryTitle;
  const detail = outcome.kind === 'unsupported' ? PREF_LIGHT.unsupportedDetail : PREF_LIGHT.temporaryDetail;
  const retryable = outcome.kind === 'temporaryUnavailable';
  return (
    <SurfacePanel title={title}>
      <p className="text-sm text-[var(--text-muted)]">{detail}</p>
      {retryable ? (
        <div className="mt-4">
          <ActionButton onClick={onRetry} variant="secondary">
            {PREF_LIGHT.retry}
          </ActionButton>
        </div>
      ) : (
        <p className="mt-4 text-xs text-[var(--text-muted)]">
          No alias or secret has been collected. Generation is blocked until the required protection is available.
        </p>
      )}
      <div className="mt-4">
        <ActionButton onClick={onBack} variant="secondary">
          Back
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}
