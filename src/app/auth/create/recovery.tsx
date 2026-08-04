/**
 * FEAT-007 create-user UI — recovery reveal and six-position confirmation
 * (Task 5.3).
 *
 * Recovery words are the ONE bounded page exception: delivered only while the
 * reveal authority is active, never stored in state, concealed on timeout or
 * any conceal trigger (removes visual AND accessibility content). The
 * challenge requests six unpredictable positions with position-only mismatch
 * feedback and three-attempt invalidation.
 */

import { useState } from 'react';
import { CONFIRM, RECOVERY } from './copy';
import { ActionButton, BackButton, FieldError, StatusRegion, SurfacePanel } from './surfaces';

export interface RecoveryProps {
  /** Null while concealed; present only inside the bounded reveal exception. */
  readonly words: readonly string[] | null;
  readonly onCopy: () => void;
  readonly onRegenerateRequest: () => void;
  readonly onContinue: () => void;
  readonly onBack: () => void;
  readonly acknowledged: boolean;
  readonly onAcknowledge: (value: boolean) => void;
  readonly timeoutMessage: string | null;
}

/** Wireframe 3 — Save recovery words (semantic ordered list, responsive). */
export function RecoveryScreen({ words, onCopy, onRegenerateRequest, onContinue, onBack, acknowledged, onAcknowledge, timeoutMessage }: RecoveryProps) {
  const visible = words !== null;
  return (
    <SurfacePanel title={RECOVERY.title}>
      <p className="mb-3 text-sm text-[var(--text-muted)]">{RECOVERY.detail}</p>
      {visible ? (
        <>
          <ol className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-4" data-testid="recovery-list">
            {words.map((word, i) => (
              <li key={i} className="flex gap-2 rounded-lg bg-[var(--surface-strong)] px-3 py-1.5 text-sm text-[var(--text)]">
                <span className="font-mono text-xs text-[var(--text-muted)]">{String(i + 1).padStart(2, '0')}</span>
                <span>{word}</span>
              </li>
            ))}
          </ol>
          <div className="mt-3 flex flex-wrap gap-3">
            <ActionButton variant="secondary" onClick={onCopy}>
              {RECOVERY.copy}
            </ActionButton>
            <ActionButton variant="danger" onClick={onRegenerateRequest}>
              {RECOVERY.regenerate}
            </ActionButton>
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">{RECOVERY.copyWarning}</p>
          <label className="mt-3 flex items-start gap-2 text-sm text-[var(--text)]">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => onAcknowledge(e.target.checked)}
              className="mt-1 h-5 w-5 accent-[var(--accent)]"
            />
            <span>{RECOVERY.understood}</span>
          </label>
        </>
      ) : (
        <StatusRegion>{timeoutMessage ?? RECOVERY.concealed}</StatusRegion>
      )}
      <div className="mt-4 flex items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton onClick={onContinue} disabled={!visible || !acknowledged}>
          Continue
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface ConfirmRecoveryProps {
  /** Positions (1-based) requested, in randomized display order. */
  readonly positions: readonly number[];
  readonly onVerify: (answers: ReadonlyMap<number, string>) => void;
  readonly onReviewAll: () => void;
  readonly onBack: () => void;
  readonly mismatchPosition: number | null;
  readonly attemptsRemaining: number;
  readonly challengeClosed: boolean;
}

/** Wireframe 4 — six-position confirmation (no autofill/autocorrect). */
export function ConfirmRecoveryScreen({ positions, onVerify, onReviewAll, onBack, mismatchPosition, attemptsRemaining, challengeClosed }: ConfirmRecoveryProps) {
  const [answers, setAnswers] = useState<Record<number, string>>({});

  if (challengeClosed) {
    return (
      <SurfacePanel title={CONFIRM.title}>
        <p className="text-sm text-[var(--warning)]">{CONFIRM.challengeClosed}</p>
        <div className="mt-4 flex items-center gap-3">
          <BackButton onClick={onBack} />
          <ActionButton onClick={onReviewAll} variant="secondary">
            {CONFIRM.reviewAll}
          </ActionButton>
        </div>
      </SurfacePanel>
    );
  }

  const verify = () => {
    const map = new Map<number, string>(positions.map((p) => [p, (answers[p] ?? '').trim().toLowerCase()]));
    onVerify(map);
  };

  return (
    <SurfacePanel title={CONFIRM.title}>
      <p className="mb-3 text-sm text-[var(--text-muted)]">{CONFIRM.detail}</p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {positions.map((pos) => (
          <div key={pos}>
            <label htmlFor={`recovery-word-${pos}`} className="mb-1 block text-sm font-medium text-[var(--text)]">
              Word {pos}
            </label>
            <input
              id={`recovery-word-${pos}`}
              value={answers[pos] ?? ''}
              onChange={(e) => setAnswers({ ...answers, [pos]: e.target.value })}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              aria-describedby={mismatchPosition === pos ? 'recovery-mismatch' : undefined}
              className="min-h-11 w-full rounded-xl border border-transparent bg-[var(--surface-strong)] px-3 text-sm text-[var(--text)] focus:border-[var(--accent)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
            />
          </div>
        ))}
      </div>
      {mismatchPosition !== null ? (
        <FieldError id="recovery-mismatch">{CONFIRM.mismatch(mismatchPosition)}</FieldError>
      ) : null}
      <StatusRegion>{CONFIRM.attempts(attemptsRemaining)}</StatusRegion>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton variant="secondary" onClick={onReviewAll}>
          {CONFIRM.reviewAll}
        </ActionButton>
        <ActionButton onClick={verify} disabled={positions.some((p) => (answers[p] ?? '').trim().length === 0)}>
          {CONFIRM.verify}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}
