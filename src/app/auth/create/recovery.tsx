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

import type { RecoveryWordDisplay } from '../../../lib/auth/web/recovery-word-display';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useClipboardController } from '../../../lib/browser-vault/ui/hooks';
import { CONFIRM, RECOVERY } from './copy';
import { ActionButton, BackButton, FieldError, StatusRegion, SurfacePanel } from './surfaces';

export interface RecoveryProps {
  /** Null while concealed; present only inside the bounded reveal exception. */
  readonly display: RecoveryWordDisplay;
  readonly visible: boolean;
  readonly onCopy: () => void;
  readonly onRegenerateRequest: (confirmed?: true) => void;
  readonly onReveal?: () => void;
  readonly onContinue: () => void;
  readonly onBack: () => void;
  readonly acknowledged: boolean;
  readonly onAcknowledge: (value: boolean) => void;
  readonly timeoutMessage: string | null;
}

/** Wireframe 3 — Save recovery words (semantic ordered list, responsive). */
export function RecoveryScreen({ display, visible, onCopy, onRegenerateRequest, onReveal, onContinue, onBack, acknowledged, onAcknowledge, timeoutMessage }: RecoveryProps) {
  const listRef = useRef<HTMLOListElement>(null);
  const [copyOutcome, setCopyOutcome] = useState<'idle' | 'copied' | 'unavailable' | 'cleanupDenied'>('idle');
  const [regenerationRequested, setRegenerationRequested] = useState(false);
  const { cleanupAfter } = useClipboardController(typeof navigator === 'undefined' ? null : navigator.clipboard ?? null);
  const copied = useRef(false);
  const mounted = useRef(false);
  const copyEpoch = useRef(0);
  const cleanupTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    mounted.current = true;
    const cleanup = () => {
      copyEpoch.current++;
      if (cleanupTimer.current !== null) clearTimeout(cleanupTimer.current);
      cleanupTimer.current = null;
      if (!copied.current) return;
      copied.current = false;
      // Lifecycle cleanup is attempted immediately, even if the browser may
      // deny a write after losing focus. Never inspect the current clipboard.
      void cleanupAfter(0, false);
    };
    const onVisibility = () => { if (document.visibilityState !== 'visible') cleanup(); };
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', cleanup);
    if (!visible || regenerationRequested) cleanup();
    return () => {
      mounted.current = false;
      cleanup();
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', cleanup);
    };
  }, [cleanupAfter, visible, regenerationRequested]);

  useLayoutEffect(() => {
    if (visible && !regenerationRequested && listRef.current) return display.attach(listRef.current);
  }, [display, visible, regenerationRequested]);

  const copyWords = async () => {
    if (!visible) return;
    const epoch = copyEpoch.current;
    try {
      if (!await display.copy()) { setCopyOutcome('unavailable'); return; }
      if (!mounted.current || epoch !== copyEpoch.current || document.visibilityState !== 'visible') { void cleanupAfter(0, false); return; }
      copied.current = true;
      if (cleanupTimer.current !== null) clearTimeout(cleanupTimer.current);
      cleanupTimer.current = setTimeout(() => {
        cleanupTimer.current = null;
        copied.current = false;
        void cleanupAfter(0).then(result => {
          if (result === 'denied' && mounted.current) setCopyOutcome('cleanupDenied');
        });
      }, 30_000);
      onCopy();
      setCopyOutcome('copied');
    } catch {
      setCopyOutcome('unavailable');
    }
  };

  if (regenerationRequested) {
    return (
      <div role="alertdialog" aria-label={RECOVERY.regenerateConfirmTitle}>
        <SurfacePanel title={RECOVERY.regenerateConfirmTitle}>
          <p className="text-sm text-[var(--text-muted)]">{RECOVERY.regenerateConfirmDetail}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <ActionButton variant="secondary" onClick={() => setRegenerationRequested(false)}>Keep current words</ActionButton>
            <ActionButton variant="danger" onClick={() => {
              setRegenerationRequested(false);
              onRegenerateRequest(true);
            }}>{RECOVERY.regenerateConfirmAction}</ActionButton>
          </div>
        </SurfacePanel>
      </div>
    );
  }

  return (
    <SurfacePanel title={RECOVERY.title}>
      <p className="mb-3 text-sm text-[var(--text-muted)]">{RECOVERY.detail}</p>
      {visible ? (
        <>
          <ol ref={listRef} className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-4" data-testid="recovery-list" />
          <div className="mt-3 flex flex-wrap gap-3">
            <ActionButton variant="secondary" onClick={() => void copyWords()}>
              {copyOutcome === 'copied' ? 'Copied' : RECOVERY.copy}
            </ActionButton>
            <ActionButton variant="danger" onClick={() => setRegenerationRequested(true)}>
              {RECOVERY.regenerate}
            </ActionButton>
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">{RECOVERY.copyWarning}</p>
          <div className={copyOutcome === 'unavailable' || copyOutcome === 'cleanupDenied' ? 'mt-2 text-xs text-[var(--warning)]' : 'sr-only'} role="status" aria-live="polite">
            {copyOutcome === 'copied' ? 'Recovery words copied.' : copyOutcome === 'unavailable' ? 'Clipboard copy is unavailable. Save the visible words manually.' : copyOutcome === 'cleanupDenied' ? 'The browser refused clipboard cleanup. Clear your clipboard manually.' : ''}
          </div>
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
        <>
          <StatusRegion>{timeoutMessage ?? RECOVERY.concealed}</StatusRegion>
          {onReveal ? <ActionButton variant="secondary" onClick={onReveal}>{RECOVERY.reveal}</ActionButton> : null}
        </>
      )}
      <div className="mt-4 flex items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton onClick={onContinue} disabled={!visible || !acknowledged} fullWidth>
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
    // Clear the transient answers immediately (bounded exception hygiene).
    setAnswers({});
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
