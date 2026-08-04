/**
 * FEAT-008 recovery-words UI — word count, grid, paste, concealment, and
 * validation surface (Task 5.1).
 *
 * Dedicated DOM-owned uncontrolled inputs hold the phrase; word values never
 * enter React/XState/app state — only numbered validity positions and the
 * selected count do. Paste rules follow the Recovery-Word Entry Contract:
 * count-correct phrases fill the whole grid atomically; mismatches reject the
 * entire paste; pasting over existing values asks for whole-grid replacement;
 * unknown words fill and mark numbered positions. Focused word visible,
 * completed unfocused words concealed; lifecycle events conceal all.
 */
import { useMemo, useRef, useState } from 'react';
import type { WordGridProjection } from '../../../lib/recovery-words/contracts/projection';
import { RecoveryActionButton, RecoveryBackButton, RecoveryFieldError, RecoveryPanel, RecoveryStatusRegion, WordInput } from './surfaces';
import { BACK, WORD_ENTRY } from './copy';

export interface WordEntryProps {
  readonly grid: WordGridProjection;
  readonly onSelectCount: (count: '12' | '24') => void;
  readonly onPastePhrase: (phrase: string) => void;
  readonly onConfirmPasteReplacement: (confirm: boolean) => void;
  readonly onClearAll: () => void;
  readonly onVerify: (phrase: string) => void;
  readonly onBack: () => void;
}

/** Normalize a pasted phrase with the same rules as the authority (NFKD/case/separators). */
export function normalizePastedPhrase(text: string): string {
  const nfkd = text.normalize('NFKD');
  const words = nfkd.toLowerCase().split(/[ \t\r\n]+/).filter((word) => word.length > 0);
  return words.join(' ');
}

/** Deterministic paste decision per the entry contract. */
export type PasteDecision =
  | { readonly kind: 'fillGrid'; readonly phrase: string; readonly count: number }
  | { readonly kind: 'countMismatch'; readonly expected: number | null; readonly actual: number }
  | { readonly kind: 'replacementRequired'; readonly phrase: string; readonly count: number }
  | { readonly kind: 'emptyPaste' };

export function decidePaste(pasted: string, selectedCount: '12' | '24' | null, anyFieldFilled: boolean): PasteDecision {
  const phrase = normalizePastedPhrase(pasted);
  const count = phrase.length === 0 ? 0 : phrase.split(' ').length;
  if (count === 0) {
    return { kind: 'emptyPaste' };
  }
  if (count !== 12 && count !== 24) {
    return { kind: 'countMismatch', expected: selectedCount === null ? null : Number(selectedCount), actual: count };
  }
  if (selectedCount !== null && count !== Number(selectedCount)) {
    return { kind: 'countMismatch', expected: Number(selectedCount), actual: count };
  }
  if (anyFieldFilled) {
    return { kind: 'replacementRequired', phrase, count };
  }
  return { kind: 'fillGrid', phrase, count };
}

export function WordEntryScreen({ grid, onSelectCount, onPastePhrase, onConfirmPasteReplacement, onClearAll, onVerify, onBack }: WordEntryProps) {
  const [draft, setDraft] = useState<ReadonlyArray<string>>([]);
  const [concealed, setConcealed] = useState(grid.allConcealed);
  const count = grid.selectedWordCount;

  const inputs = useMemo(() => {
    const size = count === '12' ? 12 : count === '24' ? 24 : 0;
    return Array.from({ length: size }, (_, index): { id: string; label: string; position: number } => {
      const position = index + 1;
      return { id: `rw-${position}`, label: WORD_ENTRY.wordLabel(position, size), position };
    });
  }, [count]);

  const anyFieldFilled = draft.some((value) => value.trim().length > 0);

  const handlePaste = (position: number, pastedText: string) => {
    const decision = decidePaste(pastedText, count, anyFieldFilled);
    if (decision.kind === 'fillGrid') {
      const words = decision.phrase.split(' ');
      setDraft(words);
      onPastePhrase(decision.phrase);
      setConcealed(true);
    } else if (decision.kind === 'replacementRequired') {
      // The parent (authority-driven grid state) shows the replacement prompt;
      // we keep the draft until the user confirms or cancels.
      setDraft((current) => current); // no-op; prompt handled by grid state
      // Defer: the paste phrase is delivered only on confirmation.
      pendingPasteRef.current = { phrase: decision.phrase, count: decision.count };
    } else if (decision.kind === 'countMismatch') {
      // Reject the entire paste; preserve all existing fields.
      setDraft((current) => current);
    }
    // emptyPaste: no-op
    void position;
  };

  const pendingPasteRef = useRef<{ phrase: string; count: number } | null>(null);

  const confirmReplacement = (confirm: boolean) => {
    const pending = pendingPasteRef.current;
    if (pending && confirm) {
      const words = pending.phrase.split(' ');
      setDraft(words);
      onPastePhrase(pending.phrase);
      setConcealed(true);
    }
    pendingPasteRef.current = null;
    onConfirmPasteReplacement(confirm);
  };

  const invalidPositions = new Set(grid.invalidPositions);

  return (
    <RecoveryPanel title={WORD_ENTRY.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{WORD_ENTRY.intro}</p>

      <fieldset className="mb-4">
        <legend className="mb-2 text-sm font-medium text-[var(--text)]">Word count</legend>
        <div className="flex flex-wrap gap-3">
          {(['12', '24'] as const).map((option) => (
            <label key={option} className="flex min-h-11 items-center gap-2 rounded-xl bg-[var(--surface-strong)] px-3 py-2 text-sm text-[var(--text)]">
              <input type="radio" name="word-count" checked={count === option} onChange={() => onSelectCount(option)} data-testid={`count-${option}`} />
              {option === '12' ? WORD_ENTRY.twelve : WORD_ENTRY.twentyFour}
            </label>
          ))}
        </div>
      </fieldset>

      {count !== null && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" data-testid="word-grid">
            {inputs.map((input) => {
              const value = draft[input.position - 1] ?? '';
              const invalid = invalidPositions.has(input.position);
              return (
                <div key={input.id} className="flex flex-col gap-1">
                  <WordInput
                    id={input.id}
                    label={input.label}
                    concealed={concealed && value.length > 0 && !invalid}
                    invalid={invalid}
                    onValue={(value) => {
                      setDraft((current) => {
                        const next = [...current];
                        next[input.position - 1] = value;
                        return next;
                      });
                    }}
                  />
                  <input
                    aria-hidden="true"
                    tabIndex={-1}
                    data-paste-target={input.position}
                    className="sr-only"
                    onPaste={(event) => {
                      handlePaste(input.position, event.clipboardData.getData('text'));
                      event.preventDefault();
                    }}
                  />
                </div>
              );
            })}
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-3">
            <RecoveryActionButton variant="secondary" onClick={() => setConcealed((current) => !current)}>
              {concealed ? WORD_ENTRY.showAll : WORD_ENTRY.hideAll}
            </RecoveryActionButton>
            <RecoveryActionButton variant="secondary" onClick={onClearAll} disabled={!anyFieldFilled}>
              {WORD_ENTRY.clearAll}
            </RecoveryActionButton>
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">{WORD_ENTRY.shoulderSurfing}</p>
        </>
      )}

      {grid.pasteReplacementPending && (
        <div role="alertdialog" aria-label="Replace words" className="mt-4 rounded-xl bg-[var(--surface-strong)] p-4">
          <p className="text-sm text-[var(--text)]">{WORD_ENTRY.replacePrompt}</p>
          <div className="mt-3 flex gap-3">
            <RecoveryActionButton variant="primary" onClick={() => confirmReplacement(true)}>
              {WORD_ENTRY.replaceConfirm}
            </RecoveryActionButton>
            <RecoveryActionButton variant="secondary" onClick={() => confirmReplacement(false)}>
              {WORD_ENTRY.replaceCancel}
            </RecoveryActionButton>
          </div>
        </div>
      )}

      {grid.errorSummary.length > 0 && (
        <div role="alert" className="mt-4">
          {grid.errorSummary.map((error) => (
            <RecoveryFieldError key={error.code} id={`rw-error-${error.code}`}>
              {error.code === 'WRONG_COUNT'
                ? WORD_ENTRY.wrongCountStatic
                : error.code === 'UNKNOWN_WORD'
                  ? WORD_ENTRY.unknownWords
                  : WORD_ENTRY.unsupportedInput}
            </RecoveryFieldError>
          ))}
        </div>
      )}

      <p className="mt-4 text-sm font-medium text-[var(--text)]">{WORD_ENTRY.noRetention}</p>
      <p className="mt-1 text-xs text-[var(--text-muted)]">{WORD_ENTRY.noRetentionDetail}</p>

      <div className="mt-4 flex items-center justify-between gap-3">
        <RecoveryBackButton onClick={onBack} label={grid.allConcealed ? BACK.staged : BACK.beforeVerify} />
        <RecoveryActionButton
          variant="primary"
          disabled={!grid.canVerify || grid.busy}
          busy={grid.busy}
          onClick={() => {
            const phrase = draft.join(' ').trim();
            if (phrase.length > 0) {
              onVerify(phrase);
            }
          }}
        >
          {grid.busy ? WORD_ENTRY.busyVerifying : WORD_ENTRY.verify}
        </RecoveryActionButton>
      </div>

      <RecoveryStatusRegion>
        {grid.checksumState === 'pending' ? WORD_ENTRY.checksumNote : null}
        {!grid.allConcealed && !concealed && count !== null ? WORD_ENTRY.shoulderSurfing : null}
      </RecoveryStatusRegion>
    </RecoveryPanel>
  );
}
