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
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { wordlists } from 'bip39';
import type { WordGridProjection } from '../../../lib/recovery-words/contracts/projection';
import { RecoveryActionButton, RecoveryBackButton, RecoveryFieldError, RecoveryPanel, RecoveryStatusRegion, WordInput } from './surfaces';
import { BACK, WORD_ENTRY } from './copy';

const ENGLISH_WORDS: ReadonlySet<string> = new Set(wordlists.english);

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
  const [filledPositions, setFilledPositions] = useState<ReadonlySet<number>>(() => new Set());
  const [concealed, setConcealed] = useState(true);
  const [replacementPrompt, setReplacementPrompt] = useState(false);
  const [pasteError, setPasteError] = useState<'WRONG_COUNT' | null>(null);
  const [unknownPositions, setUnknownPositions] = useState<readonly number[]>([]);
  // The permitted input boundary owns pending paste text too. React retains
  // only this DOM reference, never a phrase-bearing ref value or projection.
  const pendingPasteRef = useRef<HTMLInputElement | null>(null);
  const inputElementsRef = useRef(new Map<number, HTMLInputElement>());
  const errorSummaryRef = useRef<HTMLDivElement | null>(null);
  const previousErrorsRef = useRef<{ codes: string; positions: readonly number[] }>({ codes: '', positions: [] });
  const requestErrorFocusRef = useRef(false);
  const count = grid.selectedWordCount ?? '24';

  useLayoutEffect(() => {
    const inputElements = inputElementsRef.current;
    const pendingPaste = pendingPasteRef.current;
    return () => {
      // Clear while controls are still attached, before React releases refs.
      // Invalid validation results keep this component mounted for correction.
      for (const input of inputElements.values()) input.value = '';
      if (pendingPaste) pendingPaste.value = '';
    };
  }, []);

  useEffect(() => {
    const concealAll = () => {
      setConcealed(true);
      for (const input of inputElementsRef.current.values()) input.blur();
    };
    const visibilityChanged = () => { if (document.visibilityState !== 'visible') concealAll(); };
    document.addEventListener('visibilitychange', visibilityChanged);
    window.addEventListener('pagehide', concealAll);
    window.addEventListener('blur', concealAll);
    return () => {
      document.removeEventListener('visibilitychange', visibilityChanged);
      window.removeEventListener('pagehide', concealAll);
      window.removeEventListener('blur', concealAll);
    };
  }, []);

  const inputs = useMemo(() => {
    const size = count === '12' ? 12 : 24;
    return Array.from({ length: size }, (_, index): { id: string; label: string; position: number } => {
      const position = index + 1;
      return { id: `rw-${position}`, label: WORD_ENTRY.wordLabel(position, size), position };
    });
  }, [count]);

  const anyFieldFilled = filledPositions.size > 0;
  const allFieldsFilled = filledPositions.size === inputs.length;

  const fillGrid = (phrase: string) => {
    const words = phrase.split(' ');
    words.forEach((word, index) => {
      const input = inputElementsRef.current.get(index + 1);
      if (input) input.value = word;
    });
    setFilledPositions(new Set(words.map((_, index) => index + 1)));
    const unknown = words.flatMap((word, index) => ENGLISH_WORDS.has(word) ? [] : [index + 1]);
    setUnknownPositions(unknown);
    requestErrorFocusRef.current = unknown.length > 0;
    setPasteError(null);
    onPastePhrase(phrase);
    setConcealed(true);
  };

  const clearGrid = () => {
    for (const input of inputElementsRef.current.values()) input.value = '';
    setFilledPositions(new Set());
    setUnknownPositions([]);
    setPasteError(null);
    if (pendingPasteRef.current) pendingPasteRef.current.value = '';
    setReplacementPrompt(false);
    setConcealed(true);
    onClearAll();
  };

  const handlePaste = (pastedText: string) => {
    if (grid.busy) return;
    const decision = decidePaste(pastedText, count, anyFieldFilled);
    if (decision.kind === 'fillGrid') {
      fillGrid(decision.phrase);
    } else if (decision.kind === 'replacementRequired') {
      // Existing values remain untouched until explicit whole-grid replacement.
      if (!pendingPasteRef.current) return;
      pendingPasteRef.current.value = decision.phrase;
      setReplacementPrompt(true);
      setPasteError(null);
    } else if (decision.kind === 'countMismatch') {
      requestErrorFocusRef.current = true;
      setPasteError('WRONG_COUNT');
    }
    // countMismatch/emptyPaste: reject entirely; existing fields preserved.
  };

  const confirmReplacement = (confirm: boolean) => {
    const pending = pendingPasteRef.current;
    const phrase = pending?.value ?? '';
    if (pending) pending.value = '';
    if (phrase && confirm) fillGrid(phrase);
    setReplacementPrompt(false);
    onConfirmPasteReplacement(confirm);
  };

  const selectCount = (selected: '12' | '24') => {
    clearGrid();
    onSelectCount(selected);
  };

  const invalidPositions = new Set([...grid.invalidPositions, ...unknownPositions]);
  const linkedPositions = [...invalidPositions].filter(position => Number.isInteger(position)
    && position >= 1 && position <= inputs.length).sort((a, b) => a - b);
  const errorCodes = grid.busy ? '' : [
    ...grid.errorSummary.map(error => error.code),
    ...(pasteError ? ['PASTE_COUNT'] : []),
    ...(unknownPositions.length > 0 ? ['PASTE_UNKNOWN'] : []),
    ...(grid.checksumState === 'failed' ? ['CHECKSUM'] : []),
  ].join('|');

  // Numbered errors target the first affected input; phrase-wide errors target
  // the safe summary. Equivalent projections and ordinary correction must not
  // repeatedly steal focus. Only codes/positions are retained, never word values.
  useLayoutEffect(() => {
    const previous = previousErrorsRef.current;
    previousErrorsRef.current = { codes: errorCodes, positions: linkedPositions };
    if (!errorCodes) return;
    const requested = requestErrorFocusRef.current;
    requestErrorFocusRef.current = false;
    if (!requested && previous.codes === errorCodes
      && linkedPositions.every(position => previous.positions.includes(position))) return;
    const firstInvalid = inputElementsRef.current.get(linkedPositions[0]);
    (firstInvalid ?? errorSummaryRef.current)?.focus();
  });

  return (
    <RecoveryPanel title={WORD_ENTRY.title}>
      {/* Uncontrolled, inaccessible and excluded from form submission/autofill.
          Cleared on either decision, Clear all, count change and unmount. */}
      <input ref={pendingPasteRef} type="password" hidden disabled autoComplete="off" />
      <p className="mb-4 text-sm text-[var(--text-muted)]">{WORD_ENTRY.intro}</p>

      <fieldset className="mb-4" disabled={grid.busy}>
        <legend className="mb-2 text-sm font-medium text-[var(--text)]">Word count</legend>
        <div className="flex flex-wrap gap-3">
          {(['12', '24'] as const).map((option) => (
            <label key={option} className="flex min-h-11 items-center gap-2 rounded-[0.85rem] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)]">
              <input type="radio" name="word-count" checked={count === option} onChange={() => selectCount(option)} data-testid={`count-${option}`} />
              {option === '12' ? WORD_ENTRY.twelve : WORD_ENTRY.twentyFour}
            </label>
          ))}
        </div>
      </fieldset>

      <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" data-testid="word-grid">
            {inputs.map((input) => {
              const filled = filledPositions.has(input.position);
              const invalid = invalidPositions.has(input.position);
              return (
                <div key={input.id} className="flex flex-col gap-1">
                  <WordInput
                    id={input.id}
                    label={input.label}
                    concealed={concealed && filled}
                    invalid={invalid}
                    inputRef={(element) => {
                      if (element) inputElementsRef.current.set(input.position, element);
                      else inputElementsRef.current.delete(input.position);
                    }}
                    onValue={(value) => {
                      setUnknownPositions((positions) => positions.filter(position => position !== input.position));
                      setFilledPositions((current) => {
                        const next = new Set(current);
                        if (value.trim().length > 0) next.add(input.position);
                        else next.delete(input.position);
                        return next;
                      });
                    }}
                    onPaste={(event) => {
                      handlePaste(event.clipboardData.getData('text'));
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
            <RecoveryActionButton variant="secondary" onClick={clearGrid} disabled={!anyFieldFilled}>
              {WORD_ENTRY.clearAll}
            </RecoveryActionButton>
          </div>
          <p className="mt-2 text-xs text-[var(--text-muted)]">{WORD_ENTRY.shoulderSurfing}</p>
      </>

      {(grid.pasteReplacementPending || replacementPrompt) && (
        <div role="alertdialog" aria-label="Replace words" className="mt-4 rounded-[0.85rem] bg-[var(--surface)] p-4">
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

      {errorCodes && (
        <div ref={errorSummaryRef} role="region" aria-label={WORD_ENTRY.errorSummary} tabIndex={-1}
          className="mt-4 rounded-[0.85rem] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]">
          {pasteError !== null && (
            <RecoveryFieldError id="rw-paste-error">{WORD_ENTRY.wrongCountStatic}</RecoveryFieldError>
          )}
          {unknownPositions.length > 0 && grid.errorSummary.every(error => error.code !== 'UNKNOWN_WORD') && (
            <RecoveryFieldError id="rw-paste-unknown">{WORD_ENTRY.unknownWords}</RecoveryFieldError>
          )}
          {grid.errorSummary.map((error) => (
            <RecoveryFieldError key={error.code} id={`rw-error-${error.code}`}>
              {error.code === 'WRONG_COUNT'
                ? WORD_ENTRY.wrongCountStatic
                : error.code === 'UNKNOWN_WORD'
                  ? WORD_ENTRY.unknownWords
                  : WORD_ENTRY.unsupportedInput}
            </RecoveryFieldError>
          ))}
          {grid.checksumState === 'failed' && (
            <RecoveryFieldError id="rw-error-checksum">{WORD_ENTRY.checksumFailed}</RecoveryFieldError>
          )}
          {linkedPositions.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {linkedPositions.map(position => (
                <a key={position} href={`#rw-${position}`}
                  onClick={event => { event.preventDefault(); inputElementsRef.current.get(position)?.focus(); }}
                  className="inline-flex min-h-11 items-center rounded-[0.85rem] px-4 text-sm font-medium text-[var(--text)] underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]">
                  {WORD_ENTRY.reviewWord(position)}
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      <p className="mt-4 text-sm font-medium text-[var(--text)]">{WORD_ENTRY.noRetention}</p>
      <p className="mt-1 text-xs text-[var(--text-muted)]">{WORD_ENTRY.noRetentionDetail}</p>

      <div className="mt-4 flex items-center justify-between gap-3">
        <RecoveryBackButton onClick={onBack} label={grid.allConcealed ? BACK.staged : BACK.beforeVerify} />
        <RecoveryActionButton
          variant="primary"
          fullWidth
          disabled={!allFieldsFilled || !grid.canVerify || grid.busy}
          busy={grid.busy}
          onClick={() => {
            setConcealed(true);
            for (const input of inputElementsRef.current.values()) input.blur();
            const phrase = normalizePastedPhrase(inputs.map((input) => inputElementsRef.current.get(input.position)?.value ?? '').join(' '));
            if (phrase.trim().length > 0) onVerify(phrase);
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
