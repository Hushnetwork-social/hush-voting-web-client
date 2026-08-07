/**
 * FEAT-008 Task 5.2 — component and accessibility tests for the word-entry UI.
 * Coverage targets: AC-008-005–017 (component/a11y portion); paste into every
 * position, empty/non-empty replacement, wrong-count atomicity, unknown
 * positions, concealment, clear-all, error focus, no secret snapshots.
 */
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { WordGridProjection } from '../../../lib/recovery-words/contracts/projection';
import { WordEntryScreen, decidePaste, normalizePastedPhrase } from './word-entry';

const M24 = 'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24';
const M12 = M24.split(' ').slice(0, 12).join(' ');

function grid(overrides: Partial<WordGridProjection> = {}): WordGridProjection {
  return {
    selectedWordCount: null,
    invalidPositions: [],
    countValid: false,
    vocabularyValid: false,
    checksumState: 'notRun',
    allConcealed: true,
    busy: false,
    canVerify: false,
    errorSummary: [],
    pasteReplacementPending: false,
    ...overrides,
  };
}

describe('decidePaste (entry contract)', () => {
  it('fills the grid atomically for a count-correct phrase with no count selected', () => {
    expect(decidePaste(M12, null, false)).toEqual({ kind: 'fillGrid', phrase: normalizePastedPhrase(M12), count: 12 });
    expect(decidePaste(M24, null, false)).toEqual({ kind: 'fillGrid', phrase: normalizePastedPhrase(M24), count: 24 });
  });

  it('rejects a count mismatch entirely without truncation or padding', () => {
    const decision = decidePaste(M12, '24', false);
    expect(decision.kind).toBe('countMismatch');
    if (decision.kind === 'countMismatch') {
      expect(decision.expected).toBe(24);
      expect(decision.actual).toBe(12);
    }
  });

  it('requires explicit whole-grid replacement when fields are filled', () => {
    const decision = decidePaste(M12, '12', true);
    expect(decision.kind).toBe('replacementRequired');
  });

  it('normalizes NFKD/case/whitespace and collapses separators', () => {
    expect(normalizePastedPhrase('  WORD1\t Word2\nword3  word4 ')).toBe('word1 word2 word3 word4');
  });

  it('rejects empty and unsupported-count pastes', () => {
    expect(decidePaste('   ', null, false).kind).toBe('emptyPaste');
    expect(decidePaste('one two three', null, false).kind).toBe('countMismatch');
  });
});

describe('WordEntryScreen (Task 5.2)', () => {
  it('opens with all 24 indexed places visible while retaining the explicit 12-word option', () => {
    render(<WordEntryScreen grid={grid()} onSelectCount={vi.fn()} onPastePhrase={vi.fn()} onConfirmPasteReplacement={vi.fn()} onClearAll={vi.fn()} onVerify={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByLabelText('12 words')).not.toBeChecked();
    expect(screen.getByLabelText('24 words')).toBeChecked();
    expect(screen.getByTestId('word-grid')).toBeInTheDocument();
    expect(screen.getAllByTestId(/word-input-rw-/)).toHaveLength(24);
    expect(screen.getByText(/will not save these recovery words/)).toBeDefined();
  });

  it('renders the full indexed grid with accessible labels once a count is selected', () => {
    render(<WordEntryScreen grid={grid({ selectedWordCount: '24' })} onSelectCount={vi.fn()} onPastePhrase={vi.fn()} onConfirmPasteReplacement={vi.fn()} onClearAll={vi.fn()} onVerify={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByLabelText('Recovery word 1 of 24')).toBeDefined();
    expect(screen.getByLabelText('Recovery word 24 of 24')).toBeDefined();
    expect(screen.getAllByTestId(/word-input-rw-/)).toHaveLength(24);
  });

  it('keeps Verify disabled until count/vocabulary are locally valid', () => {
    render(<WordEntryScreen grid={grid({ selectedWordCount: '12', canVerify: false })} onSelectCount={vi.fn()} onPastePhrase={vi.fn()} onConfirmPasteReplacement={vi.fn()} onClearAll={vi.fn()} onVerify={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled();
  });

  it('distributes a complete pasted phrase across every position and enables Verify', async () => {
    const user = userEvent.setup();
    const onPastePhrase = vi.fn();
    const onVerify = vi.fn();
    render(<WordEntryScreen grid={grid({ selectedWordCount: '24', canVerify: true })} onSelectCount={vi.fn()} onPastePhrase={onPastePhrase} onConfirmPasteReplacement={vi.fn()} onClearAll={vi.fn()} onVerify={onVerify} onBack={vi.fn()} />);
    const first = screen.getByLabelText('Recovery word 1 of 24');
    fireEvent.paste(first, { clipboardData: { getData: () => M24 } });

    const fields = screen.getAllByTestId(/word-input-rw-/);
    expect(fields).toHaveLength(24);
    M24.split(' ').forEach((word, index) => expect(fields[index]).toHaveValue(word));
    expect(onPastePhrase).toHaveBeenCalledWith(normalizePastedPhrase(M24));
    expect(screen.getByRole('button', { name: 'Verify' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Verify' })).toHaveClass('button-default', 'w-full');

    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(onVerify).toHaveBeenCalledWith(normalizePastedPhrase(M24));
  });

  it('never renders word values into nonessential accessibility content when concealed', () => {
    render(<WordEntryScreen grid={grid({ selectedWordCount: '24', allConcealed: true })} onSelectCount={vi.fn()} onPastePhrase={vi.fn()} onConfirmPasteReplacement={vi.fn()} onClearAll={vi.fn()} onVerify={vi.fn()} onBack={vi.fn()} />);
    const body = document.body.textContent ?? '';
    expect(body).not.toMatch(/word1|word24/i);
  });

  it('marks unknown positions and renders error summaries without echoing values', () => {
    render(
      <WordEntryScreen
        grid={grid({ selectedWordCount: '12', vocabularyValid: false, canVerify: false, invalidPositions: [3], errorSummary: [{ code: 'UNKNOWN_WORD', positions: [3] }] })}
        onSelectCount={vi.fn()}
        onPastePhrase={vi.fn()}
        onConfirmPasteReplacement={vi.fn()}
        onClearAll={vi.fn()}
       
        onVerify={vi.fn()}
        onBack={vi.fn()}
      />
    );
    expect(screen.getAllByRole('alert').length).toBeGreaterThan(0);
    expect(screen.getByText(/not in the supported word list/)).toBeDefined();
    expect(document.body.textContent).not.toMatch(/word1|word24/i);
  });

  it('shows the paste replacement prompt when pending', () => {
    render(
      <WordEntryScreen
        grid={grid({ selectedWordCount: '12', pasteReplacementPending: true })}
        onSelectCount={vi.fn()}
        onPastePhrase={vi.fn()}
        onConfirmPasteReplacement={vi.fn()}
        onClearAll={vi.fn()}
       
        onVerify={vi.fn()}
        onBack={vi.fn()}
      />
    );
    expect(screen.getByRole('alertdialog')).toBeDefined();
    expect(screen.getByText(/Replace all entered recovery words/)).toBeDefined();
  });
});
