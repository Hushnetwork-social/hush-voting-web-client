// EPIC-001 -> FEAT-008 AC-008-014/016 -> Phase 5 Tasks 5.1/5.2.
// Isolated HushVotingApp TwinTests; no EPIC acceptance claim.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { WordGridProjection } from '../../../lib/recovery-words/contracts/projection';
import { WordEntryScreen } from './word-entry';

const phrase = [...Array<string>(23).fill('abandon'), 'art'].join(' ');
const grid: WordGridProjection = {
  selectedWordCount: '24', invalidPositions: [], countValid: true,
  vocabularyValid: true, checksumState: 'notRun', allConcealed: true,
  busy: false, canVerify: true, errorSummary: [], pasteReplacementPending: false,
};
const actions = () => ({ onSelectCount: vi.fn(), onPastePhrase: vi.fn(),
  onConfirmPasteReplacement: vi.fn(), onClearAll: vi.fn(), onVerify: vi.fn(), onBack: vi.fn() });

describe('HushVotingApp TwinTests — recovery word-entry custody', () => {
  // FEAT-008 AC-008-017 -> Phase 5 Tasks 5.1/5.2. Inspect actual React
  // publications/hooks, excluding the explicitly permitted DOM input boundary.
  it('keeps a pending whole-phrase paste out of React props and hook values', () => {
    render(<WordEntryScreen grid={grid} {...actions()} />);
    const input = document.getElementById('rw-1')!;
    fireEvent.change(input, { target: { value: 'legal' } });
    fireEvent.paste(input, { clipboardData: { getData: () => phrase } });
    expect(screen.getByRole('alertdialog')).toBeInTheDocument();
    const seen = new WeakSet<object>();
    const contains = (value: unknown): boolean => {
      if (typeof value === 'string') return value.includes(phrase);
      if (!value || typeof value !== 'object' || value instanceof Node || seen.has(value)) return false;
      seen.add(value);
      if (Array.isArray(value) && value.every(item => typeof item === 'string') && value.join(' ') === phrase) return true;
      return Object.entries(Object.getOwnPropertyDescriptors(value)).some(([key, property]) =>
        key !== '_owner' && 'value' in property && contains(property.value));
    };
    type Fiber = { memoizedProps: unknown; memoizedState: unknown; return: Fiber | null };
    const key = Object.keys(input).find(key => key.startsWith('__reactFiber$'));
    expect(Boolean(key)).toBe(true);
    let fiber: Fiber | null = (input as unknown as Record<string, Fiber>)[key!];
    let leaked = false;
    while (fiber) {
      leaked ||= contains(fiber.memoizedProps) || contains(fiber.memoizedState);
      fiber = fiber.return;
    }
    // A failed assertion reports only a boolean, never the phrase or React tree.
    expect(leaked).toBe(false);
  });

  it.each(['Cancel', 'Replace all', 'Clear all', 'unmount'])('clears the pending DOM paste buffer on %s', action => {
    const page = render(<WordEntryScreen grid={grid} {...actions()} />);
    const input = document.getElementById('rw-1')!;
    fireEvent.change(input, { target: { value: 'legal' } });
    fireEvent.paste(input, { clipboardData: { getData: () => phrase } });
    const pending = [...document.querySelectorAll<HTMLInputElement>('input')].filter(node => node.value === phrase);
    expect(pending.length).toBe(1);
    expect(pending[0].hidden && pending[0].disabled && !pending[0].name).toBe(true);
    if (action === 'unmount') page.unmount();
    else fireEvent.click(screen.getByRole('button', { name: action }));
    expect(pending.every(node => node.value === '')).toBe(true);
  });

  it('normalizes typed compatibility characters, casing and outer whitespace before the authority handoff', () => {
    const callbacks = actions();
    render(<WordEntryScreen grid={grid} {...callbacks} />);
    for (let position = 1; position <= 24; position++) {
      fireEvent.change(document.getElementById(`rw-${position}`)!, { target: { value: position === 24 ? ' ＡＲＴ ' : ' ＡＢＡＮＤＯＮ ' } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(callbacks.onVerify).toHaveBeenCalledTimes(1);
    expect(callbacks.onVerify.mock.calls[0]?.[0] === phrase).toBe(true);
  });

  it.each(['valid handoff', 'cancel before Verify'])('clears detached input values on %s', reason => {
    const callbacks = actions();
    const page = render(<WordEntryScreen grid={grid} {...callbacks} />);
    fireEvent.paste(document.getElementById('rw-1')!, { clipboardData: { getData: () => phrase } });
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('[id^="rw-"]')).filter(node => node.tagName === 'INPUT');
    expect(inputs).toHaveLength(24);
    expect(inputs.every(input => input.value.length > 0)).toBe(true);
    if (reason === 'valid handoff') {
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
      expect(callbacks.onVerify).toHaveBeenCalledTimes(1);
    }
    page.unmount();
    expect(inputs.every(input => input.value === '')).toBe(true);
  });

  it('retains concealed correction inputs through validation rerenders, then clears them on exit', () => {
    const callbacks = actions();
    const page = render(<WordEntryScreen grid={grid} {...callbacks} />);
    fireEvent.paste(document.getElementById('rw-1')!, { clipboardData: { getData: () => phrase } });
    const first = document.getElementById('rw-1') as HTMLInputElement;
    page.rerender(<WordEntryScreen grid={{ ...grid, busy: true, checksumState: 'pending' }} {...callbacks} />);
    page.rerender(<WordEntryScreen grid={{ ...grid, checksumState: 'failed' }} {...callbacks} />);
    expect(first.value.length > 0).toBe(true);
    expect(first.type).toBe('password');
    page.unmount();
    expect(first.value.length).toBe(0);
  });
});
