// EPIC-001 -> FEAT-009 AC-009-085 -> Phase 5 Tasks 5.1/5.2.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { PickerReadScreen } from './picker-password';
import { toRestoreViewState } from '../../../lib/credential-file-restore/presentation/view';
import { COPY } from './surfaces';

function props(reading: boolean) {
  return {
    view: toRestoreViewState({ stage: reading ? 'reading' : 'picker', progress: null, failureCode: null,
      backoffRemainingSeconds: 0, passwordField: null, protectionChoices: null, profile: null, reveal: null }),
    sessionOnlyOnly: false, onChooseFile: vi.fn(), onCancelRead: vi.fn(), onBack: vi.fn(), onAcknowledgeSessionOnly: vi.fn(),
  };
}

afterEach(() => { vi.useRealTimers(); });

describe('HushVotingApp TwinTests — credential read progress timing', () => {
  it('keeps Cancel available immediately and delays read copy and announcement until 150ms', async () => {
    vi.useFakeTimers();
    const input = props(true);
    const view = render(<PickerReadScreen {...input} />);
    expect(screen.queryAllByText(COPY.reading.title)).toHaveLength(0);
    expect(screen.queryByRole('status')).toBeNull();
    fireEvent.click(screen.getByTestId('cancel-read'));
    expect(input.onCancelRead).toHaveBeenCalledOnce();
    await act(async () => vi.advanceTimersByTimeAsync(149));
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(screen.getByRole('status').textContent).toBe(COPY.reading.title);
    view.unmount();
  });

  it('clears a completed read timer and starts fresh for the next read', async () => {
    vi.useFakeTimers();
    const view = render(<PickerReadScreen {...props(true)} />);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.queryAllByText(COPY.reading.title)).toHaveLength(0);
    view.rerender(<PickerReadScreen {...props(false)} />);
    // Drain immediate focus/event work; a leaked read timer would still have
    // 50ms remaining and must not be mistaken for that zero-delay task.
    await act(async () => vi.advanceTimersByTimeAsync(0));
    expect(vi.getTimerCount()).toBe(0);
    view.rerender(<PickerReadScreen {...props(true)} />);
    await act(async () => vi.advanceTimersByTimeAsync(149));
    expect(screen.queryAllByText(COPY.reading.title)).toHaveLength(0);
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(screen.getByRole('status').textContent).toBe(COPY.reading.title);
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('does not leave an announcement timer after cancelling the read surface', async () => {
    vi.useFakeTimers();
    const view = render(<PickerReadScreen {...props(true)} />);
    expect(vi.getTimerCount()).toBe(1);
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    await act(async () => vi.advanceTimersByTimeAsync(150));
    expect(screen.queryByRole('status')).toBeNull();
  });
});
