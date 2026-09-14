// EPIC-001 -> FEAT-008 AC-008-080, Safe progress -> Phase 5 Tasks 5.3/5.4.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { LookupProgress } from './candidate-review';

afterEach(() => { vi.useRealTimers(); });

describe('HushVotingApp TwinTests — recovery lookup progress timing', () => {
  it('waits 150ms and reports the latest count without restarting the delay', async () => {
    vi.useFakeTimers();
    const view = render(<LookupProgress done={0} total={2} />);
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => vi.advanceTimersByTimeAsync(100));
    view.rerender(<LookupProgress done={1} total={2} />);
    await act(async () => vi.advanceTimersByTimeAsync(49));
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(screen.getByRole('status').textContent).toBe('Checking identity formats 1 of 2');
    view.unmount();
  });

  it('suppresses fast completed lookups and gives a new lookup its own delay', async () => {
    vi.useFakeTimers();
    const first = render(<LookupProgress done={0} total={2} />);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.queryByRole('status')).toBeNull();
    first.unmount();
    expect(vi.getTimerCount()).toBe(0);
    const next = render(<LookupProgress done={0} total={2} />);
    await act(async () => vi.advanceTimersByTimeAsync(149));
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(screen.getByRole('status').textContent).toBe('Checking identity formats 0 of 2');
    next.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
