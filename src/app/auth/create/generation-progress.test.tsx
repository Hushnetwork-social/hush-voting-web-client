import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { GenerateScreen } from './profile';

// EPIC-001 -> FEAT-007 AC-007-009 (progress only) -> Phase 5 Tasks 5.1/5.2.
afterEach(() => { vi.useRealTimers(); });

describe('HushVotingApp TwinTests — generation progress threshold', () => {
  it('disables duplicate generation immediately but announces progress only after 150ms', async () => {
    vi.useFakeTimers();
    const view = render(<GenerateScreen onGenerate={vi.fn()} onBack={vi.fn()} progressVisible progressComplete={false} />);
    expect(screen.getByTestId('create-action').hasAttribute('disabled')).toBe(true);
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => vi.advanceTimersByTimeAsync(149));
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(screen.getByRole('status').textContent).toBe('Generating your identity securely…');
    view.unmount();
  });

  it('does not announce progress for a generation that finishes before the threshold', async () => {
    vi.useFakeTimers();
    const props = { onGenerate: vi.fn(), onBack: vi.fn(), progressComplete: false };
    const view = render(<GenerateScreen {...props} progressVisible />);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.queryByRole('status')).toBeNull();
    view.rerender(<GenerateScreen {...props} progressVisible={false} />);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.queryByRole('status')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
    view.unmount();
  });

  it('clears the pending announcement when generation unmounts', async () => {
    vi.useFakeTimers();
    const view = render(<GenerateScreen onGenerate={vi.fn()} onBack={vi.fn()} progressVisible progressComplete={false} />);
    expect(vi.getTimerCount()).toBe(1);
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    await act(async () => vi.advanceTimersByTimeAsync(150));
    expect(screen.queryByRole('status')).toBeNull();
  });
});
