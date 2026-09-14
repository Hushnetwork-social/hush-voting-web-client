import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { DelayScreen } from './status';

// EPIC-001 -> FEAT-007 AC-007-054 -> Phase 5 Tasks 5.5/5.6.
describe('HushVotingApp TwinTests — local promotion storage error', () => {
  it('shows a safe local save error with Retry and Lock', () => {
    const retry = vi.fn(), lock = vi.fn();
    const view = render(<DelayScreen onCheckAgain={retry} onLock={lock} localSaveFailed />);
    expect(screen.getByRole('heading', { name: 'Could not save your identity' })).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Blockchain confirmation delayed' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    fireEvent.click(screen.getByRole('button', { name: 'Lock' }));
    expect(retry).toHaveBeenCalledOnce();
    expect(lock).toHaveBeenCalledOnce();
    view.unmount();
  });
});
