import { createRecoveryWordDisplay } from '../../../lib/auth/web/recovery-word-display';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { RecoveryScreen } from './recovery';

afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe('HushVotingApp TwinTests — creation clipboard lifetime', () => {
  it.each(['visible', 'hidden'] as const)('attempts only a foreground empty write after thirty seconds (%s)', async visibility => {
    vi.useFakeTimers();
    const writeText = vi.fn().mockResolvedValue(undefined);
    const readText = vi.fn();
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText, readText } });
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    const view = render(<RecoveryScreen display={testDisplay(Array<string>(24).fill('abandon'))} visible={true} onCopy={vi.fn()}
      onRegenerateRequest={vi.fn()} onContinue={vi.fn()} onBack={vi.fn()} acknowledged={false}
      onAcknowledge={vi.fn()} timeoutMessage={null} />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Copy words' })));
    expect(writeText).toHaveBeenCalledTimes(1);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue(visibility);
    await act(async () => vi.advanceTimersByTimeAsync(29_999));
    expect(writeText).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(writeText).toHaveBeenCalledTimes(visibility === 'visible' ? 2 : 1);
    if (visibility === 'visible') expect(writeText).toHaveBeenLastCalledWith('');
    expect(readText).not.toHaveBeenCalled();
    view.unmount();
  });

  it('attempts immediate empty cleanup when the reveal unmounts', async () => {
    vi.useFakeTimers();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    const view = render(<RecoveryScreen display={testDisplay(Array<string>(24).fill('abandon'))} visible={true} onCopy={vi.fn()}
      onRegenerateRequest={vi.fn()} onContinue={vi.fn()} onBack={vi.fn()} acknowledged={false}
      onAcknowledge={vi.fn()} timeoutMessage={null} />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Copy words' })));
    view.unmount();
    await act(async () => vi.advanceTimersByTimeAsync(0));
    expect(writeText).toHaveBeenLastCalledWith('');
  });
});

function testDisplay(words: readonly string[] | null) {
  const controller = createRecoveryWordDisplay();
  controller.update(words);
  return controller.display;
}
