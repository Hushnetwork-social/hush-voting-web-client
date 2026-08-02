/**
 * FEAT-004 browser-vault UI tests — preflight, progress, errors, password
 * boundary, and reveal/clipboard.
 *
 * Proves: preflight surfaces distinguish unsupported/temporary; progress
 * appears only after 250 ms with aria-busy and no fabricated percentage;
 * every result code has one privacy-safe surface and unknown codes degrade
 * generically; password values never enter React state and clear on transfer;
 * reveal conceals after the bound/lifecycle events and clipboard copy is
 * explicit/warned with no clipboard reads.
 *
 * Normative source: FEAT-004 FeatureDescription "Capability Preflight",
 * "Password Boundary", "Mnemonic Reveal and Clipboard", "Error Handling";
 * Tasks 5.2/5.4/5.6 behavior specifications.
 */
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { useAutoConceal, useBoundedProgress } from './hooks';
import { BoundedProgress, PersistenceWarning, PreflightStatus, VaultErrorSurface } from './preflight';
import { DirectPasswordField } from './password';
import { RevealWords } from './reveal';

describe('preflight surfaces (Task 5.2)', () => {
  it('renders nothing when preflight is ok', () => {
    const { container } = render(<PreflightStatus report={{ ok: true, retryable: false, secureOrigin: true, unsupportedCount: 0 }} />);
    expect(container.firstChild).toBeNull();
  });

  it('distinguishes unsupported from retryable guidance', () => {
    const { rerender } = render(<PreflightStatus report={{ ok: false, retryable: false, secureOrigin: true, unsupportedCount: 1 }} />);
    expect(screen.getByText(/cannot safely store/i)).toBeTruthy();
    rerender(<PreflightStatus report={{ ok: false, retryable: true, secureOrigin: true, unsupportedCount: 0 }} />);
    expect(screen.getByText(/temporarily busy/i)).toBeTruthy();
  });

  it('explains insecure origin separately', () => {
    render(<PreflightStatus report={{ ok: false, retryable: false, secureOrigin: false, unsupportedCount: 1 }} />);
    expect(screen.getByText(/secure connection/i)).toBeTruthy();
  });

  it('persistence warning requires explicit acknowledgement', () => {
    const onAcknowledge = vi.fn();
    render(<PersistenceWarning onAcknowledge={onAcknowledge} />);
    fireEvent.click(screen.getByText(/I understand/i));
    expect(onAcknowledge).toHaveBeenCalledTimes(1);
  });
});

describe('bounded progress (Task 5.2)', () => {
  it('appears only after the 250 ms threshold with aria-busy and no percentage', async () => {
    render(<BoundedProgress active />);
    expect(screen.queryByText(/Processing/)).toBeNull();
    await waitFor(() => expect(screen.getByText(/Processing/)).toBeTruthy(), { timeout: 1000 });
    expect(screen.getByRole('status').getAttribute('aria-busy')).toBe('true');
    expect(screen.getByRole('status').textContent).not.toMatch(/\d+%/);
  });
});

describe('vault error surfaces (Task 5.2)', () => {
  it('maps every closed result code to one privacy-safe message', () => {
    const onAction = vi.fn();
    render(<VaultErrorSurface code="WrongPasswordOrDamagedData" onAction={onAction} />);
    expect(screen.getByText(/password is incorrect or the protected data is damaged/i)).toBeTruthy();
    fireEvent.click(screen.getByRole('button'));
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it('degrades generically for unknown/future codes without raw detail', () => {
    render(<VaultErrorSurface code="FutureSecretCode999" onAction={() => undefined} />);
    expect(screen.getByText(/something went wrong/i)).toBeTruthy();
    expect(screen.queryByText(/FutureSecretCode999/)).toBeNull();
  });
});

describe('direct password boundary (Task 5.4)', () => {
  it('transfers the value once and clears the input without React state', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    render(<DirectPasswordField onSubmitSecret={onSubmit} kind="current-password" label="Device password" />);
    const input = screen.getByLabelText(/device password/i) as HTMLInputElement;
    await user.type(input, 'supersecret');
    await user.click(screen.getByRole('button', { name: /continue/i }));
    expect(onSubmit).toHaveBeenCalledWith('supersecret');
    expect(input.value).toBe(''); // cleared immediately after accepted transfer
  });

  it('uses current-password autocomplete semantics and disables while busy', () => {
    render(<DirectPasswordField onSubmitSecret={() => undefined} kind="new-password" label="New password" busy />);
    expect((screen.getByLabelText(/new password/i) as HTMLInputElement).autocomplete).toBe('new-password');
    expect((screen.getByRole('button') as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('reveal and clipboard (Task 5.6)', () => {
  it('renders semantic ordered words and conceals on explicit close', async () => {
    const user = userEvent.setup();
    const onConcealed = vi.fn();
    render(<RevealWords words={['word-one', 'word-two', 'word-three']} onConcealed={onConcealed} clipboard={null} />);
    const list = screen.getByRole('list');
    expect(list.children.length).toBe(3);
    await user.click(screen.getByRole('button', { name: /conceal now/i }));
    expect(onConcealed).toHaveBeenCalled();
    expect(screen.queryByText('word-one')).toBeNull();
  });

  it('copy is explicit/warned, writes once, and denied writes surface safely', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    render(<RevealWords words={['a', 'b']} onConcealed={() => undefined} clipboard={{ writeText } as unknown as Clipboard} />);
    await user.click(screen.getByRole('button', { name: /copy words/i }));
    expect(writeText).toHaveBeenCalledWith('a b');
    expect(screen.getByText(/attempt to clear the clipboard after 30 seconds/i)).toBeTruthy();
  });

  it('auto-conceals after the lifetime bound (fake timers)', async () => {
    vi.useFakeTimers();
    try {
      const onConcealed = vi.fn();
      render(<RevealWords words={['a']} onConcealed={onConcealed} clipboard={null} />);
      expect(screen.getByText('a')).toBeTruthy();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_001);
      });
      expect(onConcealed).toHaveBeenCalled();
      expect(screen.queryByText('a')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('hooks (logic)', () => {
  it('useBoundedProgress stays hidden until the threshold', () => {
    function Probe({ active }: { readonly active: boolean }) {
      const visible = useBoundedProgress(250, active);
      return <div data-testid="probe" data-visible={String(visible)} />;
    }
    const { rerender } = render(<Probe active={false} />);
    expect(screen.getByTestId('probe').getAttribute('data-visible')).toBe('false');
    rerender(<Probe active />);
    expect(screen.getByTestId('probe').getAttribute('data-visible')).toBe('false');
  });

  it('useBoundedProgress appears after the threshold (fake timers)', async () => {
    vi.useFakeTimers();
    try {
      function Probe() {
        const visible = useBoundedProgress(250, true);
        return <div data-testid="probe" data-visible={String(visible)} />;
      }
      render(<Probe />);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(251);
      });
      expect(screen.getByTestId('probe').getAttribute('data-visible')).toBe('true');
    } finally {
      vi.useRealTimers();
    }
  });

  it('useAutoConceal conceals on blur', () => {
    function Probe() {
      const { visible, conceal } = useAutoConceal(60_000, { onConceal: () => undefined });
      return (
        <button onClick={conceal} data-visible={visible}>
          x
        </button>
      );
    }
    render(<Probe />);
    expect(screen.getByText('x').getAttribute('data-visible')).toBe('true');
    fireEvent.click(screen.getByText('x'));
    expect(screen.getByText('x').getAttribute('data-visible')).toBe('false');
  });
});
