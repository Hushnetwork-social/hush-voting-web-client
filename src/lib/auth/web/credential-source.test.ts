import { afterEach, describe, expect, it, vi } from 'vitest';
import { readCredentialSnapshot } from './credential-source';

afterEach(() => vi.useRealTimers());

function provider(size: number) {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const cancel = vi.fn();
  const file = { size, slice: vi.fn(() => ({ stream: () => new ReadableStream<Uint8Array>({
    start(value) { controller = value; }, cancel,
  }) })) } as unknown as File;
  return { file, cancel, get controller() { return controller; } };
}

describe('HushVotingApp TwinTests — bounded credential source', () => {
  it('resets inactivity only on progress, then cancels and clears partial bytes after thirty seconds', async () => {
    vi.useFakeTimers();
    const source = provider(100);
    const outcome = readCredentialSnapshot(source.file, new AbortController().signal).catch(error => error);
    const chunk = new Uint8Array([1, 2, 3]);
    await vi.advanceTimersByTimeAsync(29_000);
    source.controller.enqueue(chunk);
    await vi.advanceTimersByTimeAsync(0);
    expect(chunk).toEqual(new Uint8Array(3));
    let settled = false;
    void outcome.then(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(29_999);
    expect(settled).toBe(false);
    source.controller.enqueue(new Uint8Array());
    await vi.advanceTimersByTimeAsync(1);
    expect((await outcome).code).toBe('READ_INACTIVITY_TIMEOUT');
    expect(source.cancel).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cancellation settles a stalled read, closes its stream and clears timers', async () => {
    vi.useFakeTimers();
    const source = provider(100);
    const abort = new AbortController();
    const outcome = readCredentialSnapshot(source.file, abort.signal).catch(error => error);
    source.controller.enqueue(new Uint8Array([1, 2, 3]));
    await vi.advanceTimersByTimeAsync(0);
    abort.abort();
    expect((await outcome).code).toBe('READ_UNAVAILABLE');
    expect(source.cancel).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('rejects early EOF and never returns partial ciphertext', async () => {
    const source = provider(100);
    const outcome = readCredentialSnapshot(source.file, new AbortController().signal).catch(error => error);
    source.controller.enqueue(new Uint8Array([1, 2, 3]));
    source.controller.close();
    expect((await outcome).code).toBe('READ_PARTIAL');
  });

  it('rejects the overflow byte and clears the unexpected chunk', async () => {
    const source = provider(1_048_576);
    const outcome = readCredentialSnapshot(source.file, new AbortController().signal).catch(error => error);
    const oversized = new Uint8Array(1_048_577).fill(7);
    source.controller.enqueue(oversized);
    expect((await outcome).code).toBe('ENVELOPE_OVERSIZE');
    expect(oversized.every(value => value === 0)).toBe(true);
    expect(source.cancel).toHaveBeenCalledOnce();
  });

  it('rejects a known oversized file before opening its source', async () => {
    const source = provider(1_048_577);
    await expect(readCredentialSnapshot(source.file, new AbortController().signal)).rejects.toMatchObject({ code: 'ENVELOPE_OVERSIZE' });
    expect(source.file.slice).not.toHaveBeenCalled();
  });
});
