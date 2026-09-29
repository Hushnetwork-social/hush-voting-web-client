import { afterEach, describe, expect, it, vi } from 'vitest';
import { createElectionAccessQuery, readElectionJson } from './query';

// AC-018-008/009 -> P018-4-01/02 -> T018-4-01/02: closed, bounded query boundary.
describe('election access transport containment', () => {
  afterEach(() => vi.useRealTimers());
  it('rejects actual streamed overflow without relying on Content-Length', async () => {
    const stream = new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(new TextEncoder().encode('{"value":"'));
      controller.enqueue(new TextEncoder().encode('x'.repeat(256) + '"}')); controller.close();
    } });
    await expect(readElectionJson(stream, 256)).rejects.toThrow('bound exceeded');
  });
  it('rejects a timed-out unfinished stream even when its prefix is valid JSON', async () => {
    vi.useFakeTimers();
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode('{}')); } });
    const rejection = expect(readElectionJson(stream, 256)).rejects.toThrow('deadline exceeded');
    await vi.advanceTimersByTimeAsync(10_000); await rejection;
    expect(stream.locked).toBe(false);
  });
  it('projects unknown or cross-election replies as empty unsupported scope', async () => {
    const id = '11111111-2222-4333-8444-555555555555';
    const query = createElectionAccessQuery(async () => new Response(JSON.stringify({ scope: {
      SchemaVersion: 1, ElectionId: '22222222-2222-4333-8444-555555555555', AllowedOperations: ['vote'], EntitlementReason: '',
    } })));
    expect(await query(id, { signatory: 'public', signedAt: 'time', signature: 'signed' })).toEqual({ ok: true,
      access: { electionId: id, allowedOperations: [], reason: 'ENTITLEMENT_SEMANTICS_UNSUPPORTED' } });
  });
});
