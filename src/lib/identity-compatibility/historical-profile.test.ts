import { describe, expect, it, vi } from 'vitest';
import { hasBoundedHistoricalName, IDENTITY_RESPONSE_MAX_BYTES, readIdentityResponse } from './historical-profile';
import { createBridgeBffLookup } from '../auth/web/child-bridge';
import { createWorkerBffIdentityLookup } from '../browser-vault/production/worker-env';

// EPIC-001 → FEAT-009 AC-009-041 / FEAT-008 AC-008-035 → Phase 3 Tasks 3.5/3.6.
describe('approved historical profile response boundary', () => {
  it.each(['x'.repeat(4096), 'é'.repeat(2048), '😀'.repeat(1024)])('accepts the exact UTF-8 alias limit without rewriting it', name => {
    expect(hasBoundedHistoricalName(name)).toBe(true);
    expect(hasBoundedHistoricalName(name + 'x')).toBe(false);
  });
  it('rejects malformed Unicode without rejecting historical display characters', () => {
    expect(hasBoundedHistoricalName('\ud800')).toBe(false);
    expect(hasBoundedHistoricalName('<historical>\u202e')).toBe(true);
  });
  it.each([IDENTITY_RESPONSE_MAX_BYTES - 1, IDENTITY_RESPONSE_MAX_BYTES])('accepts a decoded response of %i bytes', async size => {
    const body = JSON.stringify({ pad: 'x'.repeat(size - 10) });
    expect(new TextEncoder().encode(body).length).toBe(size);
    await expect(readIdentityResponse(new Response(body))).resolves.toHaveProperty('pad');
  });
  it.each([null, '1'])('bounds streamed bytes despite an absent or misleading length', async length => {
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ start(controller) {
      controller.enqueue(new Uint8Array(40_000));
      controller.enqueue(new Uint8Array(30_000));
    }, cancel }), { headers: length ? { 'content-length': length } : {} });
    await expect(readIdentityResponse(response)).rejects.toThrow('IDENTITY_RESPONSE_TOO_LARGE');
    expect(cancel).toHaveBeenCalledOnce();
    expect(response.body?.locked).toBe(false);
  });
  it('cancels a held stream on caller abort and releases the reader', async () => {
    const cancel = vi.fn();
    const controller = new AbortController();
    const response = new Response(new ReadableStream({ cancel }));
    const read = readIdentityResponse(response, controller.signal);
    controller.abort();
    await expect(read).rejects.toMatchObject({ name: 'AbortError' });
    expect(cancel).toHaveBeenCalledOnce();
    expect(response.body?.locked).toBe(false);
  });
  it.each([4096, 4097])('applies the same alias limit at initial lookup and final worker verification (%i)', async size => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ reply: { successfull: true,
      profileName: 'x'.repeat(size), publicSigningAddress: '02aa', publicEncryptAddress: '03bb', isPublic: false } })));
    expect((await createBridgeBffLookup(fetcher)('02aa')).kind).toBe(size === 4096 ? 'exact' : 'transportFailure');
    expect((await createWorkerBffIdentityLookup(fetcher)('02aa')).kind).toBe(size === 4096 ? 'exact' : 'unavailable');
  });
});
