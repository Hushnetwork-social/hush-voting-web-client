import { describe, expect, it, vi } from 'vitest';
import {
  BlockchainIndexTracker,
  fetchBlockchainIndex,
  PAUSED_AFTER_SAME_INDEX_OBSERVATIONS,
} from './blockchain-index';

describe('blockchain index connectivity', () => {
  it('is online on a successful index and paused after the third same observation', () => {
    const tracker = new BlockchainIndexTracker();
    expect(PAUSED_AFTER_SAME_INDEX_OBSERVATIONS).toBe(3);
    expect(tracker.observe('42')).toBe('online');
    expect(tracker.observe('42')).toBe('online');
    expect(tracker.observe('42')).toBe('paused');
  });

  it('returns online immediately when a paused blockchain advances', () => {
    const tracker = new BlockchainIndexTracker();
    tracker.observe('42');
    tracker.observe('42');
    expect(tracker.observe('42')).toBe('paused');
    expect(tracker.observe('43')).toBe('online');
  });

  it('resets repeated observations after a failed probe', () => {
    const tracker = new BlockchainIndexTracker();
    tracker.observe('42');
    tracker.observe('42');
    expect(tracker.failure()).toBe('offline');
    expect(tracker.observe('42')).toBe('online');
  });

  it('accepts only a successful bounded decimal index reply', async () => {
    const okFetch = vi.fn(async () => new Response(JSON.stringify({ reply: { index: '123' } }), { status: 200 }));
    expect(await fetchBlockchainIndex(okFetch as typeof fetch)).toBe('123');

    const malformedFetch = vi.fn(async () => new Response(JSON.stringify({ reply: { index: 'not-an-index' } }), { status: 200 }));
    expect(await fetchBlockchainIndex(malformedFetch as typeof fetch)).toBeNull();

    const offlineFetch = vi.fn(async () => new Response('{}', { status: 502 }));
    expect(await fetchBlockchainIndex(offlineFetch as typeof fetch)).toBeNull();
  });
});
