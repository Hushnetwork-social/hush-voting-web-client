/**
 * HushServerNode connectivity is established by the real blockchain index,
 * never by navigator.onLine. Three consecutive successful observations of
 * the same index classify the reachable node as paused; any advancement
 * immediately restores online. A failed/malformed probe is offline.
 */

export type BlockchainConnectivity = 'online' | 'paused' | 'offline';

export const BLOCKCHAIN_INDEX_POLL_INTERVAL_MS = 3_000 as const;
export const BLOCKCHAIN_INDEX_PROBE_TIMEOUT_MS = 5_000 as const;
export const PAUSED_AFTER_SAME_INDEX_OBSERVATIONS = 3 as const;

export class BlockchainIndexTracker {
  private lastIndex: string | null = null;
  private sameIndexObservations = 0;

  observe(index: string): BlockchainConnectivity {
    if (!/^\d{1,20}$/.test(index)) {
      return this.failure();
    }
    if (index === this.lastIndex) {
      this.sameIndexObservations += 1;
    } else {
      this.lastIndex = index;
      this.sameIndexObservations = 1;
    }
    return this.sameIndexObservations >= PAUSED_AFTER_SAME_INDEX_OBSERVATIONS ? 'paused' : 'online';
  }

  failure(): 'offline' {
    this.lastIndex = null;
    this.sameIndexObservations = 0;
    return 'offline';
  }
}

/** Same-origin, no-store index probe. The index is control data, not logged. */
export async function fetchBlockchainIndex(fetchImpl: typeof fetch = fetch): Promise<string | null> {
  try {
    const response = await fetchImpl('/api/blockchain/index', {
      method: 'POST',
      cache: 'no-store',
      signal: AbortSignal.timeout(BLOCKCHAIN_INDEX_PROBE_TIMEOUT_MS),
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { reply?: { index?: unknown } } | null;
    const index = body?.reply?.index;
    return typeof index === 'string' && /^\d{1,20}$/.test(index) ? index : null;
  } catch {
    return null;
  }
}
