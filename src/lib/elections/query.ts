import { isElectionId, parseElectionScopedAccess, type ElectionScopedAccess } from './entitlement';

export const ELECTION_QUERY_HEADERS = ['x-hush-election-query-signatory', 'x-hush-election-query-signed-at', 'x-hush-election-query-signature'] as const;
export interface ElectionQueryHeaders { readonly signatory: string; readonly signedAt: string; readonly signature: string }
export type ElectionAccessQueryResult = { readonly ok: true; readonly access: ElectionScopedAccess }
  | { readonly ok: false; readonly reason: 'ENTITLEMENT_AUTHORITY_UNAVAILABLE' | 'ENTITLEMENT_SEMANTICS_UNSUPPORTED' };

/** Existing server canonical GetElection envelope; only the sealed engine signs it. */
export function electionQuerySignedJson(actorAddress: string, electionId: string, signedAt: string): string {
  return JSON.stringify({ actorAddress, method: 'GetElection', request: { ElectionId: electionId }, signedAt });
}

/** Bound actual streamed bytes, including chunked requests/responses. No raw body escapes. */
export async function readElectionJson(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<unknown> {
  if (body === null) throw new Error('Missing election response');
  const reader = body.getReader();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; void reader.cancel().catch(() => {}); }, 10_000);
  try {
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error('Election response bound exceeded');
      chunks.push(value);
    }
    if (timedOut) throw new Error('Election response deadline exceeded');
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally { clearTimeout(timer); try { await reader.cancel(); } finally { reader.releaseLock(); } }
}

/** Worker-only transport receives already signed headers, never a signing key. */
export function createElectionAccessQuery(fetchImpl: typeof fetch = fetch) {
  return async (electionId: string, signed: ElectionQueryHeaders): Promise<ElectionAccessQueryResult> => {
    if (!isElectionId(electionId)) return { ok: false, reason: 'ENTITLEMENT_SEMANTICS_UNSUPPORTED' };
    const abort = new AbortController(); const timer = setTimeout(() => abort.abort(), 10_000);
    try {
      const response = await fetchImpl('/api/election-access', {
        method: 'POST', cache: 'no-store', signal: abort.signal,
        headers: { 'content-type': 'application/json', [ELECTION_QUERY_HEADERS[0]]: signed.signatory,
          [ELECTION_QUERY_HEADERS[1]]: signed.signedAt, [ELECTION_QUERY_HEADERS[2]]: signed.signature },
        body: JSON.stringify({ electionId }),
      });
      if (!response.ok) return { ok: false, reason: 'ENTITLEMENT_AUTHORITY_UNAVAILABLE' };
      const value = await readElectionJson(response.body, 8192);
      const scope = value !== null && typeof value === 'object' ? (value as Record<string, unknown>).scope : null;
      return { ok: true, access: parseElectionScopedAccess(scope, electionId) };
    } catch { return { ok: false, reason: 'ENTITLEMENT_AUTHORITY_UNAVAILABLE' }; }
    finally { clearTimeout(timer); }
  };
}
