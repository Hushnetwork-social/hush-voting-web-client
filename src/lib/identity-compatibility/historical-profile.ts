/** FEAT-009 AC-009-041 / FEAT-008 AC-008-035; FEAT-031 limits approved 2026-09-13. */
export const HISTORICAL_ALIAS_MAX_UTF8_BYTES = 4_096;
export const IDENTITY_RESPONSE_MAX_BYTES = 65_536;

export function hasBoundedHistoricalName(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > HISTORICAL_ALIAS_MAX_UTF8_BYTES) return false;
  const bytes = new TextEncoder().encode(value);
  return bytes.byteLength <= HISTORICAL_ALIAS_MAX_UTF8_BYTES && new TextDecoder().decode(bytes) === value;
}

/** Bound decoded stream bytes before JSON parsing, regardless of Content-Length. */
export async function readIdentityResponse(response: Response, signal?: AbortSignal): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('IDENTITY_RESPONSE_UNAVAILABLE');
  const chunks: Uint8Array[] = [];
  let total = 0;
  let done = false;
  let abort!: () => void;
  const aborted = new Promise<never>((_, reject) => {
    abort = () => reject(new DOMException('Identity response canceled', 'AbortError'));
  });
  signal?.addEventListener('abort', abort, { once: true });
  try {
    if (signal?.aborted) throw new DOMException('Identity response canceled', 'AbortError');
    if (Number(response.headers.get('content-length')) > IDENTITY_RESPONSE_MAX_BYTES) throw new Error('IDENTITY_RESPONSE_TOO_LARGE');
    while (true) {
      const part = await Promise.race([reader.read(), aborted]);
      if (part.done) { done = true; break; }
      total += part.value.byteLength;
      if (total > IDENTITY_RESPONSE_MAX_BYTES) throw new Error('IDENTITY_RESPONSE_TOO_LARGE');
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } finally {
    signal?.removeEventListener('abort', abort);
    if (!done) void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
