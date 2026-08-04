/**
 * FEAT-007 same-origin BFF — GetIdentity lookup proxy.
 *
 * Server-only route (Node runtime): the HushServerNode endpoint lives ONLY
 * here (server-side environment, never NEXT_PUBLIC). The page/worker sends
 * only the public signing address; the reply is the closed wire shape. The
 * actual HushServerNode transport is injected through
 * `HushServerTransportPort`; the gRPC binding completes with the pinned
 * server hardening artifact. Fails closed on missing config, malformed
 * requests, size overflow, or timeout. No secrets are logged.
 */
import { NextResponse } from 'next/server';
import type { HushServerTransportPort } from '../../../lib/identity-creation/transport';
import { BFF_MAX_REQUEST_BYTES, RPC_TIMEOUT_MS } from '../../../lib/identity-creation/transport';
import { createServerTransport } from '../server-transport';

export const runtime = 'nodejs';

const ADDRESS_RE = /^[A-Za-z0-9]{1,128}$/;

/**
 * FEAT-008 no-client-caching policy: lookup responses must never be cached by
 * the browser, a service worker, a CDN, prefetch/replay tooling, or any other
 * browser persistence layer. Full addresses never appear in ordinary logs.
 */
function noStore(): Record<string, string> {
  return {
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
    Pragma: 'no-cache',
    Expires: '0',
  };
}

function jsonResponse(body: unknown, status: number): NextResponse {
  return NextResponse.json(body, { status, headers: noStore() });
}

export async function POST(request: Request): Promise<NextResponse> {
  const port: HushServerTransportPort | null = createServerTransport(process.env);
  if (port === null) {
    return jsonResponse({ error: { code: 'NOT_CONFIGURED' } }, 503);
  }
  const length = Number(request.headers.get('content-length') ?? '0');
  if (length > BFF_MAX_REQUEST_BYTES) {
    return jsonResponse({ error: { code: 'TOO_LARGE' } }, 413);
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: { code: 'MALFORMED_REQUEST' } }, 400);
  }
  const address = (body as { publicSigningAddress?: unknown } | null)?.publicSigningAddress;
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) {
    return jsonResponse({ error: { code: 'MALFORMED_REQUEST' } }, 400);
  }
  const result = await Promise.race([
    port.lookupIdentity({ publicSigningAddress: address }),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), RPC_TIMEOUT_MS)),
  ]).catch((e: unknown) => ({ ok: false as const, failure: { kind: 'timeout' as const }, error: e }));
  if (!result.ok) {
    return jsonResponse({ error: { code: 'SERVER_UNAVAILABLE' } }, 502);
  }
  return jsonResponse({ reply: result.reply }, 200);
}
