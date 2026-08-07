/**
 * FEAT-007 same-origin BFF — SubmitSignedTransaction proxy.
 *
 * Server-only route (Node runtime): the HushServerNode endpoint lives ONLY
 * here. The page/worker sends the exact signed transaction JSON; the reply is
 * the closed `Successfull/Status/ValidationCode` wire shape. The transport is
 * injected through `HushServerTransportPort` (gRPC binding completes with the
 * pinned server hardening artifact). Fails closed on missing config,
 * malformed requests, size overflow, or timeout. The signed transaction is
 * NEVER logged.
 */
import { NextResponse } from 'next/server';
import type { HushServerTransportPort } from '../../../lib/identity-creation/transport';
import { BFF_MAX_REQUEST_BYTES, RPC_TIMEOUT_MS } from '../../../lib/identity-creation/transport';
import { createServerTransport } from '../server-transport';

export const runtime = 'nodejs';

const noStoreHeaders = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  Pragma: 'no-cache',
  Expires: '0',
};

/** Real HushServerNode liveness/progress probe through GetBlockchainHeight. */
export async function GET(): Promise<NextResponse> {
  const port: HushServerTransportPort | null = createServerTransport(process.env);
  if (port === null) {
    return NextResponse.json({ error: { code: 'NOT_CONFIGURED' } }, { status: 503, headers: noStoreHeaders });
  }
  const result = await Promise.race([
    port.getBlockchainIndex(),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), RPC_TIMEOUT_MS)),
  ]).catch(() => ({ ok: false as const, failure: { kind: 'timeout' as const } }));
  if (!result.ok) {
    return NextResponse.json({ error: { code: 'SERVER_UNAVAILABLE' } }, { status: 502, headers: noStoreHeaders });
  }
  return NextResponse.json({ reply: { index: result.index } }, { headers: noStoreHeaders });
}

export async function POST(request: Request): Promise<NextResponse> {
  const port: HushServerTransportPort | null = createServerTransport(process.env);
  if (port === null) {
    return NextResponse.json({ error: { code: 'NOT_CONFIGURED' } }, { status: 503 });
  }
  const length = Number(request.headers.get('content-length') ?? '0');
  if (length > BFF_MAX_REQUEST_BYTES) {
    return NextResponse.json({ error: { code: 'TOO_LARGE' } }, { status: 413 });
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: { code: 'MALFORMED_REQUEST' } }, { status: 400 });
  }
  const signedTransaction = (body as { signedTransaction?: unknown } | null)?.signedTransaction;
  if (typeof signedTransaction !== 'string' || signedTransaction.length === 0) {
    return NextResponse.json({ error: { code: 'MALFORMED_REQUEST' } }, { status: 400 });
  }
  const result = await Promise.race([
    port.submitTransaction({ signedTransaction }),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), RPC_TIMEOUT_MS)),
  ]).catch(() => ({ ok: false as const, failure: { kind: 'timeout' as const } }));
  if (!result.ok) {
    return NextResponse.json({ error: { code: 'SERVER_UNAVAILABLE' } }, { status: 502 });
  }
  return NextResponse.json({ reply: result.reply });
}
