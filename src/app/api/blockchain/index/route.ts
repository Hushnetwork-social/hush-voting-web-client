/**
 * Same-origin HushServerNode blockchain-index BFF.
 *
 * POST-only by design: Next static export excludes server mutation handlers,
 * while the standalone Web build serves this live Node/gRPC endpoint. Native
 * targets remain fail-closed until their target transport supplies the probe.
 */
import { NextResponse } from 'next/server';
import type { HushServerTransportPort } from '../../../../lib/identity-creation/transport';
import { RPC_TIMEOUT_MS } from '../../../../lib/identity-creation/transport';
import { createServerTransport } from '../../server-transport';

export const runtime = 'nodejs';

const noStoreHeaders = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  Pragma: 'no-cache',
  Expires: '0',
};

/** Real HushServerNode liveness/progress probe through GetBlockchainHeight. */
export async function POST(): Promise<NextResponse> {
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
