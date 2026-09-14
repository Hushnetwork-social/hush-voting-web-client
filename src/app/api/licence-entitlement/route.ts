/**
 * FEAT-016 Task 6.1 — same-origin licence-entitlement BFF route (server-only).
 *
 * The browser credential authority (SharedWorker) signs a fresh
 * `GetMyEntitlement` query and forwards EXACTLY the three frozen FEAT-015
 * metadata headers to this route; the page/worker never sees an upstream
 * endpoint or TLS credential. The route:
 *   - bounds content length/content-type and rejects any extra header
 *     (no fourth/fifth header and no request ID is ever introduced);
 *   - forwards the three headers verbatim over pinned binary gRPC with the
 *     bounded ten-second deadline;
 *   - returns a `Cache-Control: no-store` envelope containing the closed
 *     `LicenceQueryTransportResult` the worker/parser already consumes.
 *
 * Signed transaction submission is NOT routed here — it stays on the
 * existing canonical `/api/blockchain` `SubmitSignedTransaction` ingress
 * (a licence-specific submission authority is never created).
 *
 * Normative source: FEAT-016 FeatureDescription "Web", "Signed Query
 * Contract"; FEAT-007/010 same-origin no-store BFF conventions;
 * FEAT-015 frozen licence query contract.
 */
import { NextResponse } from 'next/server';
import { validateLicenceBffRequest } from '../../../lib/licensing/licence-bff-http';
import { LICENCE_QUERY_SIGNATURE_HEADER, LICENCE_QUERY_SIGNED_AT_HEADER, LICENCE_QUERY_SIGNATORY_HEADER } from '../../../lib/licensing/contracts';
import { createLicenceServerTransport } from '../server-transport';
import type { LicenceQueryGrpcTransport } from '../licence-transport';

export const runtime = 'nodejs';

function noStoreHeaders(): Record<string, string> {
  return {
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
    Pragma: 'no-cache',
    Expires: '0',
  };
}

function errorJson(code: string, status: number): NextResponse {
  return NextResponse.json({ error: { code } }, { status, headers: noStoreHeaders() });
}

/**
 * POST /api/licence-entitlement
 *
 * Request: exactly the three signed-query metadata headers and an empty (or
 * `{}`) body. Response: `{ reply: LicenceQueryTransportResult }` — never
 * cached, never logged with endpoint/credential material.
 */
export async function POST(request: Request): Promise<NextResponse> {
  const transport = createLicenceServerTransport(process.env);

  const rawHeaders = new Headers(request.headers);
  const contentType = (rawHeaders.get('content-type') ?? '').toLowerCase().split(';')[0] ?? '';
  const contentLength = Number(rawHeaders.get('content-length') ?? '0');
  const headerNames = [...rawHeaders.keys()].map((name) => name.toLowerCase());

  const validation = validateLicenceBffRequest({
    configured: transport !== null,
    contentLength,
    contentType,
    headerNames,
    headers: {
      signatory: rawHeaders.get(LICENCE_QUERY_SIGNATORY_HEADER),
      signedAt: rawHeaders.get(LICENCE_QUERY_SIGNED_AT_HEADER),
      signature: rawHeaders.get(LICENCE_QUERY_SIGNATURE_HEADER),
    },
  });

  if (!validation.ok) {
    const status =
      validation.code === 'TOO_LARGE'
        ? 413
        : validation.code === 'NOT_CONFIGURED'
          ? 503
          : 400;
    return errorJson(validation.code, status);
  }

  const transportValue = transport as LicenceQueryGrpcTransport;

  // Read the empty request body (bounded by content-length validation). The
  // FEAT-015 request message has no business payload; nothing else is read.
  const text = await request.text();
  if (text.length > 0 && text.trim() !== '{}') {
    return errorJson('MALFORMED_REQUEST', 400);
  }

  const result = await transportValue.queryMyEntitlement(validation.headers);
  return NextResponse.json({ reply: result }, { headers: noStoreHeaders() });
}
