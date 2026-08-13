/**
 * FEAT-004 standalone-web CSP boundary.
 *
 * Next.js emits small inline bootstrap/RSC scripts. Production authorizes
 * only those framework-created scripts with a fresh per-request nonce; it
 * never enables blanket inline or eval execution. Development and Tauri's
 * static export remain outside this web request boundary.
 */
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { productionNonceCsp, serializeCsp } from './lib/browser-vault/deployment/policy';

export function proxy(request: NextRequest): NextResponse {
  if (process.env.NODE_ENV !== 'production') {
    return NextResponse.next();
  }

  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = serializeCsp(productionNonceCsp(nonce));
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|icon.png|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
