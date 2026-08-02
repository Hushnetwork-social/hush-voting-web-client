/**
 * FEAT-004 browser-vault deployment — restrictive first-party policy contract.
 *
 * Authenticated production pages require a restrictive reviewed policy:
 *
 * - `default-src 'self'`;
 * - `script-src 'self'` without `unsafe-eval` or unapproved inline execution;
 * - `worker-src 'self'`;
 * - `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`;
 * - `connect-src` limited to approved application and HushServerNode/proxy
 *   origins;
 * - HSTS (production HTTPS), `X-Content-Type-Options: nosniff`,
 *   `Referrer-Policy: no-referrer`, minimal Permissions-Policy;
 * - no third-party analytics/support widgets/remote crypto/CDN workers;
 * - no service worker on the authenticated origin.
 *
 * The policy is a pure, tested contract; deployment wiring applies it only to
 * production builds (dev/HMR remains unaffected).
 *
 * Normative source: FEAT-004 FeatureDescription "CSP and same-origin
 * hardening", "Supported Browser and Deployment Baseline".
 */

/** CSP directives as a typed map (serializable, testable). */
export interface CspDirectives {
  readonly 'default-src': string[];
  readonly 'script-src': string[];
  readonly 'worker-src': string[];
  readonly 'object-src': string[];
  readonly 'base-uri': string[];
  readonly 'frame-ancestors': string[];
  readonly 'connect-src': string[];
  readonly 'style-src': string[];
  readonly 'img-src': string[];
  readonly 'upgrade-insecure-requests': boolean;
}

/** Approved connect origins for authenticated pages. */
export const APPROVED_CONNECT_ORIGINS = [
  'https://api.hushnetwork.app',
  'https://www.hushnetwork.app',
] as const;

/** Production CSP directive set (equivalent to the reviewed baseline). */
export const PRODUCTION_CSP: CspDirectives = {
  'default-src': ["'self'"],
  'script-src': ["'self'"],
  'worker-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'none'"],
  'frame-ancestors': ["'none'"],
  'connect-src': ["'self'", ...APPROVED_CONNECT_ORIGINS],
  'style-src': ["'self'"],
  'img-src': ["'self'", 'data:'],
  'upgrade-insecure-requests': true,
};

/** Serialize CSP directives to a header value. */
export function serializeCsp(directives: CspDirectives): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(directives)) {
    if (key === 'upgrade-insecure-requests') {
      if (value) {
        parts.push('upgrade-insecure-requests');
      }
      continue;
    }
    parts.push(`${key} ${(value as string[]).join(' ')}`);
  }
  return parts.join('; ');
}

/** Complete production security header set. */
export function productionSecurityHeaders(): Record<string, string> {
  return {
    'Content-Security-Policy': serializeCsp(PRODUCTION_CSP),
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  };
}

/** Assert the policy invariants (tested contract; fails on unsafe drift). */
export function assertPolicySafe(headers: Record<string, string>): { readonly ok: boolean; readonly violations: readonly string[] } {
  const violations: string[] = [];
  const csp = headers['Content-Security-Policy'] ?? '';
  if (!csp.includes("default-src 'self'")) {
    violations.push('CSP missing default-src self');
  }
  if (csp.includes("script-src 'self' 'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
    violations.push('CSP contains unsafe script directives');
  }
  if (!csp.includes("object-src 'none'")) {
    violations.push('CSP missing object-src none');
  }
  if (!csp.includes("frame-ancestors 'none'")) {
    violations.push('CSP missing frame-ancestors none');
  }
  if (!csp.includes("worker-src 'self'")) {
    violations.push('CSP missing worker-src self');
  }
  if (!csp.includes("base-uri 'none'")) {
    violations.push('CSP missing base-uri none');
  }
  if (headers['X-Frame-Options'] !== 'DENY' && headers['X-Frame-Options'] !== 'SAMEORIGIN') {
    violations.push('X-Frame-Options missing or unsafe');
  }
  if (headers['X-Content-Type-Options'] !== 'nosniff') {
    violations.push('X-Content-Type-Options missing');
  }
  return { ok: violations.length === 0, violations };
}
