/**
 * FEAT-016 Task 6.1 — licence-query BFF HTTP contract (framework-neutral).
 *
 * Bounded same-origin POST contract for the signed entitlement query:
 *   - exactly the three frozen FEAT-015 metadata headers are forwarded
 *     (`x-hush-licence-query-signatory/-signed-at/-signature`);
 *   - no body is expected beyond an optional empty JSON object; oversized or
 *     foreign content is rejected before any upstream call;
 *   - the response is a no-store `LicenceQueryTransportResult` envelope the
 *     worker/parser already consumes.
 *
 * Framework-neutral so the same validation is exercised by vitest unit tests
 * and imported by the Next.js route (server-only) — no React/Next/DOM
 * dependency. Never logs upstream endpoints or header values.
 *
 * Normative source: FEAT-016 FeatureDescription "Signed Query Contract",
 * "Web" (established same-origin no-store bounded BFF);
 * FEAT-015 frozen metadata vocabulary.
 */

import type { LicenceQueryTransportResult } from './contracts';
import { LICENCE_QUERY_SIGNATURE_HEADER, LICENCE_QUERY_SIGNED_AT_HEADER, LICENCE_QUERY_SIGNATORY_HEADER } from './contracts';

/** Max accepted body bytes (the signed query carries no business payload). */
export const LICENCE_BFF_MAX_REQUEST_BYTES = 4_096 as const;

/** The exact metadata header allowlist for one licence query. */
export const LICENCE_QUERY_HEADERS = [
  LICENCE_QUERY_SIGNATORY_HEADER,
  LICENCE_QUERY_SIGNED_AT_HEADER,
  LICENCE_QUERY_SIGNATURE_HEADER,
] as const;

/** Accepted content types (empty body or minimal JSON). */
const ACCEPTED_CONTENT_TYPES: readonly string[] = ['', 'application/json'];

export type LicenceBffRequestValidation =
  | { readonly ok: true; readonly headers: { readonly signatory: string; readonly signedAt: string; readonly signature: string } }
  | { readonly ok: false; readonly code: 'NOT_CONFIGURED' | 'TOO_LARGE' | 'MALFORMED_REQUEST' };

export interface LicenceBffRequestInput {
  readonly contentLength: number;
  readonly contentType: string;
  readonly headerNames: readonly string[];
  /** Values by lowercase header name (already read by the caller). */
  readonly headers: { readonly signatory: unknown; readonly signedAt: unknown; readonly signature: unknown };
  readonly configured: boolean;
}

/** Validate a licence-query BFF request before any upstream call. */
export function validateLicenceBffRequest(input: LicenceBffRequestInput): LicenceBffRequestValidation {
  if (!input.configured) {
    return { ok: false, code: 'NOT_CONFIGURED' };
  }
  if (input.contentLength > LICENCE_BFF_MAX_REQUEST_BYTES) {
    return { ok: false, code: 'TOO_LARGE' };
  }
  if (!ACCEPTED_CONTENT_TYPES.includes(input.contentType)) {
    return { ok: false, code: 'MALFORMED_REQUEST' };
  }
  // No fourth/fifth header: a request must not add extra signed-query
  // members beyond the frozen three (request ID is never introduced).
  for (const header of LICENCE_QUERY_HEADERS) {
    if (!input.headerNames.includes(header)) {
      return { ok: false, code: 'MALFORMED_REQUEST' };
    }
  }
  for (const header of input.headerNames) {
    if (!(LICENCE_QUERY_HEADERS as readonly string[]).includes(header)) {
      return { ok: false, code: 'MALFORMED_REQUEST' };
    }
  }
  const signatory = input.headers.signatory;
  const signedAt = input.headers.signedAt;
  const signature = input.headers.signature;
  if (
    typeof signatory !== 'string' ||
    signatory.length === 0 ||
    typeof signedAt !== 'string' ||
    signedAt.length === 0 ||
    typeof signature !== 'string' ||
    signature.length === 0
  ) {
    return { ok: false, code: 'MALFORMED_REQUEST' };
  }
  return { ok: true, headers: { signatory, signedAt, signature } };
}

/**
 * Parse a licence-query BFF response body into the closed transport result.
 * Malformed/empty bodies fail closed as `UNKNOWN` — never fabricated truth.
 */
export function parseLicenceBffReply(body: unknown): LicenceQueryTransportResult {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, status: 'UNKNOWN' };
  }
  const reply = (body as { readonly reply?: unknown }).reply;
  if (reply === null || reply === undefined || typeof reply !== 'object' || Array.isArray(reply)) {
    return { ok: false, status: 'UNKNOWN' };
  }
  return reply as LicenceQueryTransportResult;
}
