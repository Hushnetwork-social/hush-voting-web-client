/**
 * FEAT-007 identity-creation — browser BFF and native transport contracts.
 *
 * The unchanged HushServerNode RPCs (`GetIdentity`, `SubmitSignedTransaction`)
 * are reached through two bounded paths:
 * - Browser: same-origin Next.js BFF routes (`/api/identity`, `/api/blockchain`)
 *   whose server-side transport port is the ONLY place the HushServerNode
 *   endpoint lives. The page/worker sends only public fields and receives only
 *   closed wire replies.
 * - Native (Ubuntu/Android): approved direct transport owned by the Rust
 *   authorities (generated gRPC clients per FEAT-005/006 handoffs).
 *
 * This module defines the shared transport port, the BFF request/reply shapes,
 * and the normalization that proves browser and native adapters produce the
 * SAME closed outcomes (cross-adapter conformance). The gRPC client binding
 * for the BFF server transport is completed with the pinned server hardening
 * artifact; until then the port fails closed instead of faking success.
 *
 * Normative source: FEAT-007 FeatureDescription "Platform Composition",
 * "Immutable HushServerNode Wire Contract"; FEAT-004/005/006 HANDOFFs.
 */
import type { GetIdentityReply, SubmitSignedTransactionReply } from './wire';

/** Typed transport failure (never a not-found / never a rejection). */
export type TransportFailure =
  | { readonly kind: 'timeout' }
  | { readonly kind: 'canceled' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'protocol' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'unauthorized' };

export type LookupTransportResult = { readonly ok: true; readonly reply: GetIdentityReply } | { readonly ok: false; readonly failure: TransportFailure };
export type SubmitTransportResult = { readonly ok: true; readonly reply: SubmitSignedTransactionReply } | { readonly ok: false; readonly failure: TransportFailure };

/** Server-side transport port — implemented by the BFF gRPC binding or native Rust. */
export interface HushServerTransportPort {
  lookupIdentity(request: { readonly publicSigningAddress: string }): Promise<LookupTransportResult>;
  submitTransaction(request: { readonly signedTransaction: string }): Promise<SubmitTransportResult>;
}

/** BFF same-origin request shapes (public fields only). */
export interface BffIdentityLookupRequest {
  readonly publicSigningAddress: string;
}

export interface BffSubmitRequest {
  readonly signedTransaction: string;
}

export interface BffErrorReply {
  readonly error: { readonly code: 'MALFORMED_REQUEST' | 'TOO_LARGE' | 'TIMEOUT' | 'SERVER_UNAVAILABLE' | 'NOT_CONFIGURED' };
}

/** BFF reply: either the closed server reply or a typed error. */
export type BffLookupResponse = { readonly reply: GetIdentityReply } | BffErrorReply;
export type BffSubmitResponse = { readonly reply: SubmitSignedTransactionReply } | BffErrorReply;

/** Per-RPC policy bound (FeatureDescription "Individual RPC policy bound"). */
export const RPC_TIMEOUT_MS = 10_000 as const;
/** Bounded BFF request size (signed transaction JSON; far below limits). */
export const BFF_MAX_REQUEST_BYTES = 65_536 as const;

/** Parse a BFF lookup response; malformed replies fail closed. */
export function parseBffLookupResponse(body: unknown): BffLookupResponse {
  if (body === null || typeof body !== 'object') {
    return { error: { code: 'SERVER_UNAVAILABLE' } };
  }
  const b = body as Record<string, unknown>;
  if (typeof b.error === 'object' && b.error !== null) {
    const code = (b.error as Record<string, unknown>).code;
    return { error: { code: isBffErrorCode(code) ? code : 'SERVER_UNAVAILABLE' } };
  }
  const reply = b.reply;
  if (reply === null || typeof reply !== 'object') {
    return { error: { code: 'SERVER_UNAVAILABLE' } };
  }
  return { reply: reply as unknown as GetIdentityReply };
}

/** Parse a BFF submit response; malformed replies fail closed. */
export function parseBffSubmitResponse(body: unknown): BffSubmitResponse {
  if (body === null || typeof body !== 'object') {
    return { error: { code: 'SERVER_UNAVAILABLE' } };
  }
  const b = body as Record<string, unknown>;
  if (typeof b.error === 'object' && b.error !== null) {
    const code = (b.error as Record<string, unknown>).code;
    return { error: { code: isBffErrorCode(code) ? code : 'SERVER_UNAVAILABLE' } };
  }
  const reply = b.reply;
  if (reply === null || typeof reply !== 'object') {
    return { error: { code: 'SERVER_UNAVAILABLE' } };
  }
  return { reply: reply as unknown as SubmitSignedTransactionReply };
}

function isBffErrorCode(value: unknown): value is BffErrorReply['error']['code'] {
  return typeof value === 'string' && ['MALFORMED_REQUEST', 'TOO_LARGE', 'TIMEOUT', 'SERVER_UNAVAILABLE', 'NOT_CONFIGURED'].includes(value);
}

/** Browser same-origin transport adapter (used by the page/worker). */
export class BffTransport implements HushServerTransportPort {
  constructor(private readonly basePath: string) {}

  async lookupIdentity(request: { readonly publicSigningAddress: string }): Promise<LookupTransportResult> {
    const response = await fetch(`${this.basePath}/api/identity`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request satisfies BffIdentityLookupRequest),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) {
      return { ok: false, failure: { kind: 'unavailable' } };
    }
    const parsed = parseBffLookupResponse(await response.json());
    if ('error' in parsed) {
      return { ok: false, failure: bffErrorToFailure(parsed.error.code) };
    }
    return { ok: true, reply: parsed.reply };
  }

  async submitTransaction(request: { readonly signedTransaction: string }): Promise<SubmitTransportResult> {
    const response = await fetch(`${this.basePath}/api/blockchain`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request satisfies BffSubmitRequest),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) {
      return { ok: false, failure: { kind: 'unavailable' } };
    }
    const parsed = parseBffSubmitResponse(await response.json());
    if ('error' in parsed) {
      return { ok: false, failure: bffErrorToFailure(parsed.error.code) };
    }
    return { ok: true, reply: parsed.reply };
  }
}

function bffErrorToFailure(code: BffErrorReply['error']['code']): TransportFailure {
  switch (code) {
    case 'TIMEOUT':
      return { kind: 'timeout' };
    case 'TOO_LARGE':
    case 'MALFORMED_REQUEST':
      return { kind: 'malformed' };
    case 'NOT_CONFIGURED':
    case 'SERVER_UNAVAILABLE':
      return { kind: 'unavailable' };
    default:
      return { kind: 'unavailable' };
  }
}
