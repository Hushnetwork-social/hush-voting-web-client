/**
 * FEAT-010 BFF server transport — real bounded HushServerNode calls
 * (Task 6.3).
 *
 * Replaces the FEAT-007-era unconditional `unavailable` stub: when the
 * server-side endpoint is configured, this transport performs REAL bounded
 * HTTP invocations of the unchanged identity RPCs with:
 * - the 10-second individual request deadline;
 * - bounded request bodies (65 KiB);
 * - no-store semantics via the caller (BFF routes);
 * - closed normalization through the sealed FEAT-007 wire parsers;
 * - the endpoint read ONLY from a NON-public server environment variable and
 *   resolved through the closed deployment manifest where configured.
 *
 * An unconditional-unavailable configured transport is a release/build
 * failure (AC-010-014): this implementation genuinely reaches the wire and
 * maps only closed outcomes. Binary gRPC framing completes with the pinned
 * server hardening artifact (external release blocker); the JSON mapping here
 * preserves the canonical field names and sealed reply shapes.
 */
import type { BlockchainIndexTransportResult, HushServerTransportPort, LookupTransportResult, SubmitTransportResult } from '../../lib/identity-creation/transport';
import { RPC_TIMEOUT_MS } from '../../lib/identity-creation/transport';
import {
  parseBffLookupResponse,
  parseBffSubmitResponse,
  type BffIdentityLookupRequest,
  type BffSubmitRequest,
} from '../../lib/identity-creation/transport';
import type { GetIdentityReply, SubmitSignedTransactionReply } from '../../lib/identity-creation/wire';
import { BinaryGrpcTransport, parseGrpcEndpoint } from './binary-grpc-transport';

/** Endpoint configuration source (server-side only, never NEXT_PUBLIC). */
export const HUSHSERVER_ENDPOINT_ENV = 'HUSHSERVER_NODE_ENDPOINT' as const;

/** gRPC-Web-style method paths (unchanged RPC names). */
const BLOCKCHAIN_INDEX_PATH = '/hushBlockchain/GetBlockchainHeight' as const;
const LOOKUP_PATH = '/hushIdentity/GetIdentity' as const;
const SUBMIT_PATH = '/hushBlockchain/SubmitSignedTransaction' as const;

/**
 * FEAT-011 Task 6.1: create the server transport. The PRODUCTION endpoint is
 * the binary gRPC `host:port` (server-side only). Legacy `http(s)://` URLs
 * still resolve to the JSON mapping for FEAT-007-era fixtures/tests; the
 * production contract is binary gRPC, and anything unparseable fails closed.
 */
export function createServerTransport(env: NodeJS.ProcessEnv): HushServerTransportPort | null {
  const raw = env[HUSHSERVER_ENDPOINT_ENV];
  const grpcEndpoint = parseGrpcEndpoint(raw);
  if (grpcEndpoint !== null) {
    try {
      return new BinaryGrpcTransport(grpcEndpoint);
    } catch {
      return null; // pinned proto verification failure or load error -> fail closed
    }
  }
  if (typeof raw === 'string' && /^https?:\/\//.test(raw)) {
    return new ManifestBoundHttpTransport(raw.replace(/\/+$/, '')); // legacy test/fixture path
  }
  return null;
}

/** Real bounded HTTP transport bound to the configured server endpoint. */
export class ManifestBoundHttpTransport implements HushServerTransportPort {
  constructor(private readonly baseUrl: string) {}

  async getBlockchainIndex(): Promise<BlockchainIndexTransportResult> {
    try {
      const response = await fetch(`${this.baseUrl}${BLOCKCHAIN_INDEX_PATH}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-hush-protocol': 'identity-v1' },
        body: '{}',
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
        cache: 'no-store',
      });
      if (!response.ok) return { ok: false, failure: { kind: 'unavailable' } };
      const body = (await response.json()) as { Index?: unknown; index?: unknown } | null;
      const raw = body?.Index ?? body?.index;
      const index = typeof raw === 'string' ? raw : typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0 ? String(raw) : null;
      return index !== null && /^\d+$/.test(index)
        ? { ok: true, index }
        : { ok: false, failure: { kind: 'protocol' } };
    } catch {
      return { ok: false, failure: { kind: 'unavailable' } };
    }
  }

  async lookupIdentity(request: { readonly publicSigningAddress: string }): Promise<LookupTransportResult> {
    return this.post<BffIdentityLookupRequest, GetIdentityReply>(LOOKUP_PATH, request, parseBffLookupResponse, (reply) => ({ ok: true, reply }));
  }

  async submitTransaction(request: { readonly signedTransaction: string }): Promise<SubmitTransportResult> {
    return this.post<BffSubmitRequest, SubmitSignedTransactionReply>(SUBMIT_PATH, request, parseBffSubmitResponse, (reply) => ({ ok: true, reply }));
  }

  private async post<TRequest, TReply>(
    path: string,
    body: TRequest,
    parse: (body: unknown) => { readonly reply?: TReply } | { readonly error: { readonly code: string } },
    success: (reply: TReply) => { readonly ok: true; readonly reply: TReply },
  ): Promise<{ readonly ok: true; readonly reply: TReply } | { readonly ok: false; readonly failure: { readonly kind: 'timeout' | 'canceled' | 'unavailable' | 'protocol' | 'malformed' } }> {
    const encoded = JSON.stringify(body);
    if (encoded.length > 65_536) {
      return { ok: false, failure: { kind: 'malformed' } };
    }
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-hush-protocol': 'identity-v1',
        },
        body: encoded,
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
        cache: 'no-store',
      });
      if (!response.ok) {
        return { ok: false, failure: { kind: 'unavailable' } };
      }
      const parsed = parse(await response.json());
      if ('error' in parsed) {
        return { ok: false, failure: bffErrorToFailure(parsed.error.code) };
      }
      if (parsed.reply === undefined) {
        return { ok: false, failure: { kind: 'malformed' } };
      }
      return success(parsed.reply);
    } catch (error) {
      if (error instanceof Error && error.name === 'TimeoutError') {
        return { ok: false, failure: { kind: 'timeout' } };
      }
      if (error instanceof Error && error.name === 'AbortError') {
        return { ok: false, failure: { kind: 'canceled' } };
      }
      return { ok: false, failure: { kind: 'unavailable' } };
    }
  }
}

function bffErrorToFailure(code: string): { readonly kind: 'timeout' | 'unavailable' | 'malformed' } {
  switch (code) {
    case 'TIMEOUT':
      return { kind: 'timeout' };
    case 'TOO_LARGE':
    case 'MALFORMED_REQUEST':
      return { kind: 'malformed' };
    default:
      return { kind: 'unavailable' };
  }
}
