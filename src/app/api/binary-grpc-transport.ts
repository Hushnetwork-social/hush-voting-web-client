/**
 * FEAT-011 Task 6.1 — server-only binary gRPC transport for the unchanged
 * HushServerNode identity RPCs (GetIdentity / SubmitSignedTransaction).
 *
 * Replaces the JSON gRPC-like mapping with a real binary gRPC client using
 * the pinned proto copies (`src/app/api/protos/`, digest-verified at load).
 * The channel is created ONLY from the server-side environment; the
 * browser/worker never sees an endpoint. Every call keeps the 10-second
 * deadline and the sealed FEAT-007 wire normalization. gRPC transport errors
 * map to closed outcomes — never absence, never fabricated success.
 */

import { credentials, loadPackageDefinition, Metadata, type ChannelCredentials } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { BlockchainIndexTransportResult, HushServerTransportPort, LookupTransportResult, SubmitTransportResult } from '../../lib/identity-creation/transport';
import { RPC_TIMEOUT_MS } from '../../lib/identity-creation/transport';
import type { GetIdentityReply, SubmitSignedTransactionReply } from '../../lib/identity-creation/wire';

/** Pinned proto digests (sha-256 of the copies; verified at load). */
export const PINNED_PROTO_DIGESTS = {
  'hushIdentity.proto': 'df3a2d9b128335dc3c92f0ef2b246655ed4c95f53f7ce058d438d945724f8ffa',
  'hushBlockchain.proto': 'e0625d52e4227ed77b6eb0e7d74b2990b7a8d3e8ecd77bd308371797275dc04b',
} as const;

export const PROTO_DIR = path.join(process.cwd(), 'src', 'app', 'api', 'protos');

const LOADER_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
} as const;

/** The closed RPC surface loaded from the pinned protos. */
export interface PinnedGrpcSurface {
  readonly HushIdentity: unknown;
  readonly HushBlockchain: unknown;
}

interface RpcHushPackage {
  rpcHush: {
    HushIdentity: new (address: string, creds: ChannelCredentials) => unknown;
    HushBlockchain: new (address: string, creds: ChannelCredentials) => unknown;
  };
}

/** Verify pinned proto copies; throws when a digest mismatches. */
export function verifyPinnedProtos(protoDir: string = PROTO_DIR): void {
  for (const [file, expected] of Object.entries(PINNED_PROTO_DIGESTS)) {
    const actual = createHash('sha256').update(readFileSync(path.join(protoDir, file))).digest('hex');
    if (actual !== expected) {
      throw new Error(`pinned proto digest mismatch for ${file}: ${actual}`);
    }
  }
}

/** Load the pinned binary gRPC surface bound to the endpoint. */
export function loadPinnedGrpcSurface(endpoint: string, protoDir: string = PROTO_DIR): PinnedGrpcSurface {
  verifyPinnedProtos(protoDir);
  const definition = loadSync([path.join(protoDir, 'hushIdentity.proto'), path.join(protoDir, 'hushBlockchain.proto')], LOADER_OPTIONS);
  const pkg = loadPackageDefinition(definition) as unknown as RpcHushPackage;
  return {
    HushIdentity: new pkg.rpcHush.HushIdentity(endpoint, credentials.createInsecure()),
    HushBlockchain: new pkg.rpcHush.HushBlockchain(endpoint, credentials.createInsecure()),
  };
}

/** Promisified unary call with the 10-second deadline (grpc-js options form). */
function unaryCall<TReply>(client: unknown, method: string, request: object, deadlineMs: number): Promise<TReply> {
  return new Promise<TReply>((resolve, reject) => {
    const c = client as Record<
      string,
      (req: object, metadata: object, options: { deadline: number }, cb: (err: unknown, resp: TReply) => void) => void
    >;
    c[method](request, new Metadata(), { deadline: Date.now() + deadlineMs }, (err: unknown, resp: TReply) => {
      if (err !== null && err !== undefined) {
        reject(err);
      } else {
        resolve(resp);
      }
    });
  });
}

/**
 * Binary gRPC transport bound to `host:port` (server-side only). The sealed
 * FEAT-007 wire normalization remains the single control-flow interpretation.
 */
export class BinaryGrpcTransport implements HushServerTransportPort {
  private readonly surface: PinnedGrpcSurface;

  constructor(endpoint: string, surface?: PinnedGrpcSurface) {
    this.surface = surface ?? loadPinnedGrpcSurface(endpoint);
  }

  async getBlockchainIndex(): Promise<BlockchainIndexTransportResult> {
    try {
      const reply = await unaryCall<unknown>(this.surface.HushBlockchain, 'GetBlockchainHeight', {}, RPC_TIMEOUT_MS);
      const index = normalizeBlockchainIndex(reply);
      return index === null
        ? { ok: false, failure: { kind: 'protocol' } }
        : { ok: true, index };
    } catch (error) {
      return { ok: false, failure: grpcErrorToFailure(error) };
    }
  }

  async lookupIdentity(request: { readonly publicSigningAddress: string }): Promise<LookupTransportResult> {
    try {
      const reply = await unaryCall<unknown>(this.surface.HushIdentity, 'GetIdentity', { PublicSigningAddress: request.publicSigningAddress }, RPC_TIMEOUT_MS);
      return { ok: true, reply: normalizeGetIdentityReply(reply) };
    } catch (error) {
      return { ok: false, failure: grpcErrorToFailure(error) };
    }
  }

  async submitTransaction(request: { readonly signedTransaction: string }): Promise<SubmitTransportResult> {
    if (request.signedTransaction.length > 65_536) {
      return { ok: false, failure: { kind: 'malformed' } };
    }
    try {
      const reply = await unaryCall<unknown>(this.surface.HushBlockchain, 'SubmitSignedTransaction', { SignedTransaction: request.signedTransaction }, RPC_TIMEOUT_MS);
      return { ok: true, reply: normalizeSubmitReply(reply) };
    } catch (error) {
      return { ok: false, failure: grpcErrorToFailure(error) };
    }
  }
}

/** Normalize the protobuf int64 without risking JavaScript precision loss. */
export function normalizeBlockchainIndex(reply: unknown): string | null {
  const index = (reply as { Index?: unknown } | null)?.Index;
  if (typeof index === 'string' && /^\d+$/.test(index)) return index;
  if (typeof index === 'number' && Number.isSafeInteger(index) && index >= 0) return String(index);
  return null;
}

/** Parse `host:port`; returns null for anything else (fail closed). */
export function parseGrpcEndpoint(raw: string | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0) {
    return null;
  }
  const trimmed = raw.trim();
  const match = /^([^:]+):(\d{1,5})$/.exec(trimmed);
  if (match === null) {
    return null;
  }
  const port = Number(match[2]);
  if (port < 1 || port > 65535) {
    return null;
  }
  return trimmed;
}

/** Closed normalization of the binary reply (sealed wire shapes only). */
function normalizeGetIdentityReply(reply: unknown): GetIdentityReply {
  const r = reply as {
    Successfull?: unknown;
    Message?: unknown;
    ProfileName?: unknown;
    PublicSigningAddress?: unknown;
    PublicEncryptAddress?: unknown;
    IsPublic?: unknown;
  };
  return {
    successfull: r.Successfull === true,
    message: typeof r.Message === 'string' ? r.Message : '',
    profileName: typeof r.ProfileName === 'string' ? r.ProfileName : '',
    publicSigningAddress: typeof r.PublicSigningAddress === 'string' ? r.PublicSigningAddress : '',
    publicEncryptAddress: typeof r.PublicEncryptAddress === 'string' ? r.PublicEncryptAddress : '',
    isPublic: r.IsPublic === true,
  };
}

/** Closed normalization of the binary submit reply (Status/ValidationCode only). */
function normalizeSubmitReply(reply: unknown): SubmitSignedTransactionReply {
  const r = reply as {
    Successfull?: unknown;
    Message?: unknown;
    status?: unknown;
    ValidationCode?: unknown;
  };
  return {
    successfull: r.Successfull === true,
    message: typeof r.Message === 'string' ? r.Message : '',
    status: normalizeStatus(r.status),
    validationCode: typeof r.ValidationCode === 'string' ? r.ValidationCode : '',
  };
}

function normalizeStatus(status: unknown): SubmitSignedTransactionReply['status'] {
  switch (status) {
    case 'TRANSACTION_STATUS_UNSPECIFIED':
    case 'Unspecified':
    case 'UNSPECIFIED':
      return 'UNSPECIFIED';
    case 'TRANSACTION_STATUS_ACCEPTED':
    case 'Accepted':
    case 'ACCEPTED':
      return 'ACCEPTED';
    case 'TRANSACTION_STATUS_ALREADY_EXISTS':
    case 'AlreadyExists':
    case 'ALREADY_EXISTS':
      return 'ALREADY_EXISTS';
    case 'TRANSACTION_STATUS_PENDING':
    case 'Pending':
    case 'PENDING':
      return 'PENDING';
    case 'TRANSACTION_STATUS_REJECTED':
    case 'Rejected':
    case 'REJECTED':
      return 'REJECTED';
    default:
      return 'UNSPECIFIED'; // unknown enum fails closed downstream
  }
}

/** gRPC transport errors → closed outcomes; never absence, never success. */
export function grpcErrorToFailure(error: unknown): { readonly kind: 'timeout' | 'canceled' | 'protocol' | 'unavailable' | 'malformed' } {
  const code = (error as { code?: number | string })?.code;
  if (code === 4 || code === 'DEADLINE_EXCEEDED') {
    return { kind: 'timeout' };
  }
  if (code === 1 || code === 'CANCELLED') {
    return { kind: 'canceled' };
  }
  if (code === 3 || code === 'INVALID_ARGUMENT' || code === 9 || code === 'FAILED_PRECONDITION' || code === 12 || code === 'UNIMPLEMENTED') {
    return { kind: 'protocol' };
  }
  return { kind: 'unavailable' };
}
