/**
 * FEAT-016 Task 6.1 — server-only licence-query gRPC client + BFF seam.
 *
 * Pinned FEAT-015 `HushVotingLicence.GetMyEntitlement` binary gRPC call. The
 * client exists ONLY server-side (Node runtime); the browser/worker never
 * sees the endpoint. The three signed-query metadata headers
 * (`x-hush-licence-query-signatory/-signed-at/-signature`) are forwarded
 * EXACTLY as gRPC metadata — no fourth/fifth header and no request ID is
 * ever introduced. The 10-second bounded deadline is preserved.
 *
 * Signed transaction submission NEVER routes here: licence transactions
 * travel through the existing canonical `/api/blockchain`
 * `SubmitSignedTransaction` ingress (single submission authority). This
 * module is strictly read-only query forwarding.
 *
 * Normative source: FEAT-016 FeatureDescription "Signed Query Contract",
 * "Web" composition; FEAT-015 `hushVotingLicence.proto`; planning report §6.
 */

import { credentials, loadPackageDefinition, Metadata, type ChannelCredentials } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { LicenceQueryTransportResult } from '../../lib/licensing/contracts';
import {
  LICENCE_QUERY_SIGNATORY_HEADER,
  LICENCE_QUERY_SIGNED_AT_HEADER,
  LICENCE_QUERY_SIGNATURE_HEADER,
} from '../../lib/licensing/contracts';
import { decodeLicenceQueryReply, licenceQueryFailureFromGrpcError } from '../../lib/licensing/bff-decode';
import { PROTO_DIR, verifyPinnedProtos } from './binary-grpc-transport';

/** Bounded ten-second query deadline (FEAT-015 transport contract). */
export const LICENCE_QUERY_DEADLINE_MS = 10_000 as const;

/** Max length for each signed-query metadata value (fail closed beyond). */
export const LICENCE_QUERY_HEADER_MAX_LENGTH = 4_096 as const;

const LOADER_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
} as const;

interface RpcHushLicencePackage {
  rpcHush: {
    HushVotingLicence: new (address: string, creds: ChannelCredentials) => unknown;
  };
}

/** Pinned licence-service surface bound to the endpoint (server-side only). */
export interface PinnedLicenceSurface {
  readonly client: unknown;
}

/** Verify the pinned licence proto copy and load its service client. */
export function loadLicenceSurface(endpoint: string, protoDir: string = PROTO_DIR): PinnedLicenceSurface {
  verifyPinnedProtos(protoDir);
  const digest = createHash('sha256').update(readFileSync(path.join(protoDir, 'hushVotingLicence.proto'))).digest('hex');
  const expected = 'ee004152c5dd24f15e9ebf88db577e3c854f93712d9499ded95dafa8f762eca8';
  if (digest !== expected) {
    throw new Error(`licence proto digest mismatch: ${digest}`);
  }
  const definition = loadSync([path.join(protoDir, 'hushVotingLicence.proto')], LOADER_OPTIONS);
  const pkg = loadPackageDefinition(definition) as unknown as RpcHushLicencePackage;
  return {
    client: new pkg.rpcHush.HushVotingLicence(endpoint, credentials.createInsecure()),
  };
}

/** One promisified GetMyEntitlement unary call with exact metadata. */
function getMyEntitlementCall(
  client: unknown,
  metadataHeaders: { readonly signatory: string; readonly signedAt: string; readonly signature: string },
): Promise<unknown> {
  return new Promise<unknown>((resolve, reject) => {
    const c = client as Record<
      string,
      (req: object, metadata: Metadata, options: { deadline: number }, cb: (err: unknown, resp: unknown) => void) => void
    >;
    const metadata = new Metadata();
    // Exactly the three frozen signed-query headers — nothing else.
    metadata.set(LICENCE_QUERY_SIGNATORY_HEADER, metadataHeaders.signatory);
    metadata.set(LICENCE_QUERY_SIGNED_AT_HEADER, metadataHeaders.signedAt);
    metadata.set(LICENCE_QUERY_SIGNATURE_HEADER, metadataHeaders.signature);
    c.GetMyEntitlement({}, metadata, { deadline: Date.now() + LICENCE_QUERY_DEADLINE_MS }, (err, resp) => {
      if (err !== null && err !== undefined) {
        reject(err);
      } else {
        resolve(resp);
      }
    });
  });
}

/** Bounded metadata header values (fail closed on any violation). */
export function validateLicenceQueryHeaders(headers: {
  readonly signatory: unknown;
  readonly signedAt: unknown;
  readonly signature: unknown;
}): { readonly ok: true; readonly value: { readonly signatory: string; readonly signedAt: string; readonly signature: string } } | { readonly ok: false; readonly reason: 'missing' | 'too-large' } {
  const signatory = typeof headers.signatory === 'string' ? headers.signatory.trim() : '';
  const signedAt = typeof headers.signedAt === 'string' ? headers.signedAt.trim() : '';
  const signature = typeof headers.signature === 'string' ? headers.signature.trim() : '';
  if (signatory.length === 0 || signedAt.length === 0 || signature.length === 0) {
    return { ok: false, reason: 'missing' };
  }
  if (
    signatory.length > LICENCE_QUERY_HEADER_MAX_LENGTH ||
    signedAt.length > LICENCE_QUERY_HEADER_MAX_LENGTH ||
    signature.length > LICENCE_QUERY_HEADER_MAX_LENGTH
  ) {
    return { ok: false, reason: 'too-large' };
  }
  return { ok: true, value: { signatory, signedAt, signature } };
}

/** Server-only licence-query transport (port-implementation for the BFF). */
export class LicenceQueryGrpcTransport {
  private readonly client: unknown;

  constructor(endpoint: string, surface?: PinnedLicenceSurface) {
    this.client = (surface ?? loadLicenceSurface(endpoint)).client;
  }

  /** One fresh signed GetMyEntitlement query with the exact three headers. */
  async queryMyEntitlement(headers: {
    readonly signatory: string;
    readonly signedAt: string;
    readonly signature: string;
  }): Promise<LicenceQueryTransportResult> {
    try {
      const reply = await getMyEntitlementCall(this.client, headers);
      return decodeLicenceQueryReply(reply);
    } catch (error) {
      return licenceQueryFailureFromGrpcError(error);
    }
  }
}
