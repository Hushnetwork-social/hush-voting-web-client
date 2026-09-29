/** Server-only bounded binary query. Endpoint and credentials never enter browser props. */
import { credentials, loadPackageDefinition, Metadata, type Client } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { PROTO_DIR, parseGrpcEndpoint } from './binary-grpc-transport';
import { ELECTION_QUERY_HEADERS, type ElectionQueryHeaders } from '../../lib/elections/query';
import { parseElectionScopedAccess } from '../../lib/elections/entitlement';

export async function queryElectionAccess(electionId: string, headers: ElectionQueryHeaders, endpoint: string | undefined): Promise<unknown> {
  const address = parseGrpcEndpoint(endpoint);
  if (address === null) throw new Error('Election authority unavailable');
  const proto = path.join(PROTO_DIR, 'hushElections.proto');
  if (createHash('sha256').update(readFileSync(proto)).digest('hex') !== 'e86be6b6bc7fe511ff0ed1b7530819a58d8a3f208c20a9febbe077684720b28d')
    throw new Error('Election contract unavailable');
  const definition = loadSync(proto, { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
  type ElectionClient = Client & { GetElection: (request: object, metadata: Metadata, options: { deadline: number }, cb: (error: unknown, response: unknown) => void) => void };
  const pkg = loadPackageDefinition(definition) as unknown as { rpcHush: { HushElections: new (...args: ConstructorParameters<typeof Client>) => ElectionClient } };
  const client = new pkg.rpcHush.HushElections(address, credentials.createInsecure());
  try {
    const metadata = new Metadata();
    metadata.set(ELECTION_QUERY_HEADERS[0], headers.signatory);
    metadata.set(ELECTION_QUERY_HEADERS[1], headers.signedAt);
    metadata.set(ELECTION_QUERY_HEADERS[2], headers.signature);
    const reply = await new Promise<unknown>((resolve, reject) => client.GetElection({ ElectionId: electionId }, metadata,
      { deadline: Date.now() + 10_000 }, (error, response) => error ? reject(error) : resolve(response)));
    if (reply === null || typeof reply !== 'object' || (reply as Record<string, unknown>).Success !== true)
      throw new Error('Election authority unavailable');
    const safe = parseElectionScopedAccess((reply as Record<string, unknown>).ScopedAccess, electionId);
    // Project only closed scope; discard all other election/roster/report metadata.
    return { ElectionId: safe.electionId, SchemaVersion: 1, AllowedOperations: safe.allowedOperations, EntitlementReason: safe.reason ?? '' };
  } finally { client.close(); }
}
