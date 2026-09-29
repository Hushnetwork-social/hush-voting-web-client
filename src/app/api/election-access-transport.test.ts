import { Server, ServerCredentials, Metadata, loadPackageDefinition } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PROTO_DIR } from './binary-grpc-transport';
import { queryElectionAccess } from './election-access-transport';
import { POST } from './election-access/route';
import { ELECTION_QUERY_HEADERS } from '../../lib/elections/query';

const electionId = '11111111-2222-4333-8444-555555555555';
const signed = { signatory: 'public-test-signatory', signedAt: '2026-09-29T10:00:00Z', signature: 'test-signed-envelope' };
// Real binary gRPC + BFF route; signature verification belongs to the actual node,
// covered by its signed-query tests. No server module/route/transport is mocked here.
describe('captured access BFF App Twin (AC-018-007/008/009, T018-4-02)', () => {
  let server: Server | undefined;
  afterEach(async () => { vi.unstubAllEnvs(); if (server) await new Promise<void>(resolve => server!.tryShutdown(() => resolve())); server = undefined; });
  async function start(reply: object, inspect?: (request: { ElectionId: string }, metadata: Metadata) => void) {
    const definition = loadSync(path.join(PROTO_DIR, 'hushElections.proto'), { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
    const pkg = loadPackageDefinition(definition) as unknown as { rpcHush: { HushElections: { service: object } } };
    server = new Server();
    server.addService(pkg.rpcHush.HushElections.service as never, { GetElection: (
      call: { request: { ElectionId: string }; metadata: Metadata }, done: (error: unknown, value: object) => void,
    ) => { inspect?.(call.request, call.metadata); done(null, reply); } } as never);
    const port = await new Promise<number>((resolve, reject) => server!.bindAsync('127.0.0.1:0', ServerCredentials.createInsecure(),
      (error, bound) => error ? reject(error) : resolve(bound)));
    return `127.0.0.1:${port}`;
  }
  function request(body: string) {
    return new Request('http://localhost/api/election-access', { method: 'POST', body, headers: {
      'content-type': 'application/json', [ELECTION_QUERY_HEADERS[0]]: signed.signatory,
      [ELECTION_QUERY_HEADERS[1]]: signed.signedAt, [ELECTION_QUERY_HEADERS[2]]: signed.signature,
    } });
  }
  it('forwards existing signed metadata and emits only the closed non-cached scope', async () => {
    let received: unknown;
    const endpoint = await start({ Success: true, Title: 'Must not reach client', Owner: 'Not a scope field',
      ScopedAccess: { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: ['vote'], EntitlementReason: '' } },
    (req, metadata) => { received = { req, headers: ELECTION_QUERY_HEADERS.map(name => metadata.get(name)[0]) }; });
    vi.stubEnv('HUSHSERVER_NODE_ENDPOINT', endpoint);
    const response = await POST(request(JSON.stringify({ electionId })));
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toContain('no-store');
    expect(received).toEqual({ req: { ElectionId: electionId }, headers: Object.values(signed) });
    expect(await response.json()).toEqual({ scope: { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: ['vote'], EntitlementReason: '' } });
  });
  it('fails closed on a different election or an older server lacking scope', async () => {
    const endpoint = await start({ Success: true });
    expect(await queryElectionAccess(electionId, signed, endpoint)).toEqual({ ElectionId: electionId, SchemaVersion: 1,
      AllowedOperations: [], EntitlementReason: 'ENTITLEMENT_SEMANTICS_UNSUPPORTED' });
  });
  it('refuses caller-selected extra fields and missing signed metadata', async () => {
    const response = await POST(request(JSON.stringify({ electionId, actorAddress: 'other' })));
    expect(response.status).toBe(400);
    expect((await POST(new Request('http://localhost/api/election-access', { method: 'POST', body: '{}' }))).status).toBe(400);
  });
});
