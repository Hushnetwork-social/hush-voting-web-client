/**
 * FEAT-011 Task 6.2 — binary gRPC transport tests against a real in-process
 * gRPC server serving the pinned protos: exact fields/status/codes, deadline,
 * malformed/unknown enum, oversize, endpoint parsing, proto pin verification.
 */

import { Server, ServerCredentials } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { loadPackageDefinition } from '@grpc/grpc-js';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  BinaryGrpcTransport,
  PINNED_PROTO_DIGESTS,
  grpcErrorToFailure,
  parseGrpcEndpoint,
  verifyPinnedProtos,
  PROTO_DIR,
} from './binary-grpc-transport';
import type { LookupTransportResult } from '../../lib/identity-creation/transport';

interface TestServer {
  server: Server;
  port: number;
  close(): Promise<void>;
}

const PROTO_FILES = [path.join(PROTO_DIR, 'hushIdentity.proto'), path.join(PROTO_DIR, 'hushBlockchain.proto')];

/** Start an in-process gRPC server with the pinned protos and given handlers. */
async function startTestServer(handlers: {
  getIdentity: (call: { request: { PublicSigningAddress: string } }, cb: (err: unknown, reply: object | null) => void) => void;
  submit: (call: { request: { SignedTransaction: string } }, cb: (err: unknown, reply: object | null) => void) => void;
}): Promise<TestServer> {
  const definition = loadSync(PROTO_FILES, { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
  const pkg = loadPackageDefinition(definition) as unknown as {
    rpcHush: { HushIdentity: { service: object }; HushBlockchain: { service: object } };
  };
  const server = new Server();
  server.addService(pkg.rpcHush.HushIdentity.service as never, { GetIdentity: handlers.getIdentity } as never);
  server.addService(pkg.rpcHush.HushBlockchain.service as never, { SubmitSignedTransaction: handlers.submit } as never);
  const port = await new Promise<number>((resolve, reject) =>
    server.bindAsync('127.0.0.1:0', ServerCredentials.createInsecure(), (error, boundPort) => (error ? reject(error) : resolve(boundPort))),
  );
  return {
    server,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.tryShutdown(() => resolve());
      }),
  };
}

describe('binary gRPC transport (Task 6.2)', () => {
  let harness: TestServer | null = null;
  const cleanup: Array<() => Promise<void>> = [];

  afterEach(async () => {
    for (const fn of cleanup.splice(0)) {
      await fn();
    }
    if (harness !== null) {
      await harness.close();
      harness = null;
    }
  });

  async function withServer(handlers: TestServer extends never ? never : Parameters<typeof startTestServer>[0]) {
    harness = await startTestServer(handlers);
    cleanup.push(() => harness!.close());
    return new BinaryGrpcTransport(`127.0.0.1:${harness.port}`);
  }

  it('returns the exact identity fields over binary gRPC', async () => {
    const transport = await withServer({
      getIdentity: (call, cb) =>
        cb(null, {
          Successfull: true,
          Message: '',
          ProfileName: 'alice',
          PublicSigningAddress: call.request.PublicSigningAddress,
          PublicEncryptAddress: 'ENC-ADDR',
          IsPublic: true,
        }),
      submit: (call, cb) => cb(null, { Successfull: true, Message: 'ok', status: 'TRANSACTION_STATUS_ACCEPTED', ValidationCode: '' }),
    });

    const result = await transport.lookupIdentity({ publicSigningAddress: 'SIG-ADDR' });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.reply.successfull).toBe(true);
      expect(result.reply.profileName).toBe('alice');
      expect(result.reply.publicSigningAddress).toBe('SIG-ADDR');
      expect(result.reply.publicEncryptAddress).toBe('ENC-ADDR');
      expect(result.reply.isPublic).toBe(true);
    }
  });

  it('maps the not-found contract and structured submit status/code', async () => {
    const transport = await withServer({
      getIdentity: (call, cb) => cb(null, { Successfull: false, Message: 'Identity not found in the Blockchain' }),
      submit: (call, cb) => cb(null, { Successfull: true, Message: 'pending', status: 'TRANSACTION_STATUS_PENDING', ValidationCode: '' }),
    });

    const lookup = await transport.lookupIdentity({ publicSigningAddress: 'X' });
    expect(lookup.ok && lookup.reply.successfull === false).toBe(true);

    const submit = await transport.submitTransaction({ signedTransaction: '{}' });
    expect(submit.ok).toBe(true);
    if (submit.ok) {
      expect(submit.reply.status).toBe('PENDING');
    }
  });

  it('rejects unknown status enums as closed Unspecified (never fabricated)', async () => {
    const transport = await withServer({
      getIdentity: (call, cb) => cb(null, { Successfull: false }),
      submit: (call, cb) => cb(null, { Successfull: true, Message: '', status: 'BogusEnum', ValidationCode: '' }),
    });

    const submit = await transport.submitTransaction({ signedTransaction: '{}' });
    expect(submit.ok).toBe(true);
    if (submit.ok) {
      expect(submit.reply.status).toBe('UNSPECIFIED');
    }
  });

  it('maps deadline exhaustion to timeout (closed outcome, never absence)', async () => {
    const transport = await withServer({
      getIdentity: (call, cb) => {
        // Exceeds the transport's 10-second deadline (RPC_TIMEOUT_MS).
        setTimeout(() => cb(null, { Successfull: true }), 12_000);
      },
      submit: (call, cb) => cb(null, { Successfull: true, status: 'TRANSACTION_STATUS_ACCEPTED' }),
    });

    const result = await transport.lookupIdentity({ publicSigningAddress: 'X' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
    }
  }, 25_000);

  it('maps INVALID_ARGUMENT to protocol (defect, never absence)', async () => {
    const transport = await withServer({
      getIdentity: (call, cb) => cb({ code: 3, details: 'invalid' }, null),
      submit: (call, cb) => cb(null, { Successfull: true, status: 'TRANSACTION_STATUS_ACCEPTED' }),
    });

    const result = await transport.lookupIdentity({ publicSigningAddress: 'X' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('protocol');
    }
  });

  it('rejects oversize submit bodies as malformed before the wire', async () => {
    const transport = await withServer({
      getIdentity: (call, cb) => cb(null, { Successfull: false }),
      submit: (call, cb) => cb(null, { Successfull: true, status: 'TRANSACTION_STATUS_ACCEPTED' }),
    });

    const result = await transport.submitTransaction({ signedTransaction: 'x'.repeat(65_537) });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('malformed');
    }
  });

  it('parseGrpcEndpoint accepts host:port and fails closed otherwise', () => {
    expect(parseGrpcEndpoint('127.0.0.1:14665')).toBe('127.0.0.1:14665');
    expect(parseGrpcEndpoint('localhost:10332')).toBe('localhost:10332');
    expect(parseGrpcEndpoint(undefined)).toBeNull();
    expect(parseGrpcEndpoint('')).toBeNull();
    expect(parseGrpcEndpoint('http://localhost:14665')).toBeNull();
    expect(parseGrpcEndpoint('host:0')).toBeNull();
    expect(parseGrpcEndpoint('host:999999')).toBeNull();
  });

  it('verifies the pinned proto digests and rejects tampering', () => {
    expect(() => verifyPinnedProtos()).not.toThrow();
    const original = PINNED_PROTO_DIGESTS['hushIdentity.proto'];
    (PINNED_PROTO_DIGESTS as Record<string, string>)['hushIdentity.proto'] = 'deadbeef';
    expect(() => verifyPinnedProtos()).toThrow(/digest mismatch/);
    (PINNED_PROTO_DIGESTS as Record<string, string>)['hushIdentity.proto'] = original;
    expect(() => verifyPinnedProtos()).not.toThrow();
  });

  it('grpcErrorToFailure maps every transport error class to a closed kind', () => {
    expect(grpcErrorToFailure({ code: 4 })).toEqual({ kind: 'timeout' });
    expect(grpcErrorToFailure({ code: 1 })).toEqual({ kind: 'canceled' });
    expect(grpcErrorToFailure({ code: 3 })).toEqual({ kind: 'protocol' });
    expect(grpcErrorToFailure({ code: 12 })).toEqual({ kind: 'protocol' });
    expect(grpcErrorToFailure({ code: 14 })).toEqual({ kind: 'unavailable' });
    expect(grpcErrorToFailure({ code: 2 })).toEqual({ kind: 'unavailable' });
  });
});
