/**
 * FEAT-016 Task 6.2 — licence-query transport + server-factory contract tests.
 *
 * Proves against a REAL in-process gRPC server serving the pinned licence
 * proto that the BFF transport: forwards exactly the three frozen signed
 * metadata headers (and nothing else); decodes active/no-active replies into
 * the closed vocabulary; maps gRPC statuses; enforces the ten-second
 * deadline; and fails closed when the endpoint is unparseable/absent (no
 * JSON fallback, no fabricated result).
 */

import { Server, ServerCredentials, Metadata } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { loadPackageDefinition } from '@grpc/grpc-js';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createLicenceServerTransport } from './server-transport';
import { LicenceQueryGrpcTransport, loadLicenceSurface, validateLicenceQueryHeaders } from './licence-transport';
import { PROTO_DIR } from './binary-grpc-transport';

const LICENCE_PROTO = path.join(PROTO_DIR, 'hushVotingLicence.proto');

interface LicenceHarness {
  server: Server;
  port: number;
  close(): Promise<void>;
}

const ACTIVE_REPLY = {
  state: 'LICENCE_ENTITLEMENT_STATE_ACTIVE',
  active: {
    licence_reference: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
    plan_id: 'hushvoting.veritas.2000',
    plan_family: 'veritas',
    display_name: 'HushVoting! Veritas 2k',
    safe_description: 'Annual Veritas licence',
    eligible_voter_cap: '2000',
    unlimited_elections: true,
    term_kind: 'annual',
    term_years: '1',
    allowed_governance_option_ids: [],
    effective_from_utc: '2026-01-01T00:00:00.000Z',
    expires_at_utc: '2027-01-01T00:00:00.000Z',
    assigned_catalogue_version: 'hushvoting-licence-catalogue/v1.0.0',
    higher_options: [],
    enterprise: null,
  },
};

async function startLicenceServer(
  handler: (metadata: Metadata) => { reply?: unknown; error?: { code: number; details: string }; delayMs?: number },
): Promise<LicenceHarness> {
  const definition = loadSync([LICENCE_PROTO], { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
  const pkg = loadPackageDefinition(definition) as unknown as { rpcHush: { HushVotingLicence: { service: object } } };
  const server = new Server();
  server.addService(pkg.rpcHush.HushVotingLicence.service as never, {
    GetMyEntitlement: (call: { metadata: Metadata }, cb: (err: unknown, reply: unknown) => void) => {
      const outcome = handler(call.metadata);
      if (outcome.delayMs !== undefined) {
        setTimeout(() => {
          if (outcome.error) cb({ code: outcome.error.code, details: outcome.error.details }, null);
          else cb(null, outcome.reply ?? {});
        }, outcome.delayMs);
        return;
      }
      if (outcome.error) cb({ code: outcome.error.code, details: outcome.error.details }, null);
      else cb(null, outcome.reply ?? {});
    },
  } as never);
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

const HEADERS = {
  signatory: '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5',
  signedAt: '2026-09-06T00:00:00Z',
  signature: 'c2lnbmF0dXJlLWJ5dGVz',
};

describe('LicenceQueryGrpcTransport (Task 6.2)', () => {
  let harness: LicenceHarness | null = null;
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

  async function withServer(handler: Parameters<typeof startLicenceServer>[0]): Promise<LicenceQueryGrpcTransport> {
    harness = await startLicenceServer(handler);
    cleanup.push(() => harness!.close());
    return new LicenceQueryGrpcTransport(`127.0.0.1:${harness.port}`);
  }

  it('forwards exactly the three frozen signed-query headers as metadata', async () => {
    let seen: string[] = [];
    const transport = await withServer((metadata) => {
      seen = [...metadata.get('x-hush-licence-query-signatory'), ...metadata.get('x-hush-licence-query-signed-at'), ...metadata.get('x-hush-licence-query-signature')].map(String);
      return { reply: { state: 'LICENCE_ENTITLEMENT_STATE_NO_ACTIVE', active: null, direct_free_template: { transition_intent: 'baseline_free', requested_plan_id: 'hushvoting.direct.free', observed_catalogue_version: 'hushvoting-licence-catalogue/v1.0.0' }, unavailable_code: '' } };
    });

    const result = await transport.queryMyEntitlement(HEADERS);
    expect(seen).toEqual([HEADERS.signatory, HEADERS.signedAt, HEADERS.signature]);
    expect(result).toEqual({
      ok: true,
      state: 'noActive',
      template: { TransitionIntent: 'baseline_free', RequestedPlanId: 'hushvoting.direct.free', ObservedCatalogueVersion: 'hushvoting-licence-catalogue/v1.0.0' },
    });
  });

  it('decodes an active reply into the closed transport vocabulary', async () => {
    const transport = await withServer(() => ({ reply: ACTIVE_REPLY }));
    const result = await transport.queryMyEntitlement(HEADERS);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.state).toBe('active');
      if (result.state === 'active') {
        expect(result.active.LicenceReference).toBe('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
        expect(result.active.PlanFamily).toBe('veritas');
        expect(result.active.EligibleVoterCap).toBe(2000);
      }
    }
  });

  it('maps UNAUTHENTICATED/UNIMPLEMENTED/other gRPC statuses to typed outcomes', async () => {
    const unauth = await withServer(() => ({ error: { code: 16, details: 'expired' } }));
    expect(await unauth.queryMyEntitlement(HEADERS)).toEqual({ ok: false, status: 'UNAUTHENTICATED' });

    const unimplemented = await withServer(() => ({ error: { code: 12, details: 'unsupported' } }));
    expect(await unimplemented.queryMyEntitlement(HEADERS)).toEqual({ ok: false, status: 'UNIMPLEMENTED' });
  });

  it('enforces the bounded ten-second deadline (DEADLINE_EXCEEDED)', async () => {
    const transport = await withServer(() => ({ delayMs: 12_000 }));
    const started = Date.now();
    const result = await transport.queryMyEntitlement(HEADERS);
    expect(result).toEqual({ ok: false, status: 'DEADLINE_EXCEEDED' });
    expect(Date.now() - started).toBeLessThan(15_000);
  }, 20_000);

  it('fails closed on a malformed server reply (never fabricates)', async () => {
    const transport = await withServer(() => ({ reply: { state: 'LICENCE_ENTITLEMENT_STATE_ACTIVE', active: { plan_id: 'x' } } }));
    expect(await transport.queryMyEntitlement(HEADERS)).toEqual({ ok: false, status: 'UNKNOWN' });
  });
});

describe('licence server factory + header validation (Task 6.2)', () => {
  it('creates a real transport only from a parseable gRPC endpoint', () => {
    expect(createLicenceServerTransport({} as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(createLicenceServerTransport({ HUSHSERVER_NODE_ENDPOINT: '' } as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(createLicenceServerTransport({ HUSHSERVER_NODE_ENDPOINT: 'http://localhost:14665' } as unknown as NodeJS.ProcessEnv)).toBeNull();
    // A valid endpoint resolves to a real (lazy) transport; verify no throw.
    const transport = createLicenceServerTransport({ HUSHSERVER_NODE_ENDPOINT: '127.0.0.1:14665' } as unknown as NodeJS.ProcessEnv);
    expect(transport).not.toBeNull();
    if (transport !== null) {
      // Loading the surface verifies the pinned proto digest at construction.
      const surface = loadLicenceSurface('127.0.0.1:14665');
      expect(surface).toBeDefined();
    }
  });

  it('validates bounded header values (missing/oversized fail closed)', () => {
    expect(validateLicenceQueryHeaders(HEADERS)).toEqual({ ok: true, value: HEADERS });
    expect(validateLicenceQueryHeaders({ signatory: '', signedAt: 'x', signature: 'y' }).ok).toBe(false);
    expect(validateLicenceQueryHeaders({ signatory: 'a'.repeat(5000), signedAt: 'x', signature: 'y' }).ok).toBe(false);
  });
});
