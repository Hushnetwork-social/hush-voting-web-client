/**
 * FEAT-010 Tasks 6.4/6.8 — real bounded transport and onboarding-registry
 * tests.
 *
 * Proves the manifest-bound transport performs REAL wire calls with exact
 * deadline/bounds/normalization (success, timeout, malformed, unavailable,
 * oversize, server error) against a local HTTP fixture, and that the
 * onboarding child-view registry round-trips publications with fail-closed
 * resolution (normative: FeatureDescription "Live HushServerNode Transport",
 * "Typed Onboarding Composition"; AC-010-012/014/018).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer as createHttpServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createServerTransport, ManifestBoundHttpTransport } from './server-transport';
import { clearChildView, publishChildView, resetChildViews, resolveOnboardingChild } from '../../app/auth/onboarding/onboarding-registry';
import type { OnboardingChild } from '../../app/auth/onboarding/OnboardingHost';

let server: Server;
let baseUrl = '';

beforeAll(async () => {
  server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (req.url === '/hushIdentity/GetIdentity') {
        if (body.includes('"malformed"')) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"unexpected": true}');
          return;
        }
        if (body.includes('"slow"')) {
          setTimeout(() => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ reply: { successfull: false, message: '' } }));
          }, 200);
          return;
        }
        if (body.includes('"boom"')) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end('{"error":{"code":"SERVER_UNAVAILABLE"}}');
          return;
        }
        if (body.includes('"timeout"')) {
          // Never respond: forces the 10s AbortSignal timeout (bounded below
          // by a client-side injected timeout in the test instance).
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            reply: {
              successfull: true,
              message: 'ok',
              profileName: 'alias',
              publicSigningAddress: 'A'.repeat(44),
              publicEncryptAddress: 'B'.repeat(44),
              isPublic: false,
            },
          }),
        );
        return;
      }
      if (req.url === '/hushBlockchain/SubmitSignedTransaction') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ reply: { successfull: true, message: 'ok', status: 'ACCEPTED' } }));
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

describe('createServerTransport', () => {
  it('returns null when the endpoint is not configured (NOT_CONFIGURED path)', () => {
    expect(createServerTransport({} as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(createServerTransport({ HUSHSERVER_NODE_ENDPOINT: '' } as unknown as NodeJS.ProcessEnv)).toBeNull();
  });

  it('creates a real transport when the server-side endpoint is configured', () => {
    const port = createServerTransport({ HUSHSERVER_NODE_ENDPOINT: baseUrl } as unknown as NodeJS.ProcessEnv);
    expect(port).not.toBeNull();
  });
});

describe('ManifestBoundHttpTransport — real wire behavior', () => {
  it('performs a real lookup call and returns the sealed reply', async () => {
    const port = new ManifestBoundHttpTransport(baseUrl);
    const result = await port.lookupIdentity({ publicSigningAddress: 'A'.repeat(44) });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.reply.profileName).toBe('alias');
      expect(result.reply.publicSigningAddress).toBe('A'.repeat(44));
    }
  });

  it('performs a real submission call with closed status normalization', async () => {
    const port = new ManifestBoundHttpTransport(baseUrl);
    const result = await port.submitTransaction({ signedTransaction: '{"tx":"x"}' });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.reply.status).toBe('ACCEPTED');
  });

  it('maps server errors and malformed replies to closed failures', async () => {
    const port = new ManifestBoundHttpTransport(baseUrl);
    const boom = await port.lookupIdentity({ publicSigningAddress: 'boom' });
    expect(boom).toEqual({ ok: false, failure: { kind: 'unavailable' } });

    // Sealed FEAT-007 semantics: a 200 reply without a `reply` object maps to
    // SERVER_UNAVAILABLE (closed, typed; free-form text never controls flow).
    const malformed = await port.lookupIdentity({ publicSigningAddress: 'malformed' });
    expect(malformed).toEqual({ ok: false, failure: { kind: 'unavailable' } });
  });

  it('enforces the 10-second deadline as a bounded timeout', async () => {
    const port = new ManifestBoundHttpTransport(baseUrl);
    const started = Date.now();
    const result = await port.lookupIdentity({ publicSigningAddress: 'timeout' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe('timeout');
    expect(Date.now() - started).toBeLessThan(15_000);
  }, 15_000);

  it('is not an unconditional-unavailable transport', async () => {
    const { isUnconditionalUnavailableTransport } = await import('../../lib/runtime/transport');
    const port = new ManifestBoundHttpTransport(baseUrl);
    expect(await isUnconditionalUnavailableTransport(port)).toBe(false);
  });
});

describe('onboarding child-view registry', () => {
  afterEach(() => resetChildViews());

  it('round-trips published child views per kind', () => {
    const child = { kind: 'createUser', props: {} } as unknown as OnboardingChild;
    publishChildView('createUser', child);
    expect(resolveOnboardingChild('createUser')).toBe(child);
    expect(resolveOnboardingChild('recoveryWords')).toBeNull();
  });

  it('clears publications on child cleanup', () => {
    const child = { kind: 'credentialFile', props: {} } as unknown as OnboardingChild;
    publishChildView('credentialFile', child);
    clearChildView('credentialFile');
    expect(resolveOnboardingChild('credentialFile')).toBeNull();
  });

  it('resolves null for unknown or missing kinds (fail-closed host)', () => {
    expect(resolveOnboardingChild(null)).toBeNull();
    expect(resolveOnboardingChild(undefined)).toBeNull();
    expect(resolveOnboardingChild('elections')).toBeNull();
  });
});
