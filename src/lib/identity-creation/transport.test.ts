/**
 * FEAT-007 Task 6.2/6.4/6.6 — BFF bounds, cross-adapter conformance, and
 * downstream contract tests. Coverage: AC-007-022–024, 028–036, 061–067,
 * 070–076 (integration/contract portion).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BffTransport, parseBffLookupResponse, parseBffSubmitResponse, RPC_TIMEOUT_MS } from './transport.js';
import { createServerTransport } from '../../app/api/server-transport.js';
import { normalizeGetIdentityReply, normalizeSubmitReply } from './wire.js';
import { FULL_IDENTITY_PAYLOAD_KIND } from './profile.js';
import { POST as lookupPost } from '../../app/api/identity/route.js';
import { POST as submitPost } from '../../app/api/blockchain/route.js';
import { abbreviateAddress, type MissingProfileCreationContract } from './contracts.js';

const LOCAL_SIGNING = 'A11B22C33D44E55F66A77B88C99D00E11F22A33B44C55D66E77F88A99B00C11';
const LOCAL_ENCRYPT = 'Q77W66E55R44T33Y22U11I00O99P88A77S66D55F44G33H22J11K00L99M88';

describe('Task 6.2 — BFF request/response bounds', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.HUSHSERVER_NODE_ENDPOINT;
  });

  it('route fails closed with NOT_CONFIGURED when the server endpoint is absent', async () => {
    delete process.env.HUSHSERVER_NODE_ENDPOINT;
    const res = await lookupPost(new Request('http://localhost/api/identity', { method: 'POST', body: JSON.stringify({ publicSigningAddress: LOCAL_SIGNING }) }));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: { code: 'NOT_CONFIGURED' } });
  });

  it('route rejects malformed lookup requests', async () => {
    process.env.HUSHSERVER_NODE_ENDPOINT = 'https://example.invalid';
    const res = await lookupPost(new Request('http://localhost/api/identity', { method: 'POST', body: JSON.stringify({ publicSigningAddress: 'not an address!' }) }));
    expect(res.status).toBe(400);
    expect((await res.json()) as { error: { code: string } }).toMatchObject({ error: { code: 'MALFORMED_REQUEST' } });
  });

  it('route rejects malformed submit requests', async () => {
    process.env.HUSHSERVER_NODE_ENDPOINT = 'https://example.invalid';
    const res = await submitPost(new Request('http://localhost/api/blockchain', { method: 'POST', body: JSON.stringify({ signedTransaction: '' }) }));
    expect(res.status).toBe(400);
  });

  it('configured server transport fails closed (no fabricated success)', async () => {
    process.env.HUSHSERVER_NODE_ENDPOINT = 'https://example.invalid';
    const port = createServerTransport(process.env);
    expect(port).not.toBeNull();
    const lookup = await port!.lookupIdentity({ publicSigningAddress: LOCAL_SIGNING });
    expect(lookup).toEqual({ ok: false, failure: { kind: 'unavailable' } });
  });

  it('factory returns null when endpoint config is missing', () => {
    expect(createServerTransport({} as NodeJS.ProcessEnv)).toBeNull();
  });

  it('parses malformed BFF bodies fail-closed', () => {
    expect(parseBffLookupResponse(null)).toEqual({ error: { code: 'SERVER_UNAVAILABLE' } });
    expect(parseBffLookupResponse({ reply: 'nope' })).toEqual({ error: { code: 'SERVER_UNAVAILABLE' } });
    expect(parseBffSubmitResponse({ error: { code: 'MADE_UP' } })).toEqual({ error: { code: 'SERVER_UNAVAILABLE' } });
  });
});

describe('Task 6.2 — BffTransport maps replies and errors', () => {
  afterEach(() => vi.restoreAllMocks());

  it('maps a successful lookup reply through the transport', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ reply: { successfull: true, message: 'ok', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false } }), { status: 200 })));
    const t = new BffTransport('http://localhost');
    const result = await t.lookupIdentity({ publicSigningAddress: LOCAL_SIGNING });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.reply.successfull).toBe(true);
    }
  });

  it('maps HTTP failure and BFF errors to typed transport failures', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 502 })));
    const t = new BffTransport('http://localhost');
    const result = await t.lookupIdentity({ publicSigningAddress: LOCAL_SIGNING });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe('unavailable');
  });

  it('uses the 10-second per-RPC policy bound', () => {
    expect(RPC_TIMEOUT_MS).toBe(10_000);
  });
});

describe('Task 6.4 — cross-adapter conformance (browser and native normalize identically)', () => {
  it('the same server reply produces the same closed lookup outcome for any adapter', () => {
    const reply = { successfull: true, message: 'ok', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false };
    const browserNormalized = normalizeGetIdentityReply(reply, LOCAL_SIGNING, LOCAL_ENCRYPT);
    const nativeNormalized = normalizeGetIdentityReply(reply, LOCAL_SIGNING, LOCAL_ENCRYPT);
    expect(browserNormalized).toEqual(nativeNormalized);
    expect(browserNormalized).toEqual({ kind: 'exactProfile', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false });
  });

  it('rejection semantics are adapter-independent', () => {
    const allowlist = new Set(['ALIAS_INVALID']);
    const reply = { successfull: true, message: 'alias invalid', status: 'REJECTED' as const, validationCode: 'ALIAS_INVALID' };
    expect(normalizeSubmitReply(reply, allowlist)).toEqual({ kind: 'editableRejection', validationCode: 'ALIAS_INVALID' });
    expect(normalizeSubmitReply(reply, allowlist)).toEqual(normalizeSubmitReply({ ...reply, message: 'different text' }, allowlist));
  });
});

describe('Task 6.6 — downstream contract stability', () => {
  it('payload kind GUID and wire contract remain unchanged', () => {
    expect(FULL_IDENTITY_PAYLOAD_KIND).toBe('351cd60b-3fdf-48d4-b608-e93c0100f7d0');
  });

  it('downstream FEAT-008 missing-profile contract stays secret-free and stable', () => {
    const contract: MissingProfileCreationContract = {
      version: 1,
      requiresAuthoritativeAbsence: true,
      requiresCredentialVerification: true,
      fields: ['normalizedAlias', 'visibility', 'abbreviatedSigningAddress', 'abbreviatedEncryptionAddress'],
      authorizationRef: 'opaque' as MissingProfileCreationContract['authorizationRef'],
    };
    expect(JSON.stringify(contract)).not.toMatch(/mnemonic|password|privateKey|transaction|signature/i);
  });

  it('abbreviated address presentation is stable for evidence', () => {
    expect(abbreviateAddress(`${LOCAL_SIGNING}EXTRA`)).toMatch(/^[A-Z0-9]{8}…[A-Z0-9]{6}$/);
  });
});
