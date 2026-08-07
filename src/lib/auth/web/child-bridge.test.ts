/**
 * FEAT-010 Task 7.3 — onboarding child-bridge port tests.
 *
 * Proves `confirmMissingProfile` (AC-010-038/039) forwards the REAL safe
 * candidate (alias + abbreviated signing address) carried by the worker's
 * PROFILE_MISSING outcome payload instead of fabricating a placeholder on a
 * security-relevant confirmation surface. Unknown payloads still fail
 * closed with the safe fallback, never a fabricated identity.
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { BrowserVaultClient, type MessagePortLike } from '../../browser-vault/production/client';
import { createWebOnboardingPorts, mapCredentialImportFailure } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import type { DeploymentManifest } from '../../runtime/deployment';

/** Fake port that records outbound messages and lets tests push events. */
class FakePort implements MessagePortLike {
  readonly sent: unknown[] = [];
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;

  postMessage(message: unknown): void {
    this.sent.push(message);
  }

  push(data: unknown): void {
    this.onmessage?.({ data });
  }
}

let idCounter = 0;

function createClient(port: FakePort): BrowserVaultClient {
  return new BrowserVaultClient({
    workerUrl: '/workers/vault-shared-worker.js',
    appIdentity: { appVersion: '0.1.0' },
    runtimeConfigId: 'development-localhost',
    randomId: (prefix) => {
      idCounter += 1;
      return `${prefix}-fixed-${idCounter}`;
    },
    workerFactory: () => ({ port }),
  });
}

/** Wait for the next operation message (dispatch is async after connect). */
async function waitForOperation(port: FakePort): Promise<{ operationId?: string } | undefined> {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const last = port.sent.at(-1) as { kind?: string; operationId?: string } | undefined;
    if (last !== undefined && last.kind === 'operation') {
      return last;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return undefined;
}

/** Resolve the client channel from the sent handshake. */
function sentChannel(port: FakePort): string {
  const handshake = port.sent.find((m) => (m as { kind?: string }).kind === 'handshake') as { clientChannel?: string } | undefined;
  return handshake?.clientChannel ?? 'chan-fixed';
}

/** Prime the client: handshake accepted + capability issued (client.test.ts pattern). */
async function primeClient(port: FakePort, client: BrowserVaultClient): Promise<void> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    if (String(input).includes('vault-shared-worker.js')) {
      return new Response('export const x = 1;', { status: 200, headers: { 'content-type': 'text/javascript' } });
    }
    return originalFetch(input);
  }) as typeof fetch;
  const promise = client.connect();
  let handshake: { clientChannel?: string } | undefined;
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    handshake = port.sent.find((m) => (m as { kind?: string }).kind === 'handshake') as { clientChannel?: string } | undefined;
    if (handshake !== undefined) break;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  if (handshake === undefined) {
    globalThis.fetch = originalFetch;
    throw new Error('handshake never posted');
  }
  port.push({ kind: 'handshake-accepted', protocolVersion: 2, appVersion: '0.1.0', buildDigest: '0123456789ab', clientChannel: handshake.clientChannel, authorityEpoch: 1, operationId: 'op-', session: { state: 'noLocalUser' } });
  const outcome = await Promise.race([promise.then((r) => ({ ok: true as const, r })), new Promise<{ ok: false }>((resolve) => setTimeout(() => resolve({ ok: false }), 2000))]);
  if (!outcome.ok) {
    globalThis.fetch = originalFetch;
    throw new Error('connect never resolved');
  }
  globalThis.fetch = originalFetch;
}

beforeEach(() => {
  idCounter = 0;
});

describe('credential import diagnostics', () => {
  it('maps closed compatibility reasons without parsing free-form messages', () => {
    expect(mapCredentialImportFailure('INVALID_INPUT', { reason: 'DAT_UNKNOWN_FIELD' })).toBe('PAYLOAD_UNKNOWN_FIELD');
    expect(mapCredentialImportFailure('INVALID_INPUT', { reason: 'DAT_KEY_MISMATCH' })).toBe('KEY_PROOF_FAILED');
    expect(mapCredentialImportFailure('WRONG_PASSWORD_OR_DAMAGED', undefined)).toBe('AUTHENTICATION_FAILED');
    expect(mapCredentialImportFailure('INVALID_INPUT', { reason: 'a filename or secret value' })).toBe('UNKNOWN_OUTCOME');
  });
});

describe('FEAT-010 child-bridge confirmMissingProfile', () => {
  it('forwards the real safe candidate from the PROFILE_MISSING payload', async () => {
    const port = new FakePort();
    const client = createClient(port);
    await primeClient(port, client);
    const ports = createWebOnboardingPorts({
      client,
      manifest: ISOLATED_DEVNET_MANIFEST as DeploymentManifest,
      lookupIdentity: async () => ({ kind: 'transportFailure' }),
      randomId: (prefix) => `${prefix}-rnd`,
    });

    const op = ports.createUser.confirmMissingProfile(1 as never);
    const operation = await waitForOperation(port);
    port.push({
      kind: 'operation-outcome',
      operationId: operation?.operationId,
      clientChannel: sentChannel(port),
      outcome: 'PROFILE_MISSING',
      retryable: false,
      allowedActions: ['createOrRestore'],
      payload: { alias: 'Alice', abbreviatedSigningAddress: '01234567…89abcd' },
    });
    const result = await op.result;
    expect(result.code).toBe('VERIFY_PROFILE_MISSING');
    if (result.code === 'VERIFY_PROFILE_MISSING') {
      expect(result.safeCandidate.alias).toBe('Alice');
      expect(result.safeCandidate.abbreviatedSigningAddress).toBe('01234567…89abcd');
    }
  });

  it('fails closed with the safe fallback when the payload is not a safe candidate', async () => {
    const port = new FakePort();
    const client = createClient(port);
    await primeClient(port, client);
    const ports = createWebOnboardingPorts({
      client,
      manifest: ISOLATED_DEVNET_MANIFEST as DeploymentManifest,
      lookupIdentity: async () => ({ kind: 'transportFailure' }),
      randomId: (prefix) => `${prefix}-rnd`,
    });

    const op = ports.createUser.confirmMissingProfile(1 as never);
    const operation = await waitForOperation(port);
    port.push({
      kind: 'operation-outcome',
      operationId: operation?.operationId,
      clientChannel: sentChannel(port),
      outcome: 'PROFILE_MISSING',
      retryable: false,
      allowedActions: ['createOrRestore'],
      payload: { unrelated: 'junk' },
    });
    const result = await op.result;
    expect(result.code).toBe('VERIFY_PROFILE_MISSING');
    if (result.code === 'VERIFY_PROFILE_MISSING') {
      // Never a fabricated identity: an unrecognized payload maps to the safe
      // generic placeholder, not to any concrete-looking alias.
      expect(result.safeCandidate.alias).toBe('Unknown');
      expect(result.safeCandidate.abbreviatedSigningAddress).toBe('…');
    }
  });
});
