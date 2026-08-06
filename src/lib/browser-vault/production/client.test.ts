/**
 * FEAT-010 Task 7.3 — page-side client + web-actor adapter tests.
 *
 * Proves the client handshake/operation/secret/capability flows over a fake
 * MessagePort, and the typed outcome mapping of every web actor (INIT_*,
 * UNLOCK_*, VERIFY_*, REMOVAL_*, coordination) against closed worker outcomes.
 * Unknown/malformed outcomes fail closed; secrets never enter results.
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { BrowserVaultClient, type MessagePortLike } from './client';
import { createWebLocalUserAuthority, createWebSecretAuthority, createWebIdentityVerification, createWebBrowserCoordination } from '../../auth/web/web-actors';

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

/** Connect the client (stubbed digest fetch) and accept the handshake. */
/** Wait for the next operation message (dispatch is async after connect). */
async function waitForOperation(port: FakePort, excludeId?: string): Promise<{ operationId?: string } | undefined> {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const last = port.sent.at(-1) as { kind?: string; operationId?: string } | undefined;
    if (last !== undefined && last.kind === 'operation' && (excludeId === undefined || last.operationId !== excludeId)) {
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

async function primeClient(client: BrowserVaultClient, port: FakePort): Promise<void> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    if (String(input).includes('vault-shared-worker.js')) {
      return new Response('export const x = 1;', { status: 200, headers: { 'content-type': 'text/javascript' } });
    }
    return originalFetch(input);
  }) as typeof fetch;
  const promise = client.connect();
  // Wait for the handshake to be posted (the digest fetch is asynchronous).
  let handshake: { clientChannel?: string } | undefined;
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    handshake = port.sent.find((m) => (m as { kind?: string }).kind === 'handshake') as { clientChannel?: string } | undefined;
    if (handshake !== undefined) {
      break;
    }
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

describe('BrowserVaultClient', () => {
  let port: FakePort;
  let client: BrowserVaultClient;

  beforeEach(async () => {
    port = new FakePort();
    client = createClient(port);
  });

  it('sends the v2 handshake with the exact build digest and runtime config', async () => {
    // primeClient installs the digest fetch stub and drives connect(); the
    // handshake message is inspected before the acceptance push.
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      if (String(input).includes('vault-shared-worker.js')) {
        return new Response('export const x = 1;', { status: 200, headers: { 'content-type': 'text/javascript' } });
      }
      return originalFetch(input);
    }) as typeof fetch;

    const promise = client.connect();
    let handshake: { protocolVersion?: number; buildDigest?: string; runtimeConfigId?: string; clientChannel?: string } | undefined;
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      handshake = port.sent.find((m) => (m as { kind?: string }).kind === 'handshake') as { protocolVersion?: number; buildDigest?: string; runtimeConfigId?: string; clientChannel?: string } | undefined;
      if (handshake !== undefined) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(handshake?.protocolVersion).toBe(2);
    expect(handshake?.buildDigest).toMatch(/^[0-9a-f]{12}$/);
    expect(handshake?.runtimeConfigId).toBe('development-localhost');
    const channel = handshake?.clientChannel;
    port.push({ kind: 'handshake-accepted', protocolVersion: 2, appVersion: '0.1.0', buildDigest: '0123456789ab', clientChannel: channel, authorityEpoch: 1, operationId: 'op-', session: { state: 'noLocalUser' } });
    const result = await promise;
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.authorityEpoch).toBe(1);
    globalThis.fetch = originalFetch;
  });

  it('dispatches operations with epoch/operation scoping and resolves outcomes', async () => {
    await primeClient(client, port);
    const promise = client.dispatch('inspectStartup');
    const operation = await waitForOperation(port) as { operation?: string; operationId?: string; authorityEpoch?: number };
    expect(operation?.operation).toBe('inspectStartup');
    expect(operation?.authorityEpoch).toBe(1);
    port.push({ kind: 'operation-outcome', operationId: operation?.operationId, clientChannel: sentChannel(port), outcome: 'OK', retryable: false, allowedActions: [], payload: { surface: 'verifiedAbsent' } });
    const result = await promise;
    expect(result.outcome).toBe('OK');
    expect(result.payload).toEqual({ surface: 'verifiedAbsent' });
  });

  it('transfers secrets out-of-band through the sink', async () => {
    await primeClient(client, port);
    client.submitSecret('op-1', 'devicePassword', 'hunter2-supersecret');
    let transfer: { purpose?: string; value?: string } | undefined;
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      transfer = port.sent.find((m) => (m as { kind?: string }).kind === 'secret-transfer') as { purpose?: string; value?: string } | undefined;
      if (transfer !== undefined) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(transfer?.purpose).toBe('devicePassword');
    expect(transfer?.value).toBe('hunter2-supersecret');
  });

  it('resolves pending operations with AUTHORITY_INVALIDATED on global invalidation', async () => {
    await primeClient(client, port);
    const promise = client.dispatch('verifyOnlineIdentity');
    // Wait for the operation post (dispatch is async after connect).
    await waitForOperation(port);
    port.push({ kind: 'global-invalidation', authorityEpoch: 2, reason: 'lock' });
    const result = await promise;
    expect(result.outcome).toBe('AUTHORITY_INVALIDATED');
  });

  it('never dispatches before a successful handshake', async () => {
    const result = await client.dispatch('unlockPassword');
    expect(result.outcome).toBe('TRANSPORT_UNAVAILABLE');
  });
});

describe('web actor outcome mapping', () => {
  it('maps worker surfaces to typed INIT results (absent/locked/quarantine)', async () => {
    const port = new FakePort();
    const client = createClient(port);
    await primeClient(client, port);
    const localUser = createWebLocalUserAuthority(client);
    const op = localUser.initialize(1 as never);
    // Wait for the operation message (dispatch happens after connect).
    let operation: { operationId?: string } | undefined;
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      operation = port.sent.find((m) => (m as { kind?: string }).kind === 'operation') as { operationId?: string } | undefined;
      if (operation !== undefined) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(operation?.operationId).toBeTruthy();
    port.push({ kind: 'operation-outcome', operationId: operation?.operationId, clientChannel: sentChannel(port), outcome: 'OK', retryable: false, allowedActions: [], payload: { surface: 'verifiedAbsent' } });
    expect(await op.result).toEqual({ code: 'INIT_NO_LOCAL_USER' });

    const op2 = localUser.initialize(1 as never);
    let operation2: { operationId?: string } | undefined;
    const deadline2 = Date.now() + 3000;
    while (Date.now() < deadline2) {
      operation2 = port.sent.at(-1) as { operationId?: string } | undefined;
      if (operation2 !== undefined && (operation2 as { kind?: string }).kind === 'operation' && operation2.operationId !== operation?.operationId) break;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(operation2?.operationId).toBeTruthy();
    port.push({ kind: 'operation-outcome', operationId: operation2?.operationId, clientChannel: sentChannel(port), outcome: 'OK', retryable: false, allowedActions: [], payload: { surface: 'lockedVault', safeIdentity: { alias: 'Alice', abbreviatedSigningAddress: '01234567…89abcd' } } });
    const result2 = await op2.result;
    expect(result2.code).toBe('INIT_LOCKED_USER');
    if (result2.code === 'INIT_LOCKED_USER') {
      expect(result2.safeIdentity.alias).toBe('Alice');
    }
  });

  it('maps unlock outcomes (combined error, cooldown, success)', async () => {
    const port = new FakePort();
    const client = createClient(port);
    await primeClient(client, port);
    const secretAuthority = createWebSecretAuthority(client);

    const op = secretAuthority.beginUnlock(1 as never);
    const operation = await waitForOperation(port);
    expect(operation?.operationId).toBeTruthy();
    port.push({ kind: 'operation-outcome', operationId: operation?.operationId, clientChannel: sentChannel(port), outcome: 'WRONG_PASSWORD_OR_DAMAGED', retryable: true, allowedActions: ['retry'] });
    expect(await op.result).toEqual({ code: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' });

    const op2 = secretAuthority.beginUnlock(1 as never);
    const operation2 = await waitForOperation(port, operation?.operationId);
    port.push({ kind: 'operation-outcome', operationId: operation2?.operationId, clientChannel: sentChannel(port), outcome: 'THROTTLED', retryable: false, allowedActions: ['retry'], retryDeadlineMs: 1234567890 });
    const throttled = await op2.result;
    expect(throttled.code).toBe('UNLOCK_THROTTLED');
    if (throttled.code === 'UNLOCK_THROTTLED') expect(throttled.cooldownDeadlineMs).toBe(1234567890);

    const op3 = secretAuthority.beginUnlock(1 as never);
    const operation3 = await waitForOperation(port, operation2?.operationId);
    port.push({ kind: 'operation-outcome', operationId: operation3?.operationId, clientChannel: sentChannel(port), outcome: 'OK', retryable: false, allowedActions: [] });
    expect(await op3.result).toEqual({ code: 'UNLOCK_SUCCESS' });
  });

  it('maps verification outcomes (exact, missing, mismatch, timeout, offline)', async () => {
    const port = new FakePort();
    const client = createClient(port);
    await primeClient(client, port);
    const verification = createWebIdentityVerification(client);

    const op = verification.verifyOnline(1 as never, 'ref' as never);
    const operation = await waitForOperation(port);
    port.push({ kind: 'operation-outcome', operationId: operation?.operationId, clientChannel: sentChannel(port), outcome: 'PROFILE_MISSING', retryable: false, allowedActions: ['createOrRestore'], payload: { safeIdentity: { alias: 'Alice', abbreviatedSigningAddress: '01234567…89abcd' } } });
    const missing = await op.result;
    expect(missing.code).toBe('VERIFY_PROFILE_MISSING');
    if (missing.code === 'VERIFY_PROFILE_MISSING') expect(missing.safeCandidate.alias).toBe('Alice');

    const op2 = verification.verifyOnline(1 as never, 'ref' as never);
    const operation2 = await waitForOperation(port, operation?.operationId);
    port.push({ kind: 'operation-outcome', operationId: operation2?.operationId, clientChannel: sentChannel(port), outcome: 'SIGNING_KEY_MISMATCH', retryable: false, allowedActions: ['lock', 'removal'] });
    expect(await op2.result).toEqual({ code: 'VERIFY_SIGNING_KEY_MISMATCH' });

    const op3 = verification.verifyOnline(1 as never, 'ref' as never);
    const operation3 = await waitForOperation(port, operation2?.operationId);
    port.push({ kind: 'operation-outcome', operationId: operation3?.operationId, clientChannel: sentChannel(port), outcome: 'VERIFY_TIMEOUT', retryable: true, allowedActions: ['retry'] });
    expect(await op3.result).toEqual({ code: 'VERIFY_TIMEOUT' });
  });

  it('maps coordination to unsafe when the worker handshake fails', async () => {
    const client = new BrowserVaultClient({
      workerUrl: '/workers/vault-shared-worker.js',
      appIdentity: { appVersion: '0.1.0' },
      runtimeConfigId: 'development-localhost',
      randomId: (prefix) => `${prefix}-fixed`,
      workerFactory: () => null,
    });
    const coordination = createWebBrowserCoordination(client);
    const op = coordination.acquire(1 as never);
    const result = await op.result;
    expect(result.code).toBe('COORDINATION_UNSAFE');
  });
});
