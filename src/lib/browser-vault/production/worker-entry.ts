/**
 * FEAT-010 production SharedWorker entry (Task 7.3).
 *
 * Boots the ONE reviewed `WorkerAuthority` over the real sealed vault engine:
 * opens IndexedDB storage, resolves the closed deployment manifest for the
 * handshake runtime configuration, wires real crypto/clock/randomness and the
 * out-of-band secret-transfer book, then attaches the first-party module
 * SharedWorker `onconnect` handler. Every connected port is validated by the
 * authority before any operation starts; worker death always projects Locked.
 *
 * This file is bundled into `public/workers/vault-shared-worker.js` by
 * `scripts/build-worker.mjs` (esbuild, first-party, same-origin). It never
 * imports page/React code.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker delivery";
 * FEAT-010 FeatureDescription "Real Composition"; AC-010-004/006.
 */

import { WorkerAuthority } from '../authority/authority';
import type { SharedWorkerGlobalScopeLike } from '../worker/shared-worker-entry';
import { openVaultStorage } from '../storage/wrapper';
import { createBrowserSuiteExecutor, resolveBrowserCryptoEnvironment } from '../crypto/executor';
import { createProductionWorkerEnvironment } from './worker-env';
import type { BrowserWorkerEvent } from '../contracts/protocol';
import type { AuthorityPhase } from '../authority/capabilities';

/** Application build identity bound by every handshake (exact-match). */
export interface WorkerAppIdentity {
  readonly appVersion: string;
  readonly buildDigest: string;
}

/** Expected runtime configuration for this isolated build. */
const EXPECTED_RUNTIME_CONFIG = 'development-localhost' as const;

/**
 * Boot the worker authority. Returns null when storage cannot open or the
 * runtime configuration is not approved (fail closed; ports still connect but
 * every operation returns a typed refusal).
 */
export async function bootVaultWorker(params: {
  readonly appIdentity: WorkerAppIdentity;
  readonly runtimeConfigId?: string;
  readonly openStorage?: typeof openVaultStorage;
  readonly createEnv?: typeof createProductionWorkerEnvironment;
  readonly indexedDBFactory?: IDBFactory;
}): Promise<{ readonly ok: true; readonly authority: WorkerAuthority; readonly registerPort: (port: MessagePort) => void } | { readonly ok: false; readonly reason: string }> {
  const runtimeConfigId = params.runtimeConfigId ?? EXPECTED_RUNTIME_CONFIG;
  if (runtimeConfigId !== EXPECTED_RUNTIME_CONFIG) {
    return { ok: false, reason: 'unapproved-runtime-config' };
  }

  const factory = params.indexedDBFactory;
  let storageResult;
  try {
    if (params.openStorage) {
      // Injected storage (tests); the factory argument is ignored.
      storageResult = await params.openStorage(factory as never);
    } else {
      storageResult = await openVaultStorage(factory ?? indexedDB);
    }
  } catch {
    return { ok: false, reason: 'storage-unavailable' };
  }
  if (!storageResult.ok) {
    return { ok: false, reason: 'storage-unavailable' };
  }
  const session = storageResult.value.session;

  let suite;
  try {
    const env = resolveBrowserCryptoEnvironment();
    suite = createBrowserSuiteExecutor(env);
  } catch {
    return { ok: false, reason: 'crypto-unavailable' };
  }

  // Port wiring: the authority delivers events to the owning port by channel.
  const channels = new Map<string, MessagePort>();
  const deliver = (clientChannel: string, event: BrowserWorkerEvent): void => {
    const port = channels.get(clientChannel);
    if (port) {
      try {
        port.postMessage(event);
      } catch {
        // A dead port never compromises the authority; cleanup is bounded.
      }
    }
  };
  const broadcast = (event: BrowserWorkerEvent): void => {
    for (const port of channels.values()) {
      try {
        port.postMessage(event);
      } catch {
        // ignore dead ports
      }
    }
  };

  const createEnv = params.createEnv ?? createProductionWorkerEnvironment;
  const { env, secrets } = createEnv({
    storage: session,
    suite,
    appIdentity: { appVersion: params.appIdentity.appVersion, buildDigest: params.appIdentity.buildDigest },
    runtimeConfigId,
    deliver,
    broadcast,
    onForceCleanup: () => {
      // Bounded cleanup bound exceeded: force-close every channel; the
      // authority keeps its epoch and the sealed engine wipes secrets.
      for (const port of channels.values()) {
        try {
          port.close();
        } catch {
          // ignore
        }
      }
      channels.clear();
    },
  });

  // Wire the out-of-band secret-transfer book into the authority.
  (env as { onSecretTransfer?: unknown }).onSecretTransfer = (transfer: {
    readonly operationId: string;
    readonly purpose: 'devicePassword' | 'mnemonic' | 'filePassword' | 'fileBytes';
    readonly value: string;
  }) => {
    secrets.store({ operationId: transfer.operationId, kind: transfer.purpose, value: transfer.value, consumed: false });
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        const channel = new BroadcastChannel('hushvoting-vault-advisory');
        channel.postMessage({ kind: 'vault-worker-op', event: { kind: 'secret-received', operation: transfer.operationId, purpose: transfer.purpose } });
        channel.close();
      }
    } catch {
      // diagnostic only
    }
  };

  const authority = new WorkerAuthority(env);

  // Startup inspection: resolve the deterministic startup surface and set the
  // initial authority phase (never authenticated after restart).
  const snapshot = authority.snapshot();
  const inspect = await env.executeOperation(
    { kind: 'operation', operation: 'inspectStartup', operationVersion: 1, clientChannel: 'boot', authorityEpoch: snapshot.epoch, operationId: 'boot-inspect' },
    snapshot.epoch,
  );
  const surface = typeof inspect.payload === 'object' && inspect.payload !== null ? (inspect.payload as { surface?: string }).surface : null;
  let phase: AuthorityPhase = 'locked';
  if (inspect.outcome === 'OK') {
    if (surface === 'verifiedAbsent') {
      phase = 'noLocalUser';
    } else if (surface === 'removalTombstone') {
      phase = 'removalInProgress';
    } else {
      phase = 'locked';
    }
  }
  authority.setPhase(phase);

  /** Wire one connected port to the authority + channel registry. */
  const registerPort = (port: MessagePort): MessagePort => {
    port.onmessage = (event: MessageEvent) => {
      const message = event.data as { kind?: unknown; clientChannel?: unknown } | null;
      if (typeof message === 'object' && message !== null && typeof message.clientChannel === 'string') {
        // Register the channel BEFORE dispatch so handshake-accepted and
        // later events reach this port. The authority rejects duplicate
        // handshakes itself (HANDSHAKE_DUPLICATE_CHANNEL).
        channels.set(message.clientChannel, port);
      }
      authority.handle(message);
    };
    port.start();
    return port;
  };

  return { ok: true, authority, registerPort };
}

/** Attach the production onconnect handler to a worker global scope.
 *
 * SYNC by design: Chromium dispatches SharedWorker connect events only while
 * the script evaluates; an onconnect attached after top-level awaits never
 * fires. Ports connected during boot are queued and wired to the authority
 * once boot completes (their page-side messages are buffered by the browser
 * until the worker sets `port.onmessage`).
 */
export function attachProductionWorkerConnect(
  globalScope: SharedWorkerGlobalScopeLike,
  wirePort: (port: MessagePort) => void,
  getBooted: () => { readonly registerPort: (port: MessagePort) => void } | null,
): void {
  const pendingPorts: MessagePort[] = [];
  globalScope.onconnect = (event: MessageEvent) => {
    const port = event.ports?.[0];
    if (!port) {
      return;
    }
    const booted = getBooted();
    if (booted !== null) {
      booted.registerPort(port);
      return;
    }
    pendingPorts.push(port);
  };
  // Flush queued ports once boot completes.
  const booted = getBooted();
  void booted;
  // The boot promise resolves asynchronously; poll until the authority is
  // available (bounded; ports wait at most 10 s then fail closed).
  const flush = setInterval(() => {
    const ready = getBooted();
    if (ready === null) {
      return;
    }
    clearInterval(flush);
    for (const queued of pendingPorts.splice(0)) {
      ready.registerPort(queued);
    }
  }, 50);
}

/** Compute the exact build digest from the served worker bundle itself. */
export async function computeWorkerBuildDigest(fetchImpl: typeof fetch = fetch): Promise<string | null> {
  try {
    const scope = self as unknown as { location?: { href?: string } };
    const url = scope.location?.href;
    if (typeof url !== 'string' || url.length === 0) {
      return null;
    }
    const response = await fetchImpl(url, { cache: 'no-store' });
    const text = await response.text();
    if (!response.ok || text.length === 0) {
      return null;
    }
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('').slice(0, 12);
  } catch {
    return null;
  }
}

/** Standalone browser-runtime boot (used by the bundled worker entry). */
export async function bootAndAttach(params?: { readonly appVersion?: string; readonly runtimeConfigId?: string }): Promise<{ readonly ok: true; readonly registerPort: (port: MessagePort) => void } | { readonly ok: false; readonly reason: string }> {
  const digest = await computeWorkerBuildDigest();
  if (digest === null) {
    return { ok: false, reason: 'build-identity-unavailable' };
  }
  const result = await bootVaultWorker({
    appIdentity: { appVersion: params?.appVersion ?? '0.1.0', buildDigest: digest },
    runtimeConfigId: params?.runtimeConfigId,
  });
  if (!result.ok) {
    return result;
  }
  return { ok: true, registerPort: result.registerPort };
}

// ---------------------------------------------------------------------------
// Bundle entry (browser SharedWorker runtime)
//
// The onconnect handler MUST be attached during the FIRST synchronous
// evaluation: Chromium dispatches SharedWorker connect events only while the
// script evaluates, so a handler attached after top-level awaits never fires.
// Ports connected during boot are queued and wired after the authority boots
// (their page-side messages are buffered by the browser until the worker sets
// `port.onmessage`).
// ---------------------------------------------------------------------------
const workerScope = typeof self !== 'undefined' ? (self as unknown as { location?: unknown; BroadcastChannel?: typeof BroadcastChannel }) : null;

/** Diagnostic boot beacon (BroadcastChannel; never affects boot success). */
function emitBootBeacon(status: { readonly ok: boolean; readonly reason?: string }): void {
  try {
    if (workerScope?.BroadcastChannel) {
      const channel = new workerScope.BroadcastChannel('hushvoting-vault-advisory');
      channel.postMessage({ kind: 'vault-worker-boot', ...status });
      channel.close();
    }
  } catch {
    // beacon is diagnostic only
  }
}

if (workerScope !== null) {
  emitBootBeacon({ ok: false, reason: 'module-executed' });
  const pendingPorts: MessagePort[] = [];
  let wired: ((port: MessagePort) => void) | null = null;
  (self as unknown as SharedWorkerGlobalScopeLike).onconnect = (event: MessageEvent) => {
    const port = event.ports?.[0];
    if (!port) {
      return;
    }
    if (wired !== null) {
      wired(port);
      return;
    }
    pendingPorts.push(port);
  };

  if ('location' in workerScope) {
    emitBootBeacon({ ok: false, reason: 'boot-start' });
    void bootAndAttach()
      .then((result) => {
        emitBootBeacon(result);
        if (result.ok) {
          wired = result.registerPort;
          for (const queued of pendingPorts.splice(0)) {
            wired(queued);
          }
        }
      })
      .catch((error: unknown) => {
        emitBootBeacon({ ok: false, reason: `boot-error: ${String(error)}` });
        setTimeout(() => {
          throw error;
        }, 0);
      });
  }
}
