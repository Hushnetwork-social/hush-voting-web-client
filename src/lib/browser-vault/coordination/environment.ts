/**
 * FEAT-004 browser coordination — real browser primitive wiring.
 *
 * Resolves real browser globals behind the injected `CoordinationPrimitives`
 * interface: SharedWorker (first-party module), Web Locks API, the IndexedDB
 * CAS'd lease (through the vault storage session — never localStorage),
 * BroadcastChannel advisory notifications, wall clock, and timers.
 *
 * `createBrowserCoordinationPrimitives` is only invoked on the web runtime
 * after capability preflight; SSR/build-time evaluation is impossible by
 * construction (the function reads browser globals at call time).
 *
 * Normative source: FEAT-004 FeatureDescription "Worker hierarchy",
 * "Session and Tab Coordination".
 */
import type { VaultStorageSession } from '../storage/wrapper';
import { createLeaseStore, type CoordinationPrimitives } from './coordinator';

/** SharedWorker entry URL (first-party module bundle, Phase 6 asset wiring). */
export interface BrowserCoordinationOptions {
  readonly sharedWorkerUrl?: string;
  readonly indexDbSession: VaultStorageSession;
  readonly clock?: { readonly now: () => number };
}

/** Resolve the real browser coordination primitives. */
export function createBrowserCoordinationPrimitives(options: BrowserCoordinationOptions): CoordinationPrimitives {
  const now = options.clock?.now ?? (() => Date.now());

  let sharedWorkerSupported = false;
  let connectSharedWorker: CoordinationPrimitives['sharedWorker']['connect'] = () => null;
  try {
    sharedWorkerSupported = typeof SharedWorker !== 'undefined' && typeof URL !== 'undefined';
    const url = options.sharedWorkerUrl ?? '/workers/vault-shared-worker.js';
    connectSharedWorker = () => {
      try {
        const worker = new SharedWorker(url, { type: 'module', name: 'hushvoting-vault-authority' });
        worker.port.start();
        return {
          send(payload) {
            worker.port.postMessage(payload);
          },
        };
      } catch {
        return null;
      }
    };
  } catch {
    sharedWorkerSupported = false;
  }

  let webLockSupported = false;
  let acquireWebLock: CoordinationPrimitives['webLock']['acquire'] = async () => false;
  let releaseWebLock: CoordinationPrimitives['webLock']['release'] = async () => undefined;
  try {
    webLockSupported = typeof navigator !== 'undefined' && typeof navigator.locks !== 'undefined';
    acquireWebLock = (name, onLost) =>
      new Promise((resolve) => {
        navigator.locks
          .request(name, { ifAvailable: true }, (lock) => {
            if (lock === null) {
              resolve(false); // held elsewhere: never steal
              return null;
            }
            resolve(true);
            // Hold the exclusive lock for the lifetime of this tab; loss is
            // authority-owned (global Lock + epoch invalidation).
            return new Promise<void>(() => {
              void onLost;
            });
          })
          .catch(() => {
            resolve(false);
          });
      });
    releaseWebLock = async () => undefined;
  } catch {
    webLockSupported = false;
  }

  let broadcastSupported = false;
  let broadcastPost: CoordinationPrimitives['broadcast']['post'] = () => undefined;
  try {
    broadcastSupported = typeof BroadcastChannel !== 'undefined';
    const channel = broadcastSupported ? new BroadcastChannel('hushvoting-vault-advisory') : null;
    broadcastPost = (payload) => {
      channel?.postMessage(payload);
    };
  } catch {
    broadcastSupported = false;
  }

  return {
    sharedWorker: { supported: sharedWorkerSupported, connect: connectSharedWorker },
    webLock: {
      supported: webLockSupported,
      acquire: acquireWebLock,
      release: releaseWebLock,
    },
    leaseStore: createLeaseStore(options.indexDbSession),
    broadcast: { supported: broadcastSupported, post: broadcastPost },
    now,
    schedule: (callback, delayMs) => {
      const handle = setTimeout(callback, delayMs);
      return { cancel: () => clearTimeout(handle) };
    },
  };
}
