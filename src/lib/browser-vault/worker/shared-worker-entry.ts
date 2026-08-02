/**
 * FEAT-004 first-party SharedWorker entry.
 *
 * One reviewed authority source drives both worker entries; this file is the
 * thin SharedWorker wiring. First-party same-origin module bundle; no
 * Blob/string workers, no runtime CDN, no SSR execution. Message admission is
 * the single `validateClientMessage` gate inside the authority.
 *
 * The production authority composition (operation executor, crypto, storage,
 * verification transport) is injected by the Phase 6 composition; this entry
 * connects MessagePorts to that authority.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker hierarchy",
 * "Worker delivery".
 */

/** Connectivity shape used by the shared-worker wiring. */
export interface SharedWorkerGlobalScopeLike {
  onconnect: ((event: MessageEvent) => void) | null;
}

/** Wire one port to an authority handle; returns the connected port. */
export function connectPort(
  port: MessagePort,
  handle: { readonly handleMessage: (message: unknown) => void },
): MessagePort {
  port.onmessage = (event: MessageEvent) => {
    handle.handleMessage(event.data);
  };
  port.start();
  return port;
}

/** Attach the onconnect handler to a worker global. */
export function attachSharedWorkerConnect(
  globalScope: SharedWorkerGlobalScopeLike,
  createHandle: () => { readonly handleMessage: (message: unknown) => void },
): void {
  globalScope.onconnect = (event: MessageEvent) => {
    const port = event.ports?.[0];
    if (!port) {
      return;
    }
    connectPort(port, createHandle());
  };
}

// The browser worker runtime wires `self` at load time via the Phase 6
// composition; this module is pure so it typechecks and unit-tests without
// worker globals.
