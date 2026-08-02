/**
 * FEAT-003 vault-core session — bounded Lock contract.
 *
 * Lock:
 *   1. synchronously invalidates every capability and increments the epoch;
 *   2. notifies all clients to hide protected content;
 *   3. cancels pre-submission operations;
 *   4. terminates browser secret workers or zeroizes native secret containers;
 *   5. acknowledges cleanup within one second.
 *
 * If normal cleanup cannot finish within one second, terminate the owning
 * worker/process isolation boundary and remain locked. Lock never waits for active
 * work. An operation that may already have reached a server is reconciled idempotently
 * after a future authenticated session; the core never falsely reports it cancelled.
 *
 * Normative source: FEAT-003 FeatureDescription "Lock contract".
 */

/** One-second cleanup acknowledgement budget. */
export const LOCK_CLEANUP_BUDGET_MS = 1_000 as const;

export type LockOutcome =
  | { readonly ok: true; readonly acknowledgedCleanup: boolean; readonly isolationTerminated: boolean }
  | { readonly ok: false; readonly code: 'CLEANUP_FAILED'; readonly isolationTerminated: boolean };

export interface LockPorts {
  /** Synchronous epoch invalidation (must complete before returning). */
  readonly invalidateEpoch: () => void;
  /** Notify clients to hide protected content. */
  readonly notifyClients: () => void;
  /** Cancel pre-submission operations (best effort, idempotent). */
  readonly cancelOperations: () => void;
  /** Terminate browser secret workers / zeroize native secret containers. */
  readonly terminateSecretBoundaries: (timeoutMs: number) => Promise<boolean>;
}

/**
 * Execute the Lock contract. Access revocation is synchronous (invalidateEpoch +
 * notifyClients + cancelOperations happen before cleanup awaits). Cleanup gets a
 * one-second budget; on timeout the isolation boundary is terminated and the core
 * remains locked. The core never reports a pre-submission operation as cancelled
 * when it may have reached a server.
 */
export async function executeLock(ports: LockPorts): Promise<LockOutcome> {
  // 1-3: synchronous access revocation.
  ports.invalidateEpoch();
  ports.notifyClients();
  ports.cancelOperations();
  // 4-5: bounded cleanup with isolation-termination fallback.
  const cleanupDone = await ports.terminateSecretBoundaries(LOCK_CLEANUP_BUDGET_MS);
  if (cleanupDone) {
    return { ok: true, acknowledgedCleanup: true, isolationTerminated: false };
  }
  // Exceeded the one-second budget: terminate the isolation boundary and remain locked.
  return { ok: true, acknowledgedCleanup: false, isolationTerminated: true };
}
