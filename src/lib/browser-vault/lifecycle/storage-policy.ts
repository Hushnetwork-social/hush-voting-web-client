/**
 * FEAT-004 browser-vault lifecycle — storage policy (persistence, headroom,
 * bounded retry, quota).
 *
 * - Persistence is requested ONLY in a user-initiated Create/Restore flow, after
 *   explaining the reason; denial returns `PersistenceDenied` and requires
 *   explicit durability acknowledgement. Reliably known ephemeral storage
 *   blocks provisioning; private-mode fingerprinting heuristics are absent.
 * - Advisory headroom before KDF work: `max(4 MiB, 3 × candidate + 1 MiB)`.
 *   A missing/imprecise estimate defers to the real staged transaction.
 * - Transient IndexedDB transaction failures retry at most three times after
 *   the first failure (100/250/500 ms + ≤100 ms jitter); KDF work is NEVER
 *   repeated for storage retry. Quota stops immediately and preserves the
 *   active/required rollback slots. No destructive cleanup is ever performed.
 *
 * Normative source: FEAT-004 FeatureDescription "Storage persistence",
 * "Storage headroom", "Failure and quota behavior".
 */
import { failure, success, type VaultResult } from '../../vault-core/contracts/results';

/** Bounded retry schedule after the FIRST failure (three retries total). */
export const RETRY_DELAYS_MS = [100, 250, 500] as const;

/** Maximum jitter added to each retry delay. */
export const MAX_RETRY_JITTER_MS = 100 as const;

/** Advisory headroom before KDF work where candidate size is already known. */
export function requiredHeadroomKiB(candidateBytes: number): number {
  const fourMiB = 4 * 1024;
  const candidateBased = 3 * Math.ceil(candidateBytes / 1024) + 1024;
  return Math.max(fourMiB, candidateBased);
}

/** Bounded retry delay for attempt index 0..2 (after first failure). */
export function retryDelayForAttempt(attempt: number, jitterMs = 0): number {
  if (attempt < 0 || attempt >= RETRY_DELAYS_MS.length) {
    throw new Error('retry attempt outside the bounded schedule');
  }
  const boundedJitter = Math.max(0, Math.min(MAX_RETRY_JITTER_MS, jitterMs));
  return RETRY_DELAYS_MS[attempt] + boundedJitter;
}

/** Storage estimate surface (injected; browser primitives live behind it). */
export interface StorageEstimateEnvironment {
  readonly estimate?: () => Promise<{ readonly usage: number; readonly quota: number } | null>;
  readonly persisted?: () => Promise<boolean>;
  readonly persist?: () => Promise<boolean>;
}

/**
 * Check advisory headroom for a known candidate size. A missing/imprecise
 * estimate returns ok (the real staged transaction is authoritative); a known
 * shortfall returns `StorageQuotaExceeded` WITHOUT any destructive cleanup.
 */
export async function checkHeadroom(
  env: StorageEstimateEnvironment,
  candidateBytes: number,
): Promise<VaultResult<{ readonly ok: true; readonly remainingKiB?: number }>> {
  if (!env.estimate) {
    return success({ ok: true });
  }
  let estimate: { readonly usage: number; readonly quota: number } | null;
  try {
    estimate = await env.estimate();
  } catch {
    return success({ ok: true }); // imprecise estimate defers to real transaction
  }
  if (estimate === null) {
    return success({ ok: true });
  }
  const remainingKiB = Math.max(0, Math.floor((estimate.quota - estimate.usage) / 1024));
  const neededKiB = requiredHeadroomKiB(candidateBytes);
  if (remainingKiB < neededKiB) {
    return failure('StorageQuotaExceeded');
  }
  return success({ ok: true, remainingKiB });
}

/** Persistence decision for user-initiated provisioning. */
export type PersistenceDecision =
  | { readonly kind: 'persisted' }
  | { readonly kind: 'denied' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'known-ephemeral' };

/**
 * Request persistence ONLY during a user-initiated Create/Restore flow.
 * `allowAcknowledgedDenial` maps to explicit user acknowledgement of the
 * durability risk; reliably known ephemeral storage blocks provisioning.
 */
export async function evaluatePersistence(
  env: StorageEstimateEnvironment,
  params: { readonly allowAcknowledgedDenial: boolean },
): Promise<VaultResult<{ readonly decision: PersistenceDecision }>> {
  if (!env.persisted || !env.persist) {
    return success({ decision: { kind: 'unavailable' } });
  }
  let alreadyPersisted: boolean;
  try {
    alreadyPersisted = await env.persisted();
  } catch {
    return failure('StorageUnavailable');
  }
  if (alreadyPersisted) {
    return success({ decision: { kind: 'persisted' } });
  }
  let granted: boolean;
  try {
    granted = await env.persist();
  } catch {
    return failure('StorageUnavailable');
  }
  if (granted) {
    return success({ decision: { kind: 'persisted' } });
  }
  // Persistence denied: proceed only after explicit acknowledgement.
  if (params.allowAcknowledgedDenial) {
    return success({ decision: { kind: 'denied' } });
  }
  return failure('PersistenceDenied');
}

/**
 * Run an operation with the bounded storage retry schedule. `isTransientStorage`
 * must classify only genuine transient storage failures (never quota, never
 * wrong-password, never KDF work). KDF work is never repeated by this helper.
 */
export async function withBoundedStorageRetry<T>(
  run: () => Promise<VaultResult<T>>,
  isTransientStorage: (result: VaultResult<T>) => boolean,
  options: { readonly jitterMs?: number; readonly sleep?: (ms: number) => Promise<void> } = {},
): Promise<VaultResult<T>> {
  const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  let result = await run();
  for (let attempt = 0; attempt < RETRY_DELAYS_MS.length && isTransientStorage(result); attempt += 1) {
    await sleep(retryDelayForAttempt(attempt, options.jitterMs));
    result = await run();
  }
  return result;
}
