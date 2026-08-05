/**
 * FEAT-009 credential-file restore authority — navigation, ownership,
 * timeout, and cleanup convergence policy (Task 3.9).
 *
 * Framework-neutral. Enforces root-only Back semantics (visible URL stays
 * `/`), exactly one restore owner (tab/window/process), the 10-minute
 * foreground authority expiry, stale/bfcache defense, logout/removal that
 * never targets the external source, and quarantine-on-cleanup-failure.
 *
 * SECRET BOUNDARY: ownership and navigation events carry no source
 * identifier, password, credential, profile, address, protection, or
 * transaction data.
 *
 * Normative source: FEAT-009 FeatureDescription "Navigation and Back",
 * "Concurrency and Ownership", "Source Preservation and Cleanup",
 * "Logout/Removal"; FEAT-002 root-only navigation; FEAT-003 lifecycle
 * kernels; FEAT-008 convergence policy.
 */
import type { RestoreResult } from '../contracts/lifecycle';
import { RESTORE_EPOCH_FOREGROUND_BOUND_MS } from '../contracts/lifecycle';
import type { CleanupScope, CleanupVerification, OwnerState, StagedCancellation, StartupInspection } from '../contracts/staging';

/** Back policy per workflow stage (browser Back, Android Back, in-app Back share one authority). */
export type BackStage = 'preDecrypt' | 'postValidationPreStage' | 'staged';

export type BackDecision =
  | { readonly action: 'clearInputs' } // pre-decryption: clear source/password; three-choice entry
  | { readonly action: 'destroyAuthority' } // post-validation/pre-stage: destroy validated authority; empty file selection
  | { readonly action: 'lock' } // post-stage: lock; Finish restoring your identity only
  | { readonly action: 'blocked' }; // staged data exists; only explicit verified cancellation unlocks

export function evaluateBack(stage: BackStage): BackDecision {
  switch (stage) {
    case 'preDecrypt':
      return { action: 'clearInputs' };
    case 'postValidationPreStage':
      return { action: 'destroyAuthority' };
    case 'staged':
      return { action: 'lock' };
  }
}

/** Opaque history token policy: stale/forged/restored tokens cannot bypass custody inspection. */
export function isStaleHistoryToken(token: string | null, entryToken: string, flowTokens: ReadonlySet<string>): boolean {
  if (token === null) {
    return true;
  }
  return token !== entryToken && !flowTokens.has(token);
}

/** Single-owner policy: the first tab/window/process to acquire the epoch owns restore. */
export type OwnerDecision =
  | { readonly decision: 'acquire'; readonly isOwner: true }
  | { readonly decision: 'blocked'; readonly isOwner: false }
  | { readonly decision: 'release' }; // owner released; Retry/focus allowed after release

export function evaluateOwnerRequest(
  currentOwner: OwnerState,
  requestedEpoch: string,
  activeEpoch: string | null,
): OwnerDecision {
  if (activeEpoch !== null && requestedEpoch !== activeEpoch) {
    return { decision: 'blocked', isOwner: false };
  }
  if (currentOwner.kind === 'owner') {
    return { decision: 'acquire', isOwner: true };
  }
  if (currentOwner.kind === 'released') {
    return { decision: 'release' };
  }
  return { decision: 'blocked', isOwner: false };
}

/** Foreground authority expiry: unprovisioned restore exceeds 10 minutes ⇒ epoch cleared. */
export function isEpochExpired(acquiredAtMs: number, nowMs: number): boolean {
  return nowMs - acquiredAtMs > RESTORE_EPOCH_FOREGROUND_BOUND_MS;
}

/** Startup inspection decision: staged data never shows first-run. */
export function decideStartup(
  hasStagedData: boolean,
  hasActiveIdentity: boolean,
  quarantine: boolean,
  competing: boolean,
): StartupInspection {
  if (competing) return { kind: 'competingAuthority' };
  if (quarantine) return { kind: 'quarantined' };
  if (hasStagedData) return { kind: 'stagedExists' };
  if (hasActiveIdentity) return { kind: 'activeIdentity' };
  return { kind: 'verifiedEmpty' };
}

/** Cleanup verification: failure is quarantine, never "empty". */
export function evaluateCleanup(
  remaining: readonly CleanupScope[],
): CleanupVerification {
  if (remaining.length === 0) {
    return { kind: 'verifiedAbsent' };
  }
  return { kind: 'quarantined', remaining: [...remaining] };
}

/** Staged cancellation: removal must verify; failure quarantines first-run paths. */
export function evaluateCancellation(removalVerified: boolean): StagedCancellation {
  if (removalVerified) {
    return { kind: 'removed' };
  }
  return { kind: 'quarantined' };
}

/** The external source is structurally absent from every legal cleanup scope set. */
export const LEGAL_CLEANUP_SCOPES: readonly CleanupScope[] = [
  'stage',
  'transaction',
  'protectionBinding',
  'sidecar',
  'session',
  'tempCiphertext',
];

/** Guard: assert a cleanup scope set never contains the external source. */
export function assertExternalSourceExcluded(scopes: readonly string[]): boolean {
  return !scopes.includes('externalSource');
}

export type CleanupResult = RestoreResult<CleanupVerification>;
