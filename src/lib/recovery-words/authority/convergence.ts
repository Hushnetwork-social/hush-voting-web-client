/**
 * FEAT-008 recovery-words authority — navigation, ownership, timeout, and
 * cleanup convergence policy.
 *
 * Framework-neutral. Enforces root-only Back semantics (URL stays `/`),
 * exactly one recovery owner (tab/process), lifecycle concealment, stale-token
 * rejection, verified empty-vault guard, secret-free cross-tab notifications,
 * and quarantine-on-cleanup-failure.
 *
 * SECRET BOUNDARY: ownership events carry no phrase, candidate, address,
 * profile, protection, credential, or transaction data.
 *
 * Normative source: FEAT-008 FeatureDescription "Navigation and History",
 * "Concurrency and Ownership", "Cleanup and Logout", "Error Model",
 * "Entry and Local-Vault Guard"; FEAT-002 root-only navigation.
 */

import type { RecoveryResult } from '../contracts/lifecycle';

/** Back policy per workflow stage (browser Back, Android Back, in-app Back share one authority). */
export type BackStage = 'preVerify' | 'postVerifyPreStage' | 'staged';

export type BackDecision =
  | { readonly action: 'clearInputs' } // before Verify: return to first-run, clear all fields
  | { readonly action: 'destroyAuthority' } // after Verify/pre-stage: destroy mnemonic/candidate authority; empty word entry
  | { readonly action: 'lock' } // after stage: Back locks; shows Finish restoring; cannot reopen word entry
  | { readonly action: 'blocked' }; // staged data exists; only explicit verified cancellation unlocks

export function evaluateBack(stage: BackStage): BackDecision {
  switch (stage) {
    case 'preVerify':
      return { action: 'clearInputs' };
    case 'postVerifyPreStage':
      return { action: 'destroyAuthority' };
    case 'staged':
      return { action: 'lock' };
  }
}

/** Opaque history token policy: stale/forged/restored tokens cannot bypass vault inspection. */
export function isStaleHistoryToken(token: string | null, entryToken: string, flowTokens: ReadonlySet<string>): boolean {
  if (token === null) {
    return true;
  }
  // Entry token is authoritative; flow tokens must have been pushed by this authority.
  return token !== entryToken && !flowTokens.has(token);
}

/** Single-owner policy: the first tab/process to acquire the epoch owns recovery. */
export type OwnerDecision =
  | { readonly kind: 'owner' }
  | { readonly kind: 'blocked'; readonly reason: 'already-in-progress' }
  | { readonly kind: 'awaitingRelease' };

export function evaluateOwnership(acquired: boolean, epochOwned: boolean): OwnerDecision {
  if (acquired && epochOwned) {
    return { kind: 'owner' };
  }
  if (epochOwned) {
    return { kind: 'blocked', reason: 'already-in-progress' };
  }
  return { kind: 'awaitingRelease' };
}

/** Safe cross-tab notification payload — never contains secret or linkage data. */
export interface LocalUserEventNotification {
  readonly kind: 'localUserExists' | 'ownerReleased' | 'recoveryInProgress';
  readonly nonSecretOnly: true;
}

export function localUserEvent(kind: LocalUserEventNotification['kind']): LocalUserEventNotification {
  return { kind, nonSecretOnly: true };
}

/** Cleanup policy: verified deletion of every HushVoting-managed local artifact. */
export type CleanupArtifact =
  | 'vaultSlotsAndJournal'
  | 'wrappedKeysOsItems'
  | 'stagedRollbackData'
  | 'sidecarsTombstones'
  | 'bffClientCaches'
  | 'credentialReferenceMetadata'
  | 'retainedTransactions'
  | 'safePreviews';

export const CLEANUP_ARTIFACT_SET: readonly CleanupArtifact[] = [
  'vaultSlotsAndJournal',
  'wrappedKeysOsItems',
  'stagedRollbackData',
  'sidecarsTombstones',
  'bffClientCaches',
  'credentialReferenceMetadata',
  'retainedTransactions',
  'safePreviews',
] as const;

/**
 * Verified cleanup convergence: absence must be verified before first-run
 * becomes available. Any cleanup failure keeps the state quarantined and
 * blocks FEAT-008. WebAuthn cannot programmatically delete a passkey — the
 * application removes its own ciphertext/binding and reports honestly that an
 * orphan passkey may remain in browser/OS settings.
 */
export function evaluateCleanup(verifiedAbsent: boolean, cleanupFailed: boolean): RecoveryResult<{ readonly state: 'firstRunAvailable' | 'quarantined' }> {
  if (cleanupFailed || !verifiedAbsent) {
    return {
      ok: false,
      code: 'CLEANUP_FAILURE',
      message: 'Local cleanup could not be verified; recovery remains blocked.',
      supportCode: 'RW-CLN-1',
    };
  }
  return { ok: true, value: { state: 'firstRunAvailable' } };
}

/** Honest WebAuthn limit: an orphan passkey may remain; without the local vault it cannot recover keys. */
export function webauthnCleanupHonesty(): { readonly applicationOwnedRemoved: true; readonly externalPasskeyMayRemain: true } {
  return { applicationOwnedRemoved: true, externalPasskeyMayRemain: true };
}

/** Verified empty-vault guard: FEAT-008 may start only when no authority exists. */
export type VaultInspection =
  | { readonly kind: 'verifiedEmpty' }
  | { readonly kind: 'activeLocalIdentity' }
  | { readonly kind: 'stagedOrProvisional' }
  | { readonly kind: 'rollbackPending' }
  | { readonly kind: 'removalTombstone' }
  | { readonly kind: 'quarantined' }
  | { readonly kind: 'competingAuthority' };

export function canStartRecovery(inspection: VaultInspection): RecoveryResult<{ readonly startable: true }> {
  if (inspection.kind === 'verifiedEmpty') {
    return { ok: true, value: { startable: true } };
  }
  return {
    ok: false,
    code: inspection.kind === 'quarantined' ? 'QUARANTINED' : 'VAULT_NOT_VERIFIED_EMPTY',
    message: 'A local identity or pending lifecycle state exists; recovery cannot start.',
    supportCode: 'RW-GUARD-1',
  };
}
