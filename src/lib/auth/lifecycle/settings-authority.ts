/**
 * FEAT-010 business authority — fresh authorization, security mutations,
 * forgotten protection, and verified removal (Task 3.7).
 *
 * Rules enforced here (normative: FeatureDescription "Identity and Security
 * Settings", "Forgot Protection and Recovery", "Local-User Removal",
 * "Offline settings"; AC-010-063…078):
 * - every security mutation requires one-use purpose-scoped fresh
 *   authorization (≤60 s; invalidated by use/time/navigation/background/
 *   Lock/epoch/authority loss/removal);
 * - device-password change: current password + fresh exact online
 *   verification + new confirmation + fresh wrapping + atomic commit;
 * - persistent protection transitions only between qualified modes; failure
 *   preserves the old verified active generation; success Locks and requires
 *   new-mode unlock + online verification before rollback retirement;
 * - persistent→session-only is NOT a switch (removal + explicit onboarding);
 * - offline allows Lock/removal/safe settings/authorized lock-policy change
 *   but blocks protection change and export;
 * - forgotten protection is removal-first: REMOVE + final confirmation,
 *   tombstone-backed cleanup, verified absence BEFORE restore mounts;
 * - removal requires no password/network; never touches blockchain or
 *   external files; preserves only approved general preferences.
 *
 * Framework-neutral, secret-free.
 */
import {
  evaluateFreshAuthorization,
  FRESH_AUTHORIZATION_MAX_AGE_MS,
  type FreshAuthorization,
  type FreshAuthorizationInvalidation,
  type FreshAuthorizationPurpose,
} from '../lifecycle-policy';
import type { CurrentProtectionModeClass } from '../../vault-core/contracts/current-binding';

/** Approved removal confirmation phrase (exact, fixed). */
export const REMOVAL_PHRASE = 'REMOVE' as const;

/** General preferences preserved across removal (allowlist). */
export const PRESERVED_PREFERENCES: readonly string[] = ['language', 'theme', 'accessibility', 'telemetryOptOut'] as const;

/** One security mutation request (purpose-scoped). */
export interface SecurityMutationRequest {
  readonly purpose: FreshAuthorizationPurpose;
  readonly authorization: FreshAuthorization | null;
  readonly nowMs: number;
  readonly invalidation: FreshAuthorizationInvalidation | 'none';
}

/** Mutation admission verdict (AC-010-063/064). */
export type MutationAdmission =
  | { readonly kind: 'permitted' }
  | { readonly kind: 'missingAuthorization' }
  | { readonly kind: 'wrongPurpose' }
  | { readonly kind: 'expired' }
  | { readonly kind: 'invalidated' };

export function admitSecurityMutation(request: SecurityMutationRequest): MutationAdmission {
  const verdict = evaluateFreshAuthorization(request.authorization, request.purpose, request.nowMs, request.invalidation);
  switch (verdict.kind) {
    case 'valid':
      return { kind: 'permitted' };
    case 'wrongPurpose':
      return { kind: 'wrongPurpose' };
    case 'expired':
      return { kind: 'expired' };
    case 'invalidated':
    case 'alreadyUsed':
      return request.authorization === null ? { kind: 'missingAuthorization' } : { kind: 'invalidated' };
    default:
      return { kind: 'invalidated' };
  }
}

/** Device-password change sequence gates (AC-010-066). */
export type PasswordChangeVerdict =
  | { readonly kind: 'proceedToCommit' }
  | { readonly kind: 'admissionDenied'; readonly reason: MutationAdmission['kind'] }
  | { readonly kind: 'onlineVerificationRequired' }
  | { readonly kind: 'confirmationMismatch' };

export function prepareDevicePasswordChange(
  admission: MutationAdmission,
  currentPasswordVerified: boolean,
  onlineVerified: boolean,
  newPasswordMatchesConfirmation: boolean,
): PasswordChangeVerdict {
  if (admission.kind !== 'permitted') {
    return { kind: 'admissionDenied', reason: admission.kind };
  }
  if (!currentPasswordVerified) {
    return { kind: 'admissionDenied', reason: 'invalidated' };
  }
  if (!onlineVerified) {
    return { kind: 'onlineVerificationRequired' };
  }
  if (!newPasswordMatchesConfirmation) {
    return { kind: 'confirmationMismatch' };
  }
  return { kind: 'proceedToCommit' };
}

/** Persistent protection transition rules (AC-010-067…069). */
export type ProtectionTransitionVerdict =
  | { readonly kind: 'proceedToEnroll' }
  | { readonly kind: 'admissionDenied'; readonly reason: MutationAdmission['kind'] }
  | { readonly kind: 'onlineVerificationRequired' }
  | { readonly kind: 'unqualifiedTarget'; readonly target: CurrentProtectionModeClass }
  | { readonly kind: 'sessionOnlySwitchForbidden' }
  | { readonly kind: 'failedTransition'; readonly preserveOldGeneration: true };

export interface ProtectionTransitionRequest {
  readonly admission: MutationAdmission;
  readonly onlineVerified: boolean;
  readonly targetMode: CurrentProtectionModeClass;
  readonly qualifiedTargets: ReadonlySet<CurrentProtectionModeClass>;
  readonly enrollmentSucceeded: boolean;
  readonly readBackMatches: boolean;
}

export function prepareProtectionTransition(request: ProtectionTransitionRequest): ProtectionTransitionVerdict {
  if (request.admission.kind !== 'permitted') {
    return { kind: 'admissionDenied', reason: request.admission.kind };
  }
  if (!request.onlineVerified) {
    return { kind: 'onlineVerificationRequired' };
  }
  if (!request.qualifiedTargets.has(request.targetMode)) {
    return { kind: 'unqualifiedTarget', target: request.targetMode };
  }
  if (!request.enrollmentSucceeded || !request.readBackMatches) {
    // Failure preserves the old verified active generation (no downgrade).
    return { kind: 'failedTransition', preserveOldGeneration: true };
  }
  return { kind: 'proceedToEnroll' };
}

/** Persistent→session-only is never a settings switch (AC-010-070). */
export function isSessionOnlySwitchRequested(current: 'persistent', requested: 'session-only' | CurrentProtectionModeClass): boolean {
  return requested === 'session-only';
}

/** Offline settings matrix (AC-010-071). */
export type OfflineOperation =
  | 'lock'
  | 'removeLocalUser'
  | 'safeSettingsView'
  | 'lockPolicyChange'
  | 'devicePasswordChange'
  | 'protectionModeChange'
  | 'export';

export const OFFLINE_AVAILABLE_OPERATIONS: ReadonlySet<OfflineOperation> = new Set([
  'lock',
  'removeLocalUser',
  'safeSettingsView',
  'lockPolicyChange',
]);
export const OFFLINE_BLOCKED_OPERATIONS: readonly OfflineOperation[] = ['devicePasswordChange', 'protectionModeChange', 'export'];

/** Removal-first recovery gates (AC-010-073…075). */
export type RemovalRecoveryVerdict =
  | { readonly kind: 'proceedToCleanup' }
  | { readonly kind: 'phraseMismatch' }
  | { readonly kind: 'confirmationRequired' }
  | { readonly kind: 'cleanupIncomplete'; readonly quarantine: true };

export interface RemovalRecoveryRequest {
  readonly enteredPhrase: string;
  readonly finalConfirmed: boolean;
  readonly cleanupComplete: boolean;
}

export function prepareRemovalRecovery(request: RemovalRecoveryRequest): RemovalRecoveryVerdict {
  if (request.enteredPhrase !== REMOVAL_PHRASE) {
    return { kind: 'phraseMismatch' };
  }
  if (!request.finalConfirmed) {
    return { kind: 'confirmationRequired' };
  }
  if (!request.cleanupComplete) {
    return { kind: 'cleanupIncomplete', quarantine: true };
  }
  return { kind: 'proceedToCleanup' };
}

/** Global removal artifact inventory (AC-010-077). */
export type RemovalArtifactKind =
  | 'vaultSlots'
  | 'rollbackSlot'
  | 'platformKeyItems'
  | 'stagedOperations'
  | 'pendingTransactions'
  | 'reconciliationCaches'
  | 'preview'
  | 'lockPolicy'
  | 'session';

export const REMOVAL_ARTIFACT_KINDS: readonly RemovalArtifactKind[] = [
  'vaultSlots',
  'rollbackSlot',
  'platformKeyItems',
  'stagedOperations',
  'pendingTransactions',
  'reconciliationCaches',
  'preview',
  'lockPolicy',
  'session',
] as const;

/**
 * Verified-absence check: every removal artifact kind must be deleted before
 * the tombstone clears and first-run/restore may mount (AC-010-077/078).
 * Any remaining artifact → quarantine across restart.
 */
export function verifyRemovalAbsence(
  remainingArtifacts: readonly RemovalArtifactKind[],
): { readonly ok: boolean; readonly remaining: readonly RemovalArtifactKind[] } {
  const present = REMOVAL_ARTIFACT_KINDS.filter((kind) => remainingArtifacts.includes(kind));
  return { ok: present.length === 0, remaining: present };
}

/** Preservation check: only allowlisted general preferences survive removal. */
export function isPreservedPreference(key: string): boolean {
  return PRESERVED_PREFERENCES.includes(key);
}

/** Fresh-authorization issuance (one-use; caller stores in memory only). */
export function issueFreshAuthorization(
  purpose: FreshAuthorizationPurpose,
  nowMs: number,
): FreshAuthorization {
  return { id: `fa-${nowMs}-${Math.random().toString(36).slice(2, 10)}`, purpose, issuedAtMs: nowMs, maxAgeMs: FRESH_AUTHORIZATION_MAX_AGE_MS };
}
