/**
 * FEAT-010 presentation logic — settings/recovery/removal/migration/error/
 * evidence projections (Task 4.5).
 *
 * Safe status/settings views, fresh-authorization prompts, exact Lock-policy
 * choices/warnings, password/mode transition progress, removal-first
 * recovery, migration/quarantine remediation, and closed unknown-error
 * projections with random per-occurrence support codes. No action implies a
 * remote reset; offline availability is exact; evidence projections carry
 * only allowlisted aggregate fields (AC-010-063…082, 088…090, 097, 099).
 *
 * Framework-neutral, secret-free.
 */
import type { IdleLockChoice, BackgroundLockChoice } from '../lifecycle-policy';
import type { CurrentProtectionModeClass } from '../../vault-core/contracts/current-binding';
import type { SettingsExtensionState } from '../composition-target';

/** Closed settings actions (FEAT-011 export appears only when compatible). */
export type SettingsActionKind =
  | 'lockPolicy'
  | 'devicePasswordChange'
  | 'protectionModeChange'
  | 'removeLocalUser'
  | 'export';

/** Settings action availability matrix (offline-exact, AC-010-071). */
export interface SettingsActionProjection {
  readonly available: readonly SettingsActionKind[];
  readonly blockedOffline: readonly SettingsActionKind[];
}

export function projectSettingsActions(
  offline: boolean,
  extension: SettingsExtensionState,
): SettingsActionProjection {
  const available: SettingsActionKind[] = ['removeLocalUser'];
  const blockedOffline: SettingsActionKind[] = [];
  if (!offline) {
    available.push('devicePasswordChange', 'protectionModeChange');
  } else {
    blockedOffline.push('devicePasswordChange', 'protectionModeChange');
  }
  // Lock-policy change works offline after fresh local authorization.
  available.push('lockPolicy');
  // FEAT-011 export: ABSENT unless a compatible real production capability
  // registers (AC-010-046); never a disabled/coming-soon/mock action.
  if (extension.kind === 'registered' && extension.compatible) {
    if (offline) {
      blockedOffline.push('export');
    } else {
      available.push('export');
    }
  }
  return { available, blockedOffline };
}

/** Exact Lock-policy presentation (choices + one-time warnings). */
export interface LockPolicyProjection {
  readonly idleChoices: readonly IdleLockChoice[];
  readonly backgroundChoices: readonly BackgroundLockChoice[];
  readonly weakerChoicesWarn: readonly string[];
}

export function projectLockPolicy(
  idleChoices: readonly IdleLockChoice[],
  backgroundChoices: readonly BackgroundLockChoice[],
  weakerChoicesWarn: readonly string[],
): LockPolicyProjection {
  return { idleChoices, backgroundChoices, weakerChoicesWarn };
}

/** Fresh-authorization prompt projection (one purpose, one consequence). */
export interface FreshAuthorizationPromptProjection {
  readonly purposeLabel: string;
  readonly usesCurrentProtectionOnly: true;
  readonly singleOperation: true;
}

export function projectFreshAuthorizationPrompt(purposeLabel: string): FreshAuthorizationPromptProjection {
  return { purposeLabel, usesCurrentProtectionOnly: true, singleOperation: true };
}

/** Removal-first recovery projection (AC-010-073/074). */
export interface RecoveryProjection {
  readonly noRemoteResetCopy: string;
  readonly requiresPhrase: 'REMOVE';
  readonly finalConfirmationRequired: true;
  /** Restore choices appear only after verified cleanup (AC-010-075). */
  readonly restoreChoicesVisible: boolean;
}

export function projectRecovery(cleanupVerified: boolean): RecoveryProjection {
  return {
    noRemoteResetCopy: 'HushVoting cannot recover or reset your protection. Your blockchain identity is unaffected.',
    requiresPhrase: 'REMOVE',
    finalConfirmationRequired: true,
    restoreChoicesVisible: cleanupVerified,
  };
}

/** Migration/quarantine remediation (AC-010-079/082). */
export type MigrationRemediationProjection =
  | { readonly kind: 'updateAvailable' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'recoveryOrRemoval' }
  | { readonly kind: 'networkMismatch' };

export function projectMigrationRemediation(verdict: 'unsupported' | 'corrupt' | 'requiresMigration' | 'wrongNetwork'): MigrationRemediationProjection {
  switch (verdict) {
    case 'unsupported':
      return { kind: 'updateAvailable' };
    case 'corrupt':
      return { kind: 'recoveryOrRemoval' };
    case 'requiresMigration':
      return { kind: 'retry' };
    case 'wrongNetwork':
      return { kind: 'networkMismatch' };
    default: {
      const never: never = verdict;
      return never;
    }
  }
}

/** Unknown-error projection: generic copy + random per-occurrence support code. */
export interface UnknownErrorProjection {
  readonly genericCopy: string;
  readonly supportCode: string;
}

export function projectUnknownError(): UnknownErrorProjection {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const supportCode = `ERR-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()}`;
  return { genericCopy: 'Something went wrong. Please try again.', supportCode };
}

/** Quarantine copy (cleanup failure persists across restart). */
export const QUARANTINE_COPY = 'Local cleanup could not finish. Retry cleanup to continue.';

/** Protection-mode transition progress projection. */
export type TransitionProgressProjection =
  | { readonly kind: 'enrolling'; readonly targetMode: CurrentProtectionModeClass }
  | { readonly kind: 'commitPending' }
  | { readonly kind: 'newModeUnlockRequired' }
  | { readonly kind: 'failedPreservingOldGeneration' };

export function projectTransitionProgress(state: TransitionProgressProjection['kind'], targetMode?: CurrentProtectionModeClass): TransitionProgressProjection {
  if (state === 'enrolling' && targetMode !== undefined) {
    return { kind: 'enrolling', targetMode };
  }
  if (state === 'enrolling') {
    return { kind: 'failedPreservingOldGeneration' };
  }
  return { kind: state };
}
