/**
 * FEAT-005 Ubuntu vault bridge — FEAT-002 safe projection mapper.
 *
 * FEAT-002 remains the sole authentication orchestration authority. This
 * bridge projects only safe Ubuntu states/actions into FEAT-002's vocabulary:
 * one closed provider state maps to a closed action set; a native outcome maps
 * to a safe UI decision. No raw provider/path/identity/secret detail ever
 * crosses. No second transition authority exists.
 *
 * Normative source: FEAT-005 FeatureDescription "Availability state model",
 * "Error Handling"; FEAT-002 ports.
 */

import type {
  NativeOutcome,
  ProviderAction,
  ProviderAvailability,
} from './contracts';

/** Closed map: provider state → allowed safe actions (mirror of Rust). */
export const PROVIDER_ACTION_MAP: Readonly<Record<ProviderAvailability, readonly ProviderAction[]>> = {
  availableUnlocked: ['cancel'],
  availableLocked: ['unlockKeyring', 'cancel'],
  promptCancelled: ['retry', 'cancel'],
  temporarilyUnavailable: ['retry', 'cancel'],
  unavailable: ['enableOsProtection', 'retry', 'passwordOnlyFallback'],
  unqualifiedProvider: ['enableOsProtection', 'cancel'],
  protectionInvalidated: ['portableRecovery', 'cancel'],
};

/** Safety predicates for the projection layer. */
export const PROVIDER_PREDICATES = {
  /** Only confirmed absence is fallback-eligible. */
  isFallbackEligible: (state: ProviderAvailability): boolean => state === 'unavailable',
  /** Lock/cancel/timeout/temporary failures never select fallback nor throttle. */
  isTransient: (state: ProviderAvailability): boolean =>
    state === 'availableLocked' || state === 'promptCancelled' || state === 'temporarilyUnavailable',
  /** Unqualified/invalidated block persistent provisioning and are never absence. */
  blocksPersistentProvisioning: (state: ProviderAvailability): boolean =>
    state === 'unqualifiedProvider' || state === 'protectionInvalidated',
} as const;

/** Safe UI decision derived from one native outcome (never raw detail). */
export type OutcomeDecision =
  | { readonly action: 'continue'; readonly kind: 'unlocked' | 'verified' | 'provisioned' | 'removed' | 'preview' }
  | { readonly action: 'operationComplete'; readonly kind: 'revealPrepared' | 'signed' | 'datImported' | 'datExported' }
  | { readonly action: 'locked' }
  | { readonly action: 'retry'; readonly code: string }
  | { readonly action: 'recover'; readonly code: string }
  | { readonly action: 'blocked'; readonly code: string };

/**
 * Map a closed native outcome to a safe FEAT-002 decision.
 * Unknown/unsupported codes fail closed to `blocked` — never a blank screen.
 * Non-auth operation completions are distinguished from unlock transitions so
 * a signed/import/export outcome is never mistaken for an unlocked session.
 */
export function projectNativeOutcome(outcome: NativeOutcome): OutcomeDecision {
  if (outcome.outcome === 'ok') {
    switch (outcome.kind) {
      case 'locked':
        return { action: 'locked' };
      case 'unlocked':
        return { action: 'continue', kind: 'unlocked' };
      case 'verified':
        return { action: 'continue', kind: 'verified' };
      case 'provisioned':
        return { action: 'continue', kind: 'provisioned' };
      case 'removed':
        return { action: 'continue', kind: 'removed' };
      case 'preview':
        return { action: 'continue', kind: 'preview' };
      case 'revealPrepared':
      case 'signed':
      case 'datImported':
      case 'datExported':
        return { action: 'operationComplete', kind: outcome.kind };
    }
  }
  const code = outcome.code;
  switch (code) {
    case 'wrongPasswordOrDamagedData':
    case 'throttled':
    case 'kdfResourceLimit':
    case 'generationConflict':
    case 'storageUnavailable':
    case 'storageQuotaExceeded':
    case 'staleSession':
    case 'cleanupFailed':
    case 'networkTimeout':
    case 'providerLocked':
    case 'promptCancelled':
    case 'promptTimedOut':
    case 'providerTemporarilyUnavailable':
      return { action: 'retry', code };
    case 'platformProtectionInvalidated':
    case 'wrapperAmbiguous':
    case 'providerAbsent':
    case 'keyMismatch':
    case 'identityBindingMismatch':
      return { action: 'recover', code };
    default:
      // Unsupported/malformed/stale/forbidden — fail closed with a safe code.
      return { action: 'blocked', code };
  }
}

/** Fixed non-secret protection summary for the Security settings surface. */
export interface ProtectionSummary {
  readonly mode: 'osBacked' | 'passwordOnly';
  readonly fallbackAcknowledged: boolean;
  readonly upgradeEligibleAfterUnlock: boolean;
}

/**
 * Persist non-secret protection state only. The authenticated protection-mode
 * and acknowledgement state is allowed; nothing else from the vault persists
 * in the bridge.
 */
export function isSafeProtectionSummary(value: unknown): value is ProtectionSummary {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    (v.mode === 'osBacked' || v.mode === 'passwordOnly') &&
    typeof v.fallbackAcknowledged === 'boolean' &&
    typeof v.upgradeEligibleAfterUnlock === 'boolean'
  );
}
