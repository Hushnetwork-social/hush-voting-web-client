/**
 * FEAT-010 auth contracts — lifecycle, timing, fresh-authorization, and
 * lock-policy contracts (Task 2.7).
 *
 * Locks the exact approved policy choices, trusted activity classes,
 * reconnect schedule, fresh-authorization semantics, and lock-policy mutation
 * contract (normative: FeatureDescription "Lock and Session Lifecycle",
 * "Activity and timing", "Identity and Security Settings"; AC-010-056…065).
 *
 * Framework-neutral, secret-free.
 */

/** Idle-lock choices (minutes or until restart). */
export type IdleLockChoice = 1 | 5 | 15 | 30 | 60 | 'until-restart';
/** Background/screen-off lock choices (seconds/minutes or until restart). */
export type BackgroundLockChoice = 'immediate' | 30 | 120 | 300 | 900 | 'until-restart';

/** Exact defaults (AC-010-058). */
export const IDLE_LOCK_DEFAULT: IdleLockChoice = 5;
export const BACKGROUND_LOCK_DEFAULT: BackgroundLockChoice = 30;

/** Approved idle choices with one-time-warning requirement. */
export const APPROVED_IDLE_CHOICES: readonly IdleLockChoice[] = [1, 5, 15, 30, 60, 'until-restart'] as const;
/** Approved background choices with one-time-warning requirement. */
export const APPROVED_BACKGROUND_CHOICES: readonly BackgroundLockChoice[] = ['immediate', 30, 120, 300, 900, 'until-restart'] as const;

/** Choices weaker than the defaults require a one-time warning. */
export function requiresOneTimeWarningIdle(choice: IdleLockChoice): boolean {
  return choice === 1 || choice === 'until-restart';
}
export function requiresOneTimeWarningBackground(choice: BackgroundLockChoice): boolean {
  return choice === 'immediate' || choice === 900 || choice === 'until-restart';
}

/** Aggregate trusted activity classes that reset the shared idle timer. */
export type TrustedActivityClass = 'keyboard' | 'pointer' | 'touch' | 'wheelScroll' | 'accessibility';

export const TRUSTED_ACTIVITY_CLASSES: readonly TrustedActivityClass[] = [
  'keyboard',
  'pointer',
  'touch',
  'wheelScroll',
  'accessibility',
] as const;

/** Activity signals that NEVER reset idle (synthetic/timers/media/animation/network/background). */
export type UntrustedActivityClass = 'synthetic' | 'timer' | 'media' | 'animation' | 'network' | 'backgroundSync';

/** Reconnect schedule (bounded foreground-only; AC-010-048). */
export const RECONNECT_STEPS_MS: readonly number[] = [2_000, 5_000, 10_000, 30_000] as const;
/** Bounded jitter interval after the fixed steps. */
export const RECONNECT_JITTER_INTERVAL_MS = 30_000 as const;
/** One coalesced user retry is permitted. */
export const RECONNECT_COALESCED_RETRIES = 1 as const;

/** Fresh-authorization purpose (one authorization authorizes exactly one). */
export type FreshAuthorizationPurpose =
  | 'lock-policy-change'
  | 'device-password-change'
  | 'protection-mode-change'
  | 'export-elevation';

/** Fresh-authorization lifetime bound (AC-010-064). */
export const FRESH_AUTHORIZATION_MAX_AGE_MS = 60_000 as const;

/** Invalidation events that destroy a fresh authorization. */
export type FreshAuthorizationInvalidation =
  | 'used'
  | 'expired'
  | 'navigation'
  | 'foregroundLoss'
  | 'lock'
  | 'epochLoss'
  | 'authorityLoss'
  | 'removal';

/** One-use purpose-scoped fresh authorization (opaque, non-persisted). */
export interface FreshAuthorization {
  readonly id: string;
  readonly purpose: FreshAuthorizationPurpose;
  readonly issuedAtMs: number;
  readonly maxAgeMs: number;
}

/** Verdict for presenting a fresh authorization at a mutation. */
export type FreshAuthorizationVerdict =
  | { readonly kind: 'valid' }
  | { readonly kind: 'wrongPurpose' }
  | { readonly kind: 'expired' }
  | { readonly kind: 'invalidated' }
  | { readonly kind: 'alreadyUsed' };

/** Evaluate a fresh authorization presentation. */
export function evaluateFreshAuthorization(
  authorization: FreshAuthorization | null | undefined,
  purpose: FreshAuthorizationPurpose,
  nowMs: number,
  invalidation: FreshAuthorizationInvalidation | 'none',
): FreshAuthorizationVerdict {
  if (authorization === null || authorization === undefined) {
    return { kind: 'invalidated' };
  }
  if (authorization.purpose !== purpose) {
    return { kind: 'wrongPurpose' };
  }
  if (nowMs - authorization.issuedAtMs > authorization.maxAgeMs) {
    return { kind: 'expired' };
  }
  if (invalidation !== 'none') {
    return { kind: 'invalidated' };
  }
  return { kind: 'valid' };
}

/** Lock-policy settings stored as encrypted generation-CAS metadata. */
export interface LockPolicySettings {
  readonly idleLock: IdleLockChoice;
  readonly backgroundLock: BackgroundLockChoice;
  /** Monotonic generation for CAS/read-back commits. */
  readonly generation: number;
}

/** Lock-policy mutation outcome (AC-010-065). */
export type LockPolicyMutationVerdict =
  | { readonly kind: 'committed' }
  | { readonly kind: 'generationConflict' }
  | { readonly kind: 'readBackMismatch' }
  | { readonly kind: 'invalidChoice' };

/**
 * Validate a lock-policy mutation: exact approved choices, expected
 * generation CAS, and read-back verification. A newly selected threshold
 * already exceeded by current elapsed time must cause immediate Lock (the
 * caller applies this after a successful commit).
 */
export function prepareLockPolicyMutation(
  current: LockPolicySettings,
  proposed: { readonly idleLock: IdleLockChoice; readonly backgroundLock: BackgroundLockChoice },
  expectedGeneration: number,
  readBackMatches: boolean,
): LockPolicyMutationVerdict {
  if (!APPROVED_IDLE_CHOICES.includes(proposed.idleLock) || !APPROVED_BACKGROUND_CHOICES.includes(proposed.backgroundLock)) {
    return { kind: 'invalidChoice' };
  }
  if (current.generation !== expectedGeneration) {
    return { kind: 'generationConflict' };
  }
  if (!readBackMatches) {
    return { kind: 'readBackMismatch' };
  }
  return { kind: 'committed' };
}

/** Whether the new policy is already exceeded by the elapsed idle/background time. */
export function isNewPolicyAlreadyExceeded(
  proposed: LockPolicySettings,
  elapsedIdleMs: number,
  elapsedBackgroundMs: number,
): boolean {
  const idleExceeded = proposed.idleLock !== 'until-restart' && elapsedIdleMs > proposed.idleLock * 60_000;
  const backgroundExceeded = proposed.backgroundLock !== 'until-restart' && proposed.backgroundLock !== 'immediate' && elapsedBackgroundMs > proposed.backgroundLock * 1000;
  const immediateBackground = proposed.backgroundLock === 'immediate' && elapsedBackgroundMs > 0;
  return idleExceeded || backgroundExceeded || immediateBackground;
}
