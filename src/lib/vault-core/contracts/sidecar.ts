/**
 * FEAT-003 vault-core contracts — operational sidecar v1.
 *
 * Non-secret active-pointer/journal/removal/cooldown data. Bounded and treated as
 * mutable/untrusted: missing, corrupt, rolled-back, implausible, or extreme cooldown data
 * resets safely with a sanitized local diagnostic. Sidecar values are never authentication
 * or integrity evidence; they cannot destroy the vault or create indefinite lockout.
 * Browser-local throttling remains bypassable by a determined local attacker (documented).
 *
 * Normative source: FEAT-003 FeatureDescription "Operational sidecar", "Wrong-password
 * throttling".
 */

/** Removal cleanup stages (idempotent resume order). */
export type RemovalStage =
  | 'revoking-session'
  | 'persisting-tombstone'
  | 'deleting-slots'
  | 'deleting-keys'
  | 'clearing-caches'
  | 'verifying-absence';

export const REMOVAL_STAGES: readonly RemovalStage[] = [
  'revoking-session',
  'persisting-tombstone',
  'deleting-slots',
  'deleting-keys',
  'clearing-caches',
  'verifying-absence',
] as const;

export interface RemovalTombstoneV1 {
  readonly inProgress: true;
  readonly startedAt: number;
  readonly stage: RemovalStage;
}

/** Exact wrong-password cooldown schedule (attempt index → added seconds). */
export const THROTTLE_SCHEDULE: readonly (number | null)[] = [
  null, // attempt 1: no added cooldown
  null, // attempt 2
  null, // attempt 3
  null, // attempt 4
  5, // attempt 5
  10, // attempt 6
  20, // attempt 7
  40, // attempt 8
  80, // attempt 9
  160, // attempt 10
  300, // attempt 11
] as const;

/** Cap for attempt 12 and later. */
export const THROTTLE_MAX_SECONDS = 300 as const;

/** Bounded failed-attempt counter (0–255). */
export const MAX_FAILED_PASSWORD_COUNT = 255 as const;

/** Operational sidecar v1. */
export interface VaultSidecarV1 {
  readonly activeGeneration: number;
  readonly rollbackGeneration?: number;
  readonly failedPasswordCount: number;
  /** Epoch ms deadline; 0 = no active cooldown. */
  readonly cooldownDeadline: number;
  readonly removalTombstone: RemovalTombstoneV1 | null;
  readonly extensions?: Readonly<Record<string, unknown>>;
}

/** Deterministic cooldown seconds for a failed-attempt count (after the 11th attempt). */
export function cooldownSecondsForAttempt(attemptNumber: number): number {
  if (attemptNumber < 1) return 0;
  if (attemptNumber - 1 < THROTTLE_SCHEDULE.length) {
    return THROTTLE_SCHEDULE[attemptNumber - 1] ?? THROTTLE_MAX_SECONDS;
  }
  return THROTTLE_MAX_SECONDS;
}
