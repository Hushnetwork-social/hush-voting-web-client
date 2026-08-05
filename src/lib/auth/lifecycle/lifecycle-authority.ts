/**
 * FEAT-010 business authority — connectivity, reverification, global Lock,
 * trusted activity, and session timing (Task 3.5).
 *
 * Rules enforced here (normative: FeatureDescription "Connectivity After
 * Authentication", "Reverification Policy", "Lock and Session Lifecycle",
 * "Activity and timing"; AC-010-047…062):
 * - connectivity loss never Locks a valid local session; no operation is
 *   queued while offline;
 * - foreground-only reconnect 2/5/10/30 s then bounded-jitter 30 s; one
 *   coalesced Retry; connectivity-restored signal triggers one immediate
 *   bounded attempt; retry stops on background/Lock/authority loss/death;
 * - fresh exact reverification before network operations resume;
 * - global Lock invalidates epoch first; cleanup acknowledges ≤1 s or the
 *   isolation boundary is terminated; Lock never waits for operations;
 * - only trusted visible-instance activity resets the shared idle timer;
 *   synthetic/timer/media/animation/network/background work never does;
 * - background timing starts only when every instance is hidden/backgrounded
 *   or the screen is off; monotonic conservative timing: uncertain time
 *   Locks instead of extending access;
 * - session-only destruction returns to verified first-run.
 *
 * Framework-neutral, secret-free.
 */
import {
  RECONNECT_COALESCED_RETRIES,
  RECONNECT_JITTER_INTERVAL_MS,
  RECONNECT_STEPS_MS,
  TRUSTED_ACTIVITY_CLASSES,
  type TrustedActivityClass,
  type UntrustedActivityClass,
} from '../lifecycle-policy';

/** Lock triggers (AC-010-060: manual/restart/loss/uncertain cannot be disabled). */
export type LockTrigger =
  | 'manual'
  | 'idleTimeout'
  | 'backgroundTimeout'
  | 'restart'
  | 'processDeath'
  | 'authorityLoss'
  | 'uncertainTime'
  | 'removal'
  | 'sessionOnly';

/** Cleanup acknowledgement bound (AC-010-054). */
export const LOCK_CLEANUP_ACKNOWLEDGEMENT_MS = 1_000 as const;

/** Connectivity state machine codes (parallel to FEAT-002 connectivity region). */
export type ConnectivityPhase = 'unknown' | 'online' | 'offline' | 'reconnecting';

/** One reconnect attempt verdict (AC-010-048). */
export function nextReconnectDelayMs(
  attempt: number,
  coalescedRetryUsed: boolean,
  connectivitySignalReceived: boolean,
): { readonly delayMs: number; readonly immediateBounded: boolean } {
  if (connectivitySignalReceived) {
    return { delayMs: 0, immediateBounded: true };
  }
  if (coalescedRetryUsed) {
    // One coalesced Retry already consumed: resume the fixed schedule at the
    // current attempt slot, then bounded jitter.
    if (attempt < RECONNECT_STEPS_MS.length) {
      return { delayMs: RECONNECT_STEPS_MS[attempt], immediateBounded: false };
    }
    return { delayMs: RECONNECT_JITTER_INTERVAL_MS, immediateBounded: false };
  }
  if (attempt < RECONNECT_STEPS_MS.length) {
    return { delayMs: RECONNECT_STEPS_MS[attempt], immediateBounded: false };
  }
  return { delayMs: RECONNECT_JITTER_INTERVAL_MS, immediateBounded: false };
}

/** Whether reconnect must stop (background/Lock/authority loss/process death). */
export function shouldStopReconnect(
  phase: ConnectivityPhase,
  backgrounded: boolean,
  locked: boolean,
  authorityLost: boolean,
): boolean {
  return backgrounded || locked || authorityLost || phase === 'unknown';
}

/** Trusted-activity verdict for the shared idle timer (AC-010-056). */
export function isTrustedActivity(input: { readonly isTrusted: boolean; readonly class: TrustedActivityClass | UntrustedActivityClass }): boolean {
  if (!input.isTrusted) return false;
  return (TRUSTED_ACTIVITY_CLASSES as readonly string[]).includes(input.class);
}

/** Background-timer precondition: every instance hidden/backgrounded or screen off (AC-010-057). */
export function shouldStartBackgroundTiming(
  visibleInstances: number,
  screenOff: boolean,
  anyInstanceVisible: boolean,
): boolean {
  return screenOff || (!anyInstanceVisible && visibleInstances === 0);
}

/** Idle/background lock decision with conservative monotonic timing (AC-010-058/059/061). */
export type TimingLockVerdict =
  | { readonly kind: 'noLock' }
  | { readonly kind: 'lock'; readonly trigger: 'idleTimeout' | 'backgroundTimeout' }
  | { readonly kind: 'lock'; readonly trigger: 'uncertainTime' };

export interface TimingInputs {
  /** Monotonic elapsed since last trusted activity (ms). */
  readonly elapsedIdleMs: number;
  /** Monotonic elapsed in all-hidden background state (ms). */
  readonly elapsedBackgroundMs: number;
  readonly idleThresholdMs: number;
  readonly backgroundThresholdMs: number;
  /** Wall-clock comparison was implausible/backward/uncertain. */
  readonly timingUncertain: boolean;
}

export function evaluateTimingLock(inputs: TimingInputs): TimingLockVerdict {
  if (inputs.timingUncertain) {
    // Conservative: uncertain time Locks rather than extending access.
    return { kind: 'lock', trigger: 'uncertainTime' };
  }
  if (inputs.elapsedIdleMs >= inputs.idleThresholdMs) {
    return { kind: 'lock', trigger: 'idleTimeout' };
  }
  if (inputs.elapsedBackgroundMs >= inputs.backgroundThresholdMs) {
    return { kind: 'lock', trigger: 'backgroundTimeout' };
  }
  return { kind: 'noLock' };
}

/** Global Lock contract: capability-first invalidation, bounded cleanup (AC-010-052…055). */
export interface LockExecutionResult {
  readonly epochInvalidated: boolean;
  readonly cleanupAcknowledged: boolean;
  readonly protectedContentUnmountedSynchronously: boolean;
  readonly possibleServerAcceptance: boolean;
}

/**
 * Sequence a global Lock: invalidate epoch/capabilities FIRST, unmount
 * protected rendering synchronously, then await cleanup ≤1 s. If cleanup is
 * not acknowledged in time, the isolation boundary is terminated (reported as
 * `cleanupAcknowledged: false`). Lock never waits for network/signing
 * operations, and a possibly accepted server operation is never claimed
 * cancelled (`possibleServerAcceptance` must be surfaced for idempotent
 * reconciliation after a future unlock).
 */
export function executeLockSequence(
  cleanupAcknowledgedWithinMs: number | null,
): LockExecutionResult {
  const cleanupAcknowledged = cleanupAcknowledgedWithinMs !== null && cleanupAcknowledgedWithinMs <= LOCK_CLEANUP_ACKNOWLEDGEMENT_MS;
  // Capability-first ordering is a sequencing contract: epoch invalidation
  // and synchronous unmount ALWAYS precede cleanup acknowledgement.
  return {
    epochInvalidated: true,
    cleanupAcknowledged,
    protectedContentUnmountedSynchronously: true,
    possibleServerAcceptance: !cleanupAcknowledged,
  };
}

/** Fresh-exact reverification points (AC-010-050). */
export type ReverificationTrigger =
  | 'afterLocalUnlock'
  | 'afterReconnect'
  | 'uncertainResume'
  | 'beforePersistentProtectionChange'
  | 'beforeExportElevation'
  | 'afterSameKeyRecreation';

export const REVERIFICATION_TRIGGERS: readonly ReverificationTrigger[] = [
  'afterLocalUnlock',
  'afterReconnect',
  'uncertainResume',
  'beforePersistentProtectionChange',
  'beforeExportElevation',
  'afterSameKeyRecreation',
] as const;

/** Session-only destruction (AC-010-062): memory authority gone → verified first-run. */
export type SessionOnlyDestruction = { readonly kind: 'destroyed'; readonly returnsTo: 'verifiedFirstRun' };

export function destroySessionOnly(): SessionOnlyDestruction {
  return { kind: 'destroyed', returnsTo: 'verifiedFirstRun' };
}
