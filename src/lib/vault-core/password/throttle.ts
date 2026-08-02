/**
 * FEAT-003 vault-core password — wrong-password throttle model.
 *
 * Failed device-password attempts are globally serialized per local vault:
 * attempts 1–4 pay the Argon2id computation cost without an added cooldown;
 * attempt 5 = 5 s, 6 = 10 s, 7 = 20 s, 8 = 40 s, 9 = 80 s, 10 = 160 s,
 * 11+ = 300 s maximum. All tabs observe the same sidecar counter/deadline;
 * restart does not reset it. Success, successful reprovisioning, or verified
 * local-user removal resets it. No failure automatically wipes or permanently
 * locks a vault.
 *
 * The sidecar is untrusted: malformed/missing/implausible values reset safely
 * rather than creating denial of service. This limitation is documented honestly.
 *
 * Normative source: FEAT-003 FeatureDescription "Wrong-password throttling".
 */
import { cooldownSecondsForAttempt, MAX_FAILED_PASSWORD_COUNT } from '../contracts/sidecar';

export interface ThrottleState {
  readonly failedPasswordCount: number;
  /** Epoch ms deadline; 0 = no active cooldown. */
  readonly cooldownDeadline: number;
}

export type ThrottleDecision =
  | { readonly ok: true; readonly cooldownSeconds: 0 }
  | { readonly ok: false; readonly cooldownSeconds: number; readonly retryDeadlineMs: number };

/** Evaluate an attempted password entry against the current throttle state. */
export function evaluateThrottle(state: ThrottleState, nowMs: number): ThrottleDecision {
  const sanitized = sanitizeState(state);
  if (sanitized.failedPasswordCount === 0 || sanitized.cooldownDeadline === 0) {
    return { ok: true, cooldownSeconds: 0 };
  }
  if (nowMs >= sanitized.cooldownDeadline) {
    return { ok: true, cooldownSeconds: 0 };
  }
  return {
    ok: false,
    cooldownSeconds: Math.ceil((sanitized.cooldownDeadline - nowMs) / 1000),
    retryDeadlineMs: sanitized.cooldownDeadline,
  };
}

/** Record a failed attempt (attempt number = current count + 1) and compute the new state. */
export function recordFailure(state: ThrottleState, nowMs: number): ThrottleState {
  const sanitized = sanitizeState(state);
  const nextCount = Math.min(sanitized.failedPasswordCount + 1, MAX_FAILED_PASSWORD_COUNT);
  const cooldown = cooldownSecondsForAttempt(nextCount);
  return {
    failedPasswordCount: nextCount,
    cooldownDeadline: cooldown === 0 ? 0 : nowMs + cooldown * 1000,
  };
}

/** Reset on success, successful reprovisioning, or verified removal. */
export function resetThrottle(): ThrottleState {
  return { failedPasswordCount: 0, cooldownDeadline: 0 };
}

/**
 * Sanitize untrusted sidecar throttle values. Missing, corrupt, rolled-back,
 * implausible, or extreme values reset to a safe bounded state with no denial of
 * service. Sidecar values are never authentication or integrity evidence.
 */
export function sanitizeState(input: ThrottleState | null | undefined): ThrottleState {
  if (input === null || input === undefined) return { failedPasswordCount: 0, cooldownDeadline: 0 };
  const count = Number.isSafeInteger(input.failedPasswordCount)
    ? Math.min(Math.max(0, input.failedPasswordCount), MAX_FAILED_PASSWORD_COUNT)
    : 0;
  const deadline = Number.isSafeInteger(input.cooldownDeadline) && input.cooldownDeadline >= 0
    ? Math.min(input.cooldownDeadline, Number.MAX_SAFE_INTEGER)
    : 0;
  if (deadline > 0 && count === 0) return { failedPasswordCount: 0, cooldownDeadline: 0 };
  return { failedPasswordCount: count, cooldownDeadline: deadline };
}
