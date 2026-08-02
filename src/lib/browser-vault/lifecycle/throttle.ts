/**
 * FEAT-004 browser-vault lifecycle — persisted password throttling.
 *
 * Serializes failed-password state across tabs and restarts through the
 * allowlisted `throttle` sidecar. Uses the FEAT-003 exact cooldown schedule.
 * The counter increments ONCE only when minimum KDF work completes and
 * authenticated decryption returns `WrongPasswordOrDamagedData`; it never
 * increments for preflight/capability failure, malformed envelope detected
 * before authentication, cancellation, stale epoch, storage/quota failure,
 * connectivity failure, worker crash, or update mismatch. Success, verified
 * reprovisioning, or completed local removal resets it.
 *
 * Normative source: FEAT-004 FeatureDescription "Password Throttling";
 * FEAT-003 `password/throttle.ts` + `contracts/sidecar.ts`.
 */
import { success, type VaultResult } from '../../vault-core/contracts/results';
import { evaluateThrottle, recordFailure, resetThrottle, type ThrottleState } from '../../vault-core/password/throttle';
import type { VaultStorageSession } from '../storage/wrapper';

const THROTTLE_SIDECAR_KEY = 'throttle' as const;

/** Persistence port over the storage session (sidecar only, never secrets). */
export interface ThrottlePort {
  readonly readState: () => Promise<VaultResult<{ readonly state: ThrottleState }>>;
  readonly writeState: (state: ThrottleState) => Promise<VaultResult<{ readonly ok: true }>>;
}

export function createThrottlePort(session: VaultStorageSession): ThrottlePort {
  return {
    async readState() {
      const outcome = await session.readRecord('operationalSidecars', THROTTLE_SIDECAR_KEY);
      if (!outcome.ok) {
        return outcome;
      }
      const value = outcome.value.record;
      if (value === undefined) {
        return success({ state: resetThrottle() });
      }
      const sanitized: ThrottleState = {
        failedPasswordCount: typeof (value as ThrottleState).failedPasswordCount === 'number' ? (value as ThrottleState).failedPasswordCount : 0,
        cooldownDeadline: typeof (value as ThrottleState).cooldownDeadline === 'number' ? (value as ThrottleState).cooldownDeadline : 0,
      };
      return success({ state: sanitized });
    },
    async writeState(state) {
      const outcome = await session.writeRecord('operationalSidecars', THROTTLE_SIDECAR_KEY, state);
      return outcome.ok ? success({ ok: true as const }) : outcome;
    },
  };
}

export type ThrottleDecision = { readonly allowed: boolean; readonly retryDeadlineMs?: number; readonly cooldownSeconds?: number };

/** Evaluate the current throttle before starting a password operation. */
export async function checkThrottle(port: ThrottlePort, nowMs: number): Promise<VaultResult<{ readonly decision: ThrottleDecision }>> {
  const read = await port.readState();
  if (!read.ok) {
    return read;
  }
  const decision = evaluateThrottle(read.value.state, nowMs);
  if (decision.ok) {
    return success({ decision: { allowed: true } });
  }
  return success({
    decision: { allowed: false, retryDeadlineMs: decision.retryDeadlineMs, cooldownSeconds: decision.cooldownSeconds },
  });
}

/**
 * Record one failed authenticated-decryption outcome. Callers MUST invoke this
 * only when minimum KDF work completed and decryption returned
 * `WrongPasswordOrDamagedData` — never for preflight/malformed/cancel/storage
 * outcomes.
 */
export async function recordPasswordFailure(port: ThrottlePort, nowMs: number): Promise<VaultResult<{ readonly state: ThrottleState }>> {
  const read = await port.readState();
  if (!read.ok) {
    return read;
  }
  const next = recordFailure(read.value.state, nowMs);
  const write = await port.writeState(next);
  return write.ok ? success({ state: next }) : write;
}

/** Reset the counter (successful unlock, verified reprovisioning, completed removal). */
export async function resetPasswordThrottle(port: ThrottlePort): Promise<VaultResult<{ readonly ok: true }>> {
  return port.writeState(resetThrottle());
}

/** Helper: storage/quota/preflight failures never increment the counter. */
export function assertNeverIncrementsOutcome(reason: string): never {
  throw new Error(`throttle must not increment for: ${reason}`);
}
