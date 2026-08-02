/**
 * FEAT-004 browser-vault crypto — KDF calibration, resource, and cancellation.
 *
 * Bounded synthetic calibration runs only during initial provisioning, password
 * change, supported migration requiring re-protection, or recovery replacement:
 *
 * - retain at least FEAT-003's minimum 19 MiB / two iterations / parallelism 1;
 * - respect the 64 MiB browser cap;
 * - target the approved 500–1,000 ms window around approximately 750 ms;
 * - on resource exhaustion return `KdfResourceLimit`, preserve all encrypted
 *   bytes, and never downgrade to weaker parameters or a temporary identity.
 *
 * Ordinary unlock uses the authenticated stored parameters exactly and never
 * recalibrates or silently rewrites the vault. Cancellation invalidates the
 * operation epoch immediately; unacknowledged cleanup within the one-second
 * bound forces authority termination (authority-owned, Phase 4).
 *
 * Normative source: FEAT-004 FeatureDescription "KDF calibration",
 * "Asynchronous execution and cancellation".
 */
import { failure, success, type VaultResult } from '../../vault-core/contracts/results';

/** Closed suite constraints (FEAT-003 min + FEAT-004 browser cap). */
export const KDF_CONSTRAINTS = {
  minMemoryKiB: 19456, // 19 MiB
  iterations: 2,
  parallelism: 1,
  outputBytes: 32,
  maxMemoryKiB: 65536, // 64 MiB browser cap
  targetMinMs: 500,
  targetMaxMs: 1000,
  targetMs: 750,
  resourceLimitMs: 1500,
} as const;

export interface KdfParameters {
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
}

export type CalibrationOutcome =
  | { readonly ok: true; readonly params: KdfParameters }
  | { readonly ok: false; readonly code: 'KdfResourceLimit' | 'Cancelled' };

/** Injected KDF timing probe (synthetic input only; never real secret material). */
export interface CalibrationEnvironment {
  /** Measure one Argon2id run with the given parameters (synthetic bytes). */
  readonly measureMs: (params: KdfParameters) => Promise<number>;
  /** True when the operation has been cancelled (epoch invalidated). */
  readonly isCancelled: () => boolean;
  readonly constraints?: Partial<typeof KDF_CONSTRAINTS>;
}

/**
 * Calibrate bounded memory within [min, max] toward the target window using a
 * geometric probe. Returns the selected closed-suite parameters or a typed
 * resource/cancellation failure. Never returns weaker parameters.
 */
export async function calibrateKdf(env: CalibrationEnvironment): Promise<CalibrationOutcome> {
  const constraints = { ...KDF_CONSTRAINTS, ...(env.constraints ?? {}) };
  if (env.isCancelled()) {
    return { ok: false, code: 'Cancelled' };
  }
  const min: KdfParameters = {
    memoryKiB: constraints.minMemoryKiB,
    iterations: constraints.iterations,
    parallelism: constraints.parallelism,
  };
  const minMs = await env.measureMs(min);
  if (env.isCancelled()) {
    return { ok: false, code: 'Cancelled' };
  }
  if (minMs > constraints.resourceLimitMs) {
    // Minimum parameters cannot execute within the resource limit: preserve
    // bytes, recommend a capable browser/native path. No weaker parameters.
    return { ok: false, code: 'KdfResourceLimit' };
  }
  if (minMs >= constraints.targetMinMs && minMs <= constraints.targetMaxMs) {
    return { ok: true, params: min };
  }

  // Bounded geometric search upward from the minimum toward the cap.
  let memoryKiB = min.memoryKiB;
  let best: KdfParameters = min;
  let bestMs = minMs;
  while (memoryKiB < constraints.maxMemoryKiB) {
    const next = Math.min(Math.floor(memoryKiB * 1.5), constraints.maxMemoryKiB);
    const probe: KdfParameters = { ...min, memoryKiB: next };
    const ms = await env.measureMs(probe);
    if (env.isCancelled()) {
      return { ok: false, code: 'Cancelled' };
    }
    if (ms >= constraints.targetMinMs && ms <= constraints.targetMaxMs) {
      return { ok: true, params: probe };
    }
    if (ms < constraints.targetMinMs && Math.abs(ms - constraints.targetMs) < Math.abs(bestMs - constraints.targetMs)) {
      best = probe;
      bestMs = ms;
    }
    memoryKiB = next;
    if (ms > constraints.resourceLimitMs) {
      break; // probe exceeded the resource limit; do not go higher
    }
  }
  // No probe landed in the window; return the closest in-window-bounded result
  // at or below the cap, or fail closed when even the minimum is unserviceable.
  return bestMs <= constraints.resourceLimitMs ? { ok: true, params: best } : { ok: false, code: 'KdfResourceLimit' };
}

/** Wrapper returning the closed typed VaultResult for lifecycle callers. */
export async function calibrateKdfResult(env: CalibrationEnvironment): Promise<VaultResult<{ readonly params: KdfParameters }>> {
  const outcome = await calibrateKdf(env);
  if (outcome.ok) {
    return success({ params: outcome.params });
  }
  if (outcome.code === 'KdfResourceLimit') {
    return failure('KdfResourceLimit');
  }
  return failure('OperationForbidden'); // cancellation surfaces as forbidden/stale to the caller
}

/** Authenticate-and-use: ordinary unlock never recalibrates or silently rewrites. */
export function assertStoredParamsUsable(params: KdfParameters): VaultResult<{ readonly ok: true }> {
  if (params.memoryKiB < KDF_CONSTRAINTS.minMemoryKiB || params.iterations < KDF_CONSTRAINTS.iterations) {
    return failure('KdfResourceLimit');
  }
  return success({ ok: true });
}
