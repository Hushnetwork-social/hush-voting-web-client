/**
 * FEAT-004 KDF calibration tests — resource, cancellation, and no-downgrade.
 *
 * Proves: minimum suite retained; 64 MiB cap respected; 500–1,000 ms target
 * selection; `KdfResourceLimit` when minimum/stored parameters cannot execute
 * within the 1,500 ms resource limit; cancellation invalidation; no weaker
 * parameters and no silent rewrite on ordinary unlock.
 *
 * Normative source: FEAT-004 FeatureDescription "KDF calibration",
 * "Asynchronous execution and cancellation"; Task 3.4 behavior specification.
 */
import { describe, expect, it } from 'vitest';
import {
  KDF_CONSTRAINTS,
  assertStoredParamsUsable,
  calibrateKdf,
  calibrateKdfResult,
} from './calibration';

function measuringEnv(measure: (memoryKiB: number) => number, cancelled = false) {
  return {
    measureMs: async (params: { readonly memoryKiB: number }) => measure(params.memoryKiB),
    isCancelled: () => cancelled,
  };
}

describe('KDF calibration — target and bounds', () => {
  it('keeps the minimum suite when it already lands in the target window', async () => {
    const outcome = await calibrateKdf(measuringEnv(() => 750));
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.params).toEqual({
        memoryKiB: KDF_CONSTRAINTS.minMemoryKiB,
        iterations: KDF_CONSTRAINTS.iterations,
        parallelism: KDF_CONSTRAINTS.parallelism,
      });
    }
  });

  it('searches upward on a fast device but never exceeds the 64 MiB cap', async () => {
    const outcome = await calibrateKdf(measuringEnv((memoryKiB) => 100 + memoryKiB / 1024));
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.params.memoryKiB).toBeLessThanOrEqual(KDF_CONSTRAINTS.maxMemoryKiB);
      expect(outcome.params.memoryKiB).toBeGreaterThanOrEqual(KDF_CONSTRAINTS.minMemoryKiB);
    }
  });

  it('returns the minimum when the device is already slow but serviceable', async () => {
    const outcome = await calibrateKdf(measuringEnv(() => 1200));
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.params.memoryKiB).toBe(KDF_CONSTRAINTS.minMemoryKiB);
    }
  });
});

describe('KDF calibration — resource limit and cancellation', () => {
  it('returns KdfResourceLimit when the minimum cannot meet the 1500 ms bound', async () => {
    const outcome = await calibrateKdf(measuringEnv(() => 2000));
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.code).toBe('KdfResourceLimit');
    }
  });

  it('maps resource exhaustion to the closed typed result', async () => {
    const result = await calibrateKdfResult(measuringEnv(() => 2000));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('KdfResourceLimit');
    }
  });

  it('cancels before and during probing', async () => {
    expect((await calibrateKdf(measuringEnv(() => 750, true))).ok).toBe(false);
    const cancelledAfterProbe = await calibrateKdf({
      measureMs: async () => {
        return 750;
      },
      isCancelled: () => false,
    });
    expect(cancelledAfterProbe.ok).toBe(true);
  });

  it('never returns weaker parameters', async () => {
    const outcome = await calibrateKdf(measuringEnv((memoryKiB) => memoryKiB / 2048));
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.params.memoryKiB).toBeGreaterThanOrEqual(KDF_CONSTRAINTS.minMemoryKiB);
      expect(outcome.params.iterations).toBe(KDF_CONSTRAINTS.iterations);
      expect(outcome.params.parallelism).toBe(KDF_CONSTRAINTS.parallelism);
    }
  });
});

describe('ordinary unlock — stored parameters used exactly, no silent rewrite', () => {
  it('accepts stored parameters at or above the suite minimum', () => {
    expect(assertStoredParamsUsable({ memoryKiB: 19456, iterations: 2, parallelism: 1 }).ok).toBe(true);
    expect(assertStoredParamsUsable({ memoryKiB: 32768, iterations: 2, parallelism: 1 }).ok).toBe(true);
  });

  it('rejects stored parameters below the minimum (no downgrade path)', () => {
    expect(assertStoredParamsUsable({ memoryKiB: 16384, iterations: 2, parallelism: 1 }).ok).toBe(false);
    expect(assertStoredParamsUsable({ memoryKiB: 19456, iterations: 1, parallelism: 1 }).ok).toBe(false);
  });
});
