/**
 * FEAT-004 preflight contract tests — capability matrix and safe codes.
 *
 * Proves: unsupported vs temporary storage denial are distinct; mandatory
 * checks fail closed; retryable reports are flagged; deterministic codes never
 * leak raw platform messages.
 *
 * Normative source: FEAT-004 FeatureDescription "Capability Preflight";
 * Task 2.2 behavior specification.
 */
import { describe, expect, it } from 'vitest';
import { preflightCode, runCapabilityPreflight, type BrowserPreflightEnvironment } from './preflight';

function env(overrides: Partial<BrowserPreflightEnvironment> = {}): BrowserPreflightEnvironment {
  return {
    isSecureContext: true,
    indexedDBAvailable: () => true,
    probeIndexedDb: async () => 'ok',
    webCryptoAvailable: () => true,
    hkdfAvailable: async () => true,
    aesGcmAvailable: async () => true,
    cryptoRandomAvailable: () => true,
    moduleWorkerAvailable: () => true,
    sharedWorkerAvailable: () => true,
    webLockAvailable: () => true,
    storageEstimateAvailable: () => true,
    storagePersistedAvailable: () => true,
    ...overrides,
  };
}

describe('preflight — healthy environment', () => {
  it('reports ok with no retry and PREFLIGHT_OK code', async () => {
    const report = await runCapabilityPreflight(env());
    expect(report.ok).toBe(true);
    expect(report.retryable).toBe(false);
    expect(report.secureOrigin).toBe(true);
    expect(preflightCode(report)).toBe('PREFLIGHT_OK');
  });
});

describe('preflight — fail-closed and distinct classifications', () => {
  it('rejects insecure origin with INSECURE_ORIGIN', async () => {
    const report = await runCapabilityPreflight(env({ isSecureContext: false }));
    expect(report.ok).toBe(false);
    expect(preflightCode(report)).toBe('INSECURE_ORIGIN');
  });

  it('distinguishes temporary storage denial from unavailable storage', async () => {
    const temporary = await runCapabilityPreflight(env({ probeIndexedDb: async () => 'temporary' }));
    expect(temporary.retryable).toBe(true);
    expect(preflightCode(temporary)).toBe('TEMPORARY_STORAGE_DENIED');

    const unavailable = await runCapabilityPreflight(env({ probeIndexedDb: async () => 'unavailable' }));
    expect(unavailable.ok).toBe(false);
    expect(preflightCode(unavailable)).toBe('STORAGE_UNAVAILABLE');
  });

  it('rejects missing crypto/randomness/worker with distinct codes', async () => {
    expect(preflightCode(await runCapabilityPreflight(env({ hkdfAvailable: async () => false })))).toBe('CRYPTO_UNAVAILABLE');
    expect(preflightCode(await runCapabilityPreflight(env({ cryptoRandomAvailable: () => false })))).toBe('RANDOM_UNAVAILABLE');
    expect(preflightCode(await runCapabilityPreflight(env({ moduleWorkerAvailable: () => false })))).toBe('WORKER_UNAVAILABLE');
  });

  it('rejects when both shared worker and web lock are missing (no coordination)', async () => {
    const report = await runCapabilityPreflight(env({ sharedWorkerAvailable: () => false, webLockAvailable: () => false }));
    expect(report.ok).toBe(false);
    expect(preflightCode(report)).toBe('COORDINATION_UNAVAILABLE');
  });

  it('fails closed on unknown capability (cannot prove safety)', async () => {
    const report = await runCapabilityPreflight(env({ storageEstimateAvailable: () => false }));
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.check === 'storageEstimate')?.status).toBe('unknown');
  });
});

describe('preflight — detail codes are deterministic and raw-error free', () => {
  it('every report detail is a bounded safe code', async () => {
    const report = await runCapabilityPreflight(env({ probeIndexedDb: async () => 'temporary' }));
    for (const check of report.checks) {
      expect(check.detail).toMatch(/^[A-Z0-9_]+$/);
      expect(check.detail.length).toBeLessThanOrEqual(64);
    }
  });
});
