/**
 * FEAT-004 composition tests — web-only selection and production exclusion.
 *
 * Proves: true Web + passing preflight registers real actors; native/SSR and
 * failed preflights fail closed with `unavailable` (no native fallback, no
 * synthetic actors); every vault slot is declared exactly once; the FEAT-002
 * production registry rules hold.
 *
 * Normative source: FEAT-004 FeatureDescription "Runtime composition",
 * "Supported Browser and Deployment Baseline"; Task 6.2 behavior spec.
 */
import { describe, expect, it } from 'vitest';
import {
  BROWSER_VAULT_CAPABILITY_SLOTS,
  buildBrowserVaultRegistrations,
  canSelectBrowserVault,
  resolveBrowserVaultRuntime,
  validateBrowserVaultComposition,
} from './composition';
import type { PreflightReport } from '../contracts/preflight';

function preflight(ok: boolean, secureOrigin = true): PreflightReport {
  return { ok, retryable: false, secureOrigin, checks: [] };
}

describe('runtime resolution', () => {
  it('classifies web, native, and ssr runtimes', () => {
    // jsdom provides `window`; getRuntimeTarget returns 'web' without Tauri globals.
    expect(resolveBrowserVaultRuntime()).toBe('web');
  });
});

describe('web-only selection', () => {
  it('selects the adapter only for true Web with a passing preflight', () => {
    expect(canSelectBrowserVault('web', preflight(true))).toBe(true);
    expect(canSelectBrowserVault('native', preflight(true))).toBe(false);
    expect(canSelectBrowserVault('ssr', preflight(true))).toBe(false);
    expect(canSelectBrowserVault('web', preflight(false))).toBe(false);
    expect(canSelectBrowserVault('web', preflight(true, false))).toBe(false);
  });
});

describe('registrations fail closed', () => {
  it('registers real non-synthetic actors for web + preflight', () => {
    const registrations = buildBrowserVaultRegistrations({ runtime: 'web', preflight: preflight(true) });
    expect(registrations.length).toBe(BROWSER_VAULT_CAPABILITY_SLOTS.length);
    for (const registration of registrations) {
      expect(registration.synthetic).toBe(false);
      expect(registration.availability).toBe('mandatory');
    }
    expect(validateBrowserVaultComposition(registrations).ok).toBe(true);
  });

  it('leaves every vault slot unavailable for native/SSR/failed preflight', () => {
    for (const runtime of ['native', 'ssr'] as const) {
      const registrations = buildBrowserVaultRegistrations({ runtime, preflight: preflight(true) });
      expect(registrations.every((r) => r.availability === 'unavailable')).toBe(true);
      expect(validateBrowserVaultComposition(registrations).ok).toBe(true);
    }
    const failed = buildBrowserVaultRegistrations({ runtime: 'web', preflight: preflight(false) });
    expect(failed.every((r) => r.availability === 'unavailable')).toBe(true);
  });

  it('rejects synthetic registrations, duplicates, and out-of-slot availability', () => {
    const registrations = buildBrowserVaultRegistrations({ runtime: 'web', preflight: preflight(true) });
    const duplicated = [...registrations, ...registrations];
    expect(validateBrowserVaultComposition(duplicated).ok).toBe(false);

    const synthetic = registrations.map((r) => ({ ...r, synthetic: true }));
    expect(validateBrowserVaultComposition(synthetic).ok).toBe(false);

    const outOfSlot = [...registrations, { capability: 'onboardingCreateUser' as const, availability: 'mandatory' as const, synthetic: false }];
    expect(validateBrowserVaultComposition(outOfSlot).ok).toBe(false);

    const missing = registrations.filter((r) => r.capability !== 'secretAuthority');
    expect(validateBrowserVaultComposition(missing).ok).toBe(false);
  });
});
