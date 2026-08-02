/**
 * FEAT-004 browser-vault integration — web-only production composition.
 *
 * The production browser adapter registers ONLY for true Web after mandatory
 * capability preflight succeeds. Native (Tauri) and SSR runtimes, insecure
 * origins, and unsupported capabilities FAIL CLOSED: the FEAT-002 registry
 * slots stay `unavailable` and protected content remains unavailable with
 * typed guidance. Ubuntu/Android builds prove through production-exclusion
 * tests that this adapter can never be selected or silently fall back.
 *
 * FEAT-002 remains the sole UI/auth orchestration authority: this module only
 * declares which capability slots the browser adapter backs and whether the
 * real (non-synthetic) actors may register. Synthetic/test actors never
 * satisfy production registrations.
 *
 * Normative source: FEAT-004 FeatureDescription "Runtime composition",
 * "Capability Preflight"; FEAT-002 `src/lib/auth/registry.ts`;
 * FEAT-003 `src/lib/vault-core/integration/composition.ts`.
 */
import type { CapabilityRegistration } from '../../auth/ports';
import type { CapabilityId } from '../../auth/types';
import type { PreflightReport } from '../contracts/preflight';
import { getRuntimeTarget } from '../../runtime/runtime-target';

/** Browser-vault runtime classification. */
export type BrowserVaultRuntime = 'web' | 'native' | 'ssr';

/** Resolve the runtime for FEAT-004 selection (never user-agent based). */
export function resolveBrowserVaultRuntime(): BrowserVaultRuntime {
  const target = getRuntimeTarget();
  if (target === 'tauri') {
    return 'native';
  }
  if (typeof window === 'undefined') {
    return 'ssr';
  }
  return 'web';
}

/** Vault-backed capability slots (FEAT-003 vocabulary). */
export const BROWSER_VAULT_CAPABILITY_SLOTS: readonly CapabilityId[] = [
  'localUserAuthority',
  'secretAuthority',
  'identityVerification',
  'browserCoordination',
];

/**
 * Decide whether the browser adapter may register. True only for true Web with
 * a passing preflight; every other combination fails closed.
 */
export function canSelectBrowserVault(runtime: BrowserVaultRuntime, preflight: PreflightReport): boolean {
  return runtime === 'web' && preflight.ok && preflight.secureOrigin;
}

/**
 * Build the production capability registrations for the FEAT-002 registry.
 * Non-web runtimes and failed preflights yield `unavailable` registrations so
 * the composition fails closed; they never produce a native fallback.
 */
export function buildBrowserVaultRegistrations(params: {
  readonly runtime: BrowserVaultRuntime;
  readonly preflight: PreflightReport;
}): readonly CapabilityRegistration[] {
  const selectable = canSelectBrowserVault(params.runtime, params.preflight);
  // FEAT-002 vocabulary: 'mandatory' (present, non-synthetic, required) or
  // 'unavailable' (fail closed). No 'available' literal exists by design.
  const availability = selectable ? 'mandatory' : 'unavailable';
  return BROWSER_VAULT_CAPABILITY_SLOTS.map((capability) => ({
    capability,
    availability,
    synthetic: false,
  }));
}

/** Validate the registrations against FEAT-002's production registry rules. */
export function validateBrowserVaultComposition(registrations: readonly CapabilityRegistration[]): {
  readonly ok: boolean;
  readonly diagnostics: readonly string[];
} {
  const diagnostics: string[] = [];
  const seen = new Set<CapabilityId>();
  for (const registration of registrations) {
    if (seen.has(registration.capability)) {
      diagnostics.push(`duplicate registration: ${registration.capability}`);
    }
    seen.add(registration.capability);
    if (registration.synthetic) {
      diagnostics.push(`synthetic registration in production: ${registration.capability}`);
    }
    if (registration.availability === 'mandatory' && !BROWSER_VAULT_CAPABILITY_SLOTS.includes(registration.capability)) {
      diagnostics.push(`mandatory capability outside the browser-vault slots: ${registration.capability}`);
    }
  }
  for (const required of BROWSER_VAULT_CAPABILITY_SLOTS) {
    if (!seen.has(required)) {
      diagnostics.push(`missing vault slot: ${required}`);
    }
  }
  return { ok: diagnostics.length === 0, diagnostics };
}
