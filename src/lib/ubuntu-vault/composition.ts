/**
 * FEAT-005 Ubuntu vault production composition (Task 6.1).
 *
 * The Ubuntu native adapter registers its capability slots ONLY for the Tauri
 * desktop runtime when the exact native/WebView build+protocol handshake and
 * the bounded native preflight pass. Web, SSR, Android, mismatched builds,
 * and failed preflights FAIL CLOSED: the FEAT-002 registry slots stay
 * `unavailable` and protected content remains unavailable with typed
 * guidance. No browser-vault fallback is ever selected in native builds, and
 * synthetic/test actors never satisfy production registrations.
 *
 * FEAT-002 remains the sole UI/auth orchestration authority: this module only
 * declares which capability slots the Ubuntu adapter backs and whether the
 * real (non-synthetic) actors may register.
 *
 * Normative source: FEAT-005 FeatureDescription "Tauri IPC and Native
 * Session", "WebView/native handshake"; FEAT-002 `src/lib/auth/registry.ts`;
 * FEAT-003 `src/lib/vault-core/integration/composition.ts`; FEAT-004
 * `src/lib/browser-vault/integration/composition.ts` (mirror, native side).
 */
import type { CapabilityRegistration } from '../auth/ports';
import type { CapabilityId } from '../auth/types';
import { getRuntimeTarget } from '../runtime/runtime-target';

/** Ubuntu native runtime classification (never user-agent based). */
export type UbuntuRuntime = 'tauri' | 'web' | 'ssr';

/** Resolve the runtime for FEAT-005 selection. */
export function resolveUbuntuRuntime(): UbuntuRuntime {
  const target = getRuntimeTarget();
  if (target === 'tauri') {
    return 'tauri';
  }
  if (typeof window === 'undefined') {
    return 'ssr';
  }
  return 'web';
}

/** Vault-backed capability slots the Ubuntu adapter backs (FEAT-002/003). */
export const UBUNTU_CAPABILITY_SLOTS: readonly CapabilityId[] = [
  'localUserAuthority',
  'secretAuthority',
  'identityVerification',
];

/**
 * Whether the Ubuntu adapter may register. True ONLY for the Tauri runtime
 * with an exact build/protocol handshake and a passing native preflight.
 * Every other combination fails closed — a locked/cancelled/temporary
 * provider or failed preflight never selects a weaker adapter.
 */
export function canSelectUbuntuVault(params: {
  runtime: UbuntuRuntime;
  handshakeOk: boolean;
  preflightOk: boolean;
}): boolean {
  return params.runtime === 'tauri' && params.handshakeOk && params.preflightOk;
}

/**
 * Build the production capability registrations for the FEAT-002 registry.
 * Non-Tauri runtimes and failed handshakes/preflights yield `unavailable`
 * registrations so the composition fails closed; they never produce a
 * browser fallback.
 */
export function buildUbuntuRegistrations(params: {
  runtime: UbuntuRuntime;
  handshakeOk: boolean;
  preflightOk: boolean;
}): readonly CapabilityRegistration[] {
  const selectable = canSelectUbuntuVault(params);
  // FEAT-002 vocabulary: 'mandatory' (present, non-synthetic, required) or
  // 'unavailable' (fail closed). No 'available' literal exists by design.
  const availability = selectable ? 'mandatory' : 'unavailable';
  return UBUNTU_CAPABILITY_SLOTS.map((capability) => ({
    capability,
    availability,
    synthetic: false,
  }));
}

/** Validate the registrations against FEAT-002's production registry rules. */
export function validateUbuntuComposition(
  registrations: readonly CapabilityRegistration[],
): { readonly ok: boolean; readonly diagnostics: readonly string[] } {
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
    if (
      registration.availability === 'mandatory' &&
      !UBUNTU_CAPABILITY_SLOTS.includes(registration.capability)
    ) {
      diagnostics.push(
        `mandatory capability outside the Ubuntu slots: ${registration.capability}`,
      );
    }
  }
  for (const required of UBUNTU_CAPABILITY_SLOTS) {
    if (!seen.has(required)) {
      diagnostics.push(`missing Ubuntu slot: ${required}`);
    }
  }
  return { ok: diagnostics.length === 0, diagnostics };
}

/**
 * Native/WebView mutual exclusion: for a given capability slot, the browser
 * adapter and the Ubuntu adapter must never BOTH be mandatory — exactly one
 * authority backs a slot in any runtime.
 */
export function slotsConflict(
  ubuntu: readonly CapabilityRegistration[],
  browser: readonly CapabilityRegistration[],
): boolean {
  const ubuntuMandatory = new Set(
    ubuntu.filter((r) => r.availability === 'mandatory').map((r) => r.capability),
  );
  return browser.some(
    (r) => r.availability === 'mandatory' && ubuntuMandatory.has(r.capability),
  );
}
