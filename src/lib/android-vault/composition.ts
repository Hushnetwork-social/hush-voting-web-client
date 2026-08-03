/**
 * FEAT-006 Android runtime composition (Phase 5, Task 5.5).
 *
 * Android production actors register ONLY for the exact Tauri mobile runtime
 * after matching WebView/Rust/Kotlin versions and a passing non-mutating
 * capability preflight. Web, Ubuntu desktop, SSR, test providers, mismatches,
 * and failed preflights fail closed: Android registrations remain unavailable
 * and no browser/Ubuntu adapter is silently selected for Android. Runtime
 * adapters are mutually exclusive; synthetic actors are release-excluded.
 *
 * Normative source: FEAT-006 FeatureDescription "Build/protocol handshake",
 * "WebView and Android Shell Hardening"; mirror of FEAT-005
 * `src/lib/ubuntu-vault/composition.ts` (native side).
 */

import type { CapabilityRegistration } from '../auth/ports';
import type { CapabilityId } from '../auth/types';

/** Android runtime classification (never user-agent based; injected by the
 * Tauri mobile integration point). */
export type AndroidRuntime = 'androidMobile' | 'tauriDesktop' | 'web' | 'ssr';

/** Capability slots the Android adapter backs (FEAT-002/003 vocabulary). */
export const ANDROID_CAPABILITY_SLOTS: readonly CapabilityId[] = [
  'localUserAuthority',
  'secretAuthority',
  'identityVerification',
];

/** Preflight kinds the Android adapter requires (non-mutating capability
 * probe outcomes). */
export type AndroidPreflight = 'passed' | 'failed' | 'notRun';

/** Whether the Android adapter may register. True ONLY for the Tauri mobile
 * runtime with exact versions and a passing preflight. Every other
 * combination fails closed. */
export function canSelectAndroidVault(params: {
  runtime: AndroidRuntime;
  webviewRustHandshakeOk: boolean;
  rustKotlinHandshakeOk: boolean;
  preflight: AndroidPreflight;
}): boolean {
  return (
    params.runtime === 'androidMobile' &&
    params.webviewRustHandshakeOk &&
    params.rustKotlinHandshakeOk &&
    params.preflight === 'passed'
  );
}

/** Build the production capability registrations (fail closed otherwise). */
export function buildAndroidRegistrations(params: {
  runtime: AndroidRuntime;
  webviewRustHandshakeOk: boolean;
  rustKotlinHandshakeOk: boolean;
  preflight: AndroidPreflight;
}): readonly CapabilityRegistration[] {
  const selectable = canSelectAndroidVault(params);
  const availability = selectable ? 'mandatory' : 'unavailable';
  return ANDROID_CAPABILITY_SLOTS.map((capability) => ({
    capability,
    availability,
    synthetic: false,
  }));
}

/** Runtime mutual-exclusion: exactly one adapter may back a slot. Given the
 * selected runtime, only the matching adapter family is selectable. */
export function runtimeExcludesOtherAdapters(params: {
  runtime: AndroidRuntime;
  ubuntuSelectable: boolean;
  browserSelectable: boolean;
}): boolean {
  if (params.runtime === 'androidMobile') {
    return !params.ubuntuSelectable && !params.browserSelectable;
  }
  // Non-Android runtimes can never select the Android adapter.
  return true;
}

/** Synthetic/test actors never satisfy production registrations. */
export function productionRegistrationsAreNonSynthetic(
  registrations: readonly CapabilityRegistration[],
): boolean {
  return registrations.every((r) => r.synthetic === false);
}
