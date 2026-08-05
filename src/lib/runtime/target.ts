/**
 * FEAT-010 runtime contracts — trusted native target handshake.
 *
 * Tauri exposes ONE narrow Rust-owned startup command returning a safe closed
 * descriptor. JavaScript validates exact-compatible versions before any
 * registration. Platform selection NEVER comes from user agent, public
 * environment variables, page input, trial-and-error adapter loading, or
 * endpoint reachability (normative: FeatureDescription "Trusted
 * runtime-target handshake", AC-010-005/006).
 *
 * A recognized native target can never fall back to Browser IndexedDB, BFF
 * transport, software-only storage, or password-only Android persistence:
 * target resolution here either yields the exact native descriptor or fails
 * closed with a typed diagnostic.
 *
 * Framework-neutral.
 */

import type { DeploymentManifest } from './deployment';

/** Recognized native platforms (compiled-target truth, Rust-owned). */
export type NativePlatform = 'ubuntu' | 'android';

/** Capability classes a native build may declare (closed allowlist). */
export type NativeCapabilityClass =
  | 'secret-service'
  | 'android-keystore'
  | 'native-transport'
  | 'native-lifecycle';

const ALLOWED_CAPABILITY_CLASSES: readonly string[] = [
  'secret-service',
  'android-keystore',
  'native-transport',
  'native-lifecycle',
] as const;

/** Trusted runtime descriptor returned by the Rust startup command. */
export interface TrustedTargetDescriptor {
  readonly platform: NativePlatform;
  /** Application/build identity (digest of the compiled target). */
  readonly buildIdentity: string;
  /** Exact adapter contract versions per platform. */
  readonly adapterContractVersion: string;
  /** Available qualified capability classes. */
  readonly capabilityClasses: readonly NativeCapabilityClass[];
  /** Deployment configuration identifier the build was compiled for. */
  readonly deploymentConfigurationId: string;
}

/** Closed target-resolution diagnostics. */
export type TargetResolutionDiagnostic =
  | { readonly code: 'UNKNOWN_PLATFORM' }
  | { readonly code: 'INVALID_BUILD_IDENTITY' }
  | { readonly code: 'INVALID_ADAPTER_VERSION' }
  | { readonly code: 'INCOMPATIBLE_ADAPTER_VERSION' }
  | { readonly code: 'UNKNOWN_CAPABILITY_CLASS' }
  | { readonly code: 'MISSING_MANDATORY_CAPABILITY' }
  | { readonly code: 'DEPLOYMENT_MISMATCH' }
  | { readonly code: 'CONTRADICTORY_DESCRIPTOR' };

export type TargetResolution =
  | { readonly ok: true; readonly target: ResolvedRuntimeTarget }
  | { readonly ok: false; readonly diagnostics: readonly TargetResolutionDiagnostic[] };

/** The only two runtime targets a composition may select. */
export type ResolvedRuntimeTarget =
  | { readonly kind: 'browser' }
  | { readonly kind: 'native'; readonly platform: NativePlatform; readonly descriptor: TrustedTargetDescriptor };

/** Mandatory native capability per platform (fail closed when absent). */
const MANDATORY_CAPABILITY: Readonly<Record<NativePlatform, NativeCapabilityClass>> = {
  ubuntu: 'secret-service',
  android: 'android-keystore',
};

const BUILD_IDENTITY_PATTERN = /^[A-Za-z0-9._-]{8,128}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

function isNativePlatform(value: unknown): value is NativePlatform {
  return value === 'ubuntu' || value === 'android';
}

/**
 * Resolve the runtime target from an optional trusted handshake.
 * - No handshake → Browser target (Browser composition is selected only when
 *   no valid Tauri bridge handshake exists).
 * - Handshake present → must be a valid native descriptor; any malformed,
 *   unknown, incompatible, or contradictory value fails closed. A failed or
 *   timed-out handshake NEVER falls back to Browser (AC-010-006).
 *
 * `manifest` provides the deployment configuration the descriptor must match.
 */
export function resolveRuntimeTarget(
  handshake: TrustedTargetDescriptor | null | undefined,
  manifest: DeploymentManifest,
): TargetResolution {
  if (handshake === null || handshake === undefined) {
    return { ok: true, target: { kind: 'browser' } };
  }
  const diagnostics: TargetResolutionDiagnostic[] = [];

  if (!isNativePlatform(handshake.platform)) {
    diagnostics.push({ code: 'UNKNOWN_PLATFORM' });
  }
  if (typeof handshake.buildIdentity !== 'string' || !BUILD_IDENTITY_PATTERN.test(handshake.buildIdentity)) {
    diagnostics.push({ code: 'INVALID_BUILD_IDENTITY' });
  }
  if (typeof handshake.adapterContractVersion !== 'string' || !VERSION_PATTERN.test(handshake.adapterContractVersion)) {
    diagnostics.push({ code: 'INVALID_ADAPTER_VERSION' });
  } else if (handshake.adapterContractVersion !== manifest.contractVersions.adapter) {
    diagnostics.push({ code: 'INCOMPATIBLE_ADAPTER_VERSION' });
  }
  if (!Array.isArray(handshake.capabilityClasses) || handshake.capabilityClasses.length === 0) {
    diagnostics.push({ code: 'MISSING_MANDATORY_CAPABILITY' });
  } else {
    const classes = new Set(handshake.capabilityClasses);
    for (const capability of handshake.capabilityClasses) {
      if (!ALLOWED_CAPABILITY_CLASSES.includes(capability)) {
        diagnostics.push({ code: 'UNKNOWN_CAPABILITY_CLASS' });
      }
    }
    if (isNativePlatform(handshake.platform) && !classes.has(MANDATORY_CAPABILITY[handshake.platform])) {
      diagnostics.push({ code: 'MISSING_MANDATORY_CAPABILITY' });
    }
  }
  if (
    typeof handshake.deploymentConfigurationId !== 'string' ||
    handshake.deploymentConfigurationId !== manifest.configurationId
  ) {
    diagnostics.push({ code: 'DEPLOYMENT_MISMATCH' });
  }
  // Contradictory descriptor: platform claims one thing, capability classes another.
  if (
    isNativePlatform(handshake.platform) &&
    Array.isArray(handshake.capabilityClasses) &&
    ((handshake.platform === 'ubuntu' && handshake.capabilityClasses.includes('android-keystore')) ||
      (handshake.platform === 'android' && handshake.capabilityClasses.includes('secret-service')))
  ) {
    diagnostics.push({ code: 'CONTRADICTORY_DESCRIPTOR' });
  }

  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return {
    ok: true,
    target: { kind: 'native', platform: handshake.platform as NativePlatform, descriptor: handshake },
  };
}

/** Browser target is never acceptable for a recognized native platform. */
export function isBrowserTarget(target: ResolvedRuntimeTarget): boolean {
  return target.kind === 'browser';
}
