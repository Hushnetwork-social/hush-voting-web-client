/**
 * FEAT-010 auth contracts — target-aware production actor-set composition
 * (Task 2.5).
 *
 * One central builder registers the complete real actor set as an ATOMIC set
 * (AC-010-003): missing, duplicate, synthetic, incompatible, partial,
 * target-contradictory, or unknown registrations fail the whole set before
 * secret entry (AC-010-004). Registration provenance is explicit
 * (`provider: 'real' | 'null'`); `null` providers are incomplete, never
 * acceptable. FEAT-011 settings-extension metadata is capability-gated:
 * absent, or present only when a compatible real production capability
 * registers (AC-010-046).
 *
 * Framework-neutral, secret-free.
 */

import type { CapabilityId } from './types';

/** Closed target classes a registration may serve. */
export type TargetClass = 'web' | 'ubuntu' | 'android';

export const TARGET_CLASSES: readonly TargetClass[] = ['web', 'ubuntu', 'android'] as const;

/** Registration provenance: only `real` providers satisfy production slots. */
export type ActorProvider = 'real' | 'null';

/** One target-aware actor registration. */
export interface TargetAwareActorRegistration {
  readonly capability: CapabilityId;
  readonly targetClasses: readonly TargetClass[];
  /** Exact pinned contract version (semver, no ranges). */
  readonly contractVersion: string;
  readonly provider: ActorProvider;
  readonly synthetic: boolean;
}

/** FEAT-011 export settings-extension state. */
export type SettingsExtensionState =
  | { readonly kind: 'absent' }
  | { readonly kind: 'registered'; readonly contractVersion: string; readonly compatible: true }
  | { readonly kind: 'incompatible'; readonly contractVersion: string };

/** Closed composition diagnostics. */
export type TargetCompositionDiagnostic =
  | { readonly code: 'MISSING_MANDATORY'; readonly capability: CapabilityId }
  | { readonly code: 'DUPLICATE_REGISTRATION'; readonly capability: CapabilityId }
  | { readonly code: 'SYNTHETIC_IN_PRODUCTION'; readonly capability: CapabilityId }
  | { readonly code: 'NULL_PROVIDER'; readonly capability: CapabilityId }
  | { readonly code: 'INVALID_TARGET'; readonly capability: CapabilityId }
  | { readonly code: 'TARGET_CONTRADICTION'; readonly capability: CapabilityId }
  | { readonly code: 'INCOMPATIBLE_VERSION'; readonly capability: CapabilityId; readonly version: string }
  | { readonly code: 'UNKNOWN_CAPABILITY'; readonly capability: string }
  | { readonly code: 'EXTENSION_INCOMPATIBLE' };

export interface TargetCompositionValidation {
  readonly ok: boolean;
  readonly diagnostics: readonly TargetCompositionDiagnostic[];
}

/**
 * Mandatory production actor slots every target needs (extends the FEAT-002
 * mandatory set with lifecycle/settings/removal ownership).
 */
export const MANDATORY_TARGET_CAPABILITIES: readonly CapabilityId[] = [
  'localUserAuthority',
  'secretAuthority',
  'identityVerification',
  'browserCoordination',
  'removal',
];

/** Capability IDs this feature knows; anything else is unknown and fails. */
const KNOWN_CAPABILITIES: ReadonlySet<string> = new Set([
  ...MANDATORY_TARGET_CAPABILITIES,
  'onboardingCreateUser',
  'onboardingRestoreCredentialFile',
  'onboardingRestoreRecoveryWords',
  'temporaryMode',
]);

const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

/**
 * Validate the complete actor set atomically for the resolved target.
 * Rules:
 * - every mandatory slot present exactly once, real, non-synthetic;
 * - each registration must serve the resolved target class;
 * - contract versions must be exact-pinned and equal to the pinned version;
 * - cross-target contradictions (a registration claiming both web and a
 *   native class, or a native registration claiming the wrong native class)
 *   fail the whole set;
 * - unknown capabilities fail;
 * - an incompatible FEAT-011 extension state fails the set.
 */
export function validateTargetAwareActorSet(
  registrations: readonly TargetAwareActorRegistration[],
  target: TargetClass,
  pinnedContractVersion: string,
  extension: SettingsExtensionState,
): TargetCompositionValidation {
  const diagnostics: TargetCompositionDiagnostic[] = [];
  const seen = new Map<CapabilityId, TargetAwareActorRegistration>();

  for (const registration of registrations) {
    if (!KNOWN_CAPABILITIES.has(registration.capability)) {
      diagnostics.push({ code: 'UNKNOWN_CAPABILITY', capability: registration.capability });
      continue;
    }
    if (seen.has(registration.capability)) {
      diagnostics.push({ code: 'DUPLICATE_REGISTRATION', capability: registration.capability });
      continue;
    }
    seen.set(registration.capability, registration);

    if (registration.synthetic) {
      diagnostics.push({ code: 'SYNTHETIC_IN_PRODUCTION', capability: registration.capability });
    }
    if (registration.provider !== 'real') {
      diagnostics.push({ code: 'NULL_PROVIDER', capability: registration.capability });
    }
    if (!registration.targetClasses.includes(target)) {
      diagnostics.push({ code: 'INVALID_TARGET', capability: registration.capability });
    }
    if (!VERSION_PATTERN.test(registration.contractVersion) || registration.contractVersion !== pinnedContractVersion) {
      diagnostics.push({ code: 'INCOMPATIBLE_VERSION', capability: registration.capability, version: registration.contractVersion });
    }
    // Target contradiction: a single registration serving both web and native
    // classes (mixed authorities can never coexist in one set).
    const servesNative = registration.targetClasses.some((t) => t === 'ubuntu' || t === 'android');
    if (servesNative && registration.targetClasses.includes('web')) {
      diagnostics.push({ code: 'TARGET_CONTRADICTION', capability: registration.capability });
    }
    if (registration.targetClasses.includes('ubuntu') && registration.targetClasses.includes('android')) {
      diagnostics.push({ code: 'TARGET_CONTRADICTION', capability: registration.capability });
    }
  }

  for (const capability of MANDATORY_TARGET_CAPABILITIES) {
    if (!seen.has(capability)) {
      diagnostics.push({ code: 'MISSING_MANDATORY', capability });
    }
  }

  if (extension.kind === 'incompatible') {
    diagnostics.push({ code: 'EXTENSION_INCOMPATIBLE' });
  }

  return { ok: diagnostics.length === 0, diagnostics };
}

/** Deterministic single-target projection of a registration set (helper). */
export function projectForTarget(
  registrations: readonly TargetAwareActorRegistration[],
  target: TargetClass,
): readonly TargetAwareActorRegistration[] {
  return registrations.filter((registration) => registration.targetClasses.includes(target));
}
