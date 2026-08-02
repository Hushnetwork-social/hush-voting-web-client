/**
 * FEAT-002 authentication contracts — capability registration and production gates.
 *
 * Explicit capability registration that fails closed: mandatory production
 * actors must be present and non-synthetic; test/demo/in-memory actors are
 * unreachable from production composition; persistent authentication requires
 * safe browser coordination. Validation emits only safe typed diagnostics
 * (never implementation exceptions, never secrets).
 *
 * Normative source: FEAT-002 FeatureDescription "Authority and Dependencies",
 * "Production actor registration is explicit and fail-closed", acceptance
 * criterion 22, and security invariants.
 */

import type { CapabilityId } from './types';
import type { CapabilityRegistration, RegistrationDiagnostic, RegistryValidationResult } from './ports';

/** Capabilities mandatory for any persistent authentication flow. */
export const MANDATORY_CAPABILITIES: readonly CapabilityId[] = [
  'localUserAuthority',
  'secretAuthority',
  'identityVerification',
  'browserCoordination',
];

/** Onboarding child-flow capabilities (individually optional, fail closed when absent). */
export const ONBOARDING_CAPABILITIES: readonly CapabilityId[] = [
  'onboardingCreateUser',
  'onboardingRestoreCredentialFile',
  'onboardingRestoreRecoveryWords',
];

/** Temporary memory-only mode capability (valid only alongside safe coordination). */
export const TEMPORARY_MODE_CAPABILITY: CapabilityId = 'temporaryMode';

/**
 * Validate a production registration list against the fail-closed rules.
 *
 * Rules:
 * - every mandatory capability must be registered exactly once and non-synthetic;
 * - duplicate registrations of the same capability are rejected;
 * - synthetic registrations are always rejected for production;
 * - `temporaryMode` is incompatible when browser coordination is unsafe;
 * - unavailable registrations never satisfy a mandatory slot.
 */
export function validateProductionRegistry(
  registrations: readonly CapabilityRegistration[],
): RegistryValidationResult {
  const diagnostics: RegistrationDiagnostic[] = [];
  const seen = new Set<CapabilityId>();
  const availabilityByCapability = new Map<CapabilityId, CapabilityRegistration['availability']>();
  const syntheticByCapability = new Map<CapabilityId, boolean>();

  for (const registration of registrations) {
    if (seen.has(registration.capability)) {
      diagnostics.push({ code: 'DUPLICATE_REGISTRATION', capability: registration.capability });
      continue;
    }
    seen.add(registration.capability);
    availabilityByCapability.set(registration.capability, registration.availability);
    syntheticByCapability.set(registration.capability, registration.synthetic);

    if (registration.synthetic) {
      diagnostics.push({ code: 'SYNTHETIC_IN_PRODUCTION', capability: registration.capability });
    }
    if (registration.availability === 'temporaryMode' && registration.capability !== TEMPORARY_MODE_CAPABILITY) {
      diagnostics.push({ code: 'INCOMPATIBLE_AVAILABILITY', capability: registration.capability });
    }
  }

  // Mandatory capabilities: present, exactly once, non-synthetic, usable availability.
  for (const capability of MANDATORY_CAPABILITIES) {
    if (!seen.has(capability)) {
      diagnostics.push({ code: 'MISSING_MANDATORY', capability });
      continue;
    }
    const availability = availabilityByCapability.get(capability);
    if (availability === undefined || availability === 'unavailable') {
      diagnostics.push({ code: 'MISSING_MANDATORY', capability });
    }
  }

  // Persistent authentication requires safe browser coordination.
  const coordinationAvailability = availabilityByCapability.get('browserCoordination');
  if (coordinationAvailability === undefined || coordinationAvailability === 'unavailable') {
    diagnostics.push({ code: 'UNSAFE_COORDINATION', capability: 'browserCoordination' });
  }
  if (seen.has(TEMPORARY_MODE_CAPABILITY) && coordinationAvailability === 'unavailable') {
    diagnostics.push({ code: 'INCOMPATIBLE_AVAILABILITY', capability: TEMPORARY_MODE_CAPABILITY });
  }

  const availableCapabilities = new Set<CapabilityId>();
  if (diagnostics.length === 0) {
    for (const capability of seen) {
      const availability = availabilityByCapability.get(capability);
      if (availability !== undefined && availability !== 'unavailable') {
        availableCapabilities.add(capability);
      }
    }
  }

  return {
    ok: diagnostics.length === 0,
    diagnostics,
    availableCapabilities,
  };
}

/** Build one typed registration descriptor. */
export function registerCapability(
  capability: CapabilityId,
  availability: CapabilityRegistration['availability'],
  synthetic = false,
): CapabilityRegistration {
  return { capability, availability, synthetic };
}
