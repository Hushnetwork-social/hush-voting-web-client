/**
 * FEAT-003 vault-core contracts — independent version axes and registries.
 *
 * Four independent monotonic integer versions track compatibility:
 * 1. `envelopeFormatVersion` — envelope shape
 * 2. `parameterSuiteVersion` — closed cryptographic construction
 * 3. `recordSchemaVersion`   — encrypted record schema
 * 4. `platformWrapperVersion`— native OS-backed wrapper (0 = none in logical envelope)
 *
 * A newer unsupported critical version returns `UnsupportedVaultVersion`, preserves all
 * bytes, and never attempts best-effort downgrade. One global semantic-version string must
 * not substitute for these compatibility dimensions.
 *
 * Normative source: FEAT-003 FeatureDescription "Version Model".
 */
import type { CompatibilityFailure } from '../../identity-compatibility/types';

/** Supported envelope format version for this corpus. */
export const ENVELOPE_FORMAT_VERSION = 1 as const;
/** Supported parameter-suite version (closed suite v1). */
export const PARAMETER_SUITE_VERSION = 1 as const;
/** Supported record schema version. */
export const RECORD_SCHEMA_VERSION = 1 as const;
/** Logical envelope carries no native wrapper; 0 is the only v1 value. */
export const PLATFORM_WRAPPER_VERSION_NONE = 0 as const;

/** Bounded signed 32-bit integer range for generation counters (schema bound). */
export const MAX_GENERATION = 2_147_483_647 as const;

/** Closed registry: every supported v1 version combination. */
export interface VaultVersionSet {
  readonly envelopeFormatVersion: 1;
  readonly parameterSuiteVersion: 1;
  readonly recordSchemaVersion: 1;
  readonly platformWrapperVersion: 0;
}

/** The one supported v1 version combination. */
export const VAULT_VERSION_V1: VaultVersionSet = {
  envelopeFormatVersion: ENVELOPE_FORMAT_VERSION,
  parameterSuiteVersion: PARAMETER_SUITE_VERSION,
  recordSchemaVersion: RECORD_SCHEMA_VERSION,
  platformWrapperVersion: PLATFORM_WRAPPER_VERSION_NONE,
} as const;

/**
 * Deterministic compatibility verdict for a parsed version set.
 * Readable combinations are listed in the version/migration matrix (Phase 3).
 */
export type VersionCompatibility =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'UNSUPPORTED_CRITICAL_VERSION' };

/** Reject any version set that is not the exact v1 combination (fail closed). */
export function checkSupportedVersion(version: VaultVersionSet): VersionCompatibility {
  if (
    version.envelopeFormatVersion === 1 &&
    version.parameterSuiteVersion === 1 &&
    version.recordSchemaVersion === 1 &&
    version.platformWrapperVersion === 0
  ) {
    return { ok: true };
  }
  return { ok: false, code: 'UNSUPPORTED_CRITICAL_VERSION' };
}

/** Adapter/platform binding identifier used in AAD (v1 logical fixtures). */
export type AdapterBinding = 'logical' | 'browser' | 'ubuntu' | 'android';

export const ADAPTER_BINDINGS: readonly AdapterBinding[] = [
  'logical',
  'browser',
  'ubuntu',
  'android',
] as const;

/** Stable typed failure for contract-level validation (never echoes secrets). */
export type VaultContractFailure = CompatibilityFailure;
