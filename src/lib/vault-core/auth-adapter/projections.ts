/**
 * FEAT-003 vault-core auth-adapter — FEAT-002 safe projections (thin additive adapters).
 *
 * Maps vault-core safe results into UNCHANGED FEAT-002 ports. FEAT-002 remains the sole
 * UI/orchestration authority; XState receives safe projections only — never secrets,
 * opaque capability references, or vault internals. Every v1 result code is either
 * explicitly mapped to one existing FEAT-002 outcome or explicitly blocked (fail-closed
 * unknown outcome). Raw details are never forwarded.
 *
 * Normative source: FEAT-003 FeatureDescription "Session Core", "Typed Result Contract";
 * FEAT-002 src/lib/auth/results.ts outcome vocabulary.
 */
import type { AuthOutcomeCode } from '../../auth/types';
import type { VaultResultCode } from '../contracts/results';

/** A vault result projected into the FEAT-002 vocabulary. */
export type VaultToAuthProjection =
  | { readonly kind: 'mapped'; readonly outcome: AuthOutcomeCode }
  | { readonly kind: 'blocked'; readonly reason: 'unknown-future-result' };

/**
 * Explicit deterministic mapping: vault v1 result -> existing FEAT-002 outcome.
 * Every entry maps to ONE safe FEAT-002 code (no blank screens, no ambiguity).
 */
const MAPPED: Readonly<Record<string, AuthOutcomeCode>> = {
  NoVault: 'INIT_NO_LOCAL_USER',
  UnsupportedVaultVersion: 'INIT_UNSUPPORTED_VAULT_VERSION',
  MalformedEnvelope: 'INIT_CORRUPT_VAULT',
  WrongPasswordOrDamagedData: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED',
  Throttled: 'UNLOCK_THROTTLED',
  KdfResourceLimit: 'MISSING_PLATFORM_PROTECTION',
  PlatformProtectionUnavailable: 'MISSING_PLATFORM_PROTECTION',
  PlatformProtectionInvalidated: 'INIT_UNSUPPORTED_VAULT_VERSION',
  IdentityBindingMismatch: 'VERIFY_SIGNING_KEY_MISMATCH',
  StorageUnavailable: 'INIT_STORAGE_UNAVAILABLE',
  StorageQuotaExceeded: 'INIT_STORAGE_UNAVAILABLE',
  PersistenceDenied: 'INIT_STORAGE_UNAVAILABLE',
  StaleSession: 'SESSION_INVALIDATED',
  OperationForbidden: 'SESSION_INVALIDATED',
  CleanupFailed: 'REMOVAL_BLOCKED_REMEDIATION',
  ExtensionUnsupported: 'INIT_UNSUPPORTED_VAULT_VERSION',
};

/**
 * Explicitly blocked codes: FEAT-002 has no safe projection today. Fail closed to an
 * unknown outcome; raw details are not forwarded. New vault codes MUST be added to one
 * of these two tables before the registry test passes.
 */
const BLOCKED: readonly VaultResultCode[] = ['MigrationFailedRollbackAvailable', 'GenerationConflict'];

/** Deterministic projection. Exhaustiveness is enforced by `assertProjectionsExhaustive`. */
export function projectVaultResult(code: VaultResultCode): VaultToAuthProjection {
  const outcome = MAPPED[code];
  if (outcome !== undefined) return { kind: 'mapped', outcome };
  return { kind: 'blocked', reason: 'unknown-future-result' };
}

/** Exhaustiveness: every v1 code is mapped or explicitly blocked, never both. */
export function assertProjectionsExhaustive(): void {
  const codes: readonly VaultResultCode[] = [
    'NoVault', 'UnsupportedVaultVersion', 'MalformedEnvelope', 'WrongPasswordOrDamagedData',
    'Throttled', 'KdfResourceLimit', 'PlatformProtectionUnavailable', 'PlatformProtectionInvalidated',
    'IdentityBindingMismatch', 'MigrationFailedRollbackAvailable', 'GenerationConflict',
    'StorageUnavailable', 'StorageQuotaExceeded', 'PersistenceDenied', 'StaleSession',
    'OperationForbidden', 'CleanupFailed', 'ExtensionUnsupported',
  ];
  for (const code of codes) {
    const mapped = Object.prototype.hasOwnProperty.call(MAPPED, code);
    const blocked = BLOCKED.includes(code);
    if (mapped === blocked) {
      throw new Error(`projection table invalid for ${code}: must be mapped OR blocked, not both/neither`);
    }
  }
}
