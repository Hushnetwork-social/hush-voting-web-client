/**
 * FEAT-003 vault-core contracts — closed typed result union.
 *
 * Expected adapter failures return a closed discriminated result union with safe
 * structured fields: stable typed code, retryable flag, allowed recovery actions,
 * optional bounded retry deadline, optional random per-occurrence support code.
 * No raw exception, path, key alias, full identity, ciphertext excerpt, or free-form
 * platform message crosses the boundary.
 *
 * Deep-Dive override: `NetworkMismatch` is NOT an emitted v1 behavior; future network
 * binding requires a new version. v1 registry: 18 codes.
 *
 * Normative source: FEAT-003 FeatureDescription "Typed Result Contract".
 */

/** Allowed recovery actions surfaced to FEAT-002 for safe UX decisions. */
export type AllowedRecoveryAction =
  | 'retry'
  | 'reprovision'
  | 'verifyOnline'
  | 'requestPersistence'
  | 'unlockPlatformProtection'
  | 'changePassword'
  | 'clearRemovalTombstone'
  | 'resumeRemoval';

/** Closed v1 result codes (18). `NetworkMismatch` reserved for a future version. */
export type VaultResultCode =
  | 'NoVault'
  | 'UnsupportedVaultVersion'
  | 'MalformedEnvelope'
  | 'WrongPasswordOrDamagedData'
  | 'Throttled'
  | 'KdfResourceLimit'
  | 'PlatformProtectionUnavailable'
  | 'PlatformProtectionInvalidated'
  | 'IdentityBindingMismatch'
  | 'MigrationFailedRollbackAvailable'
  | 'GenerationConflict'
  | 'StorageUnavailable'
  | 'StorageQuotaExceeded'
  | 'PersistenceDenied'
  | 'StaleSession'
  | 'OperationForbidden'
  | 'CleanupFailed'
  | 'ExtensionUnsupported';

/** Closed registry: every v1 code with its safe metadata (declarative, exhaustive). */
export interface ResultCodeMeta {
  readonly code: VaultResultCode;
  readonly retryable: boolean;
  readonly allowedActions: readonly AllowedRecoveryAction[];
}

export const VAULT_RESULT_CODES: readonly VaultResultCode[] = [
  'NoVault',
  'UnsupportedVaultVersion',
  'MalformedEnvelope',
  'WrongPasswordOrDamagedData',
  'Throttled',
  'KdfResourceLimit',
  'PlatformProtectionUnavailable',
  'PlatformProtectionInvalidated',
  'IdentityBindingMismatch',
  'MigrationFailedRollbackAvailable',
  'GenerationConflict',
  'StorageUnavailable',
  'StorageQuotaExceeded',
  'PersistenceDenied',
  'StaleSession',
  'OperationForbidden',
  'CleanupFailed',
  'ExtensionUnsupported',
] as const;

export const VAULT_RESULT_REGISTRY: Readonly<Record<VaultResultCode, ResultCodeMeta>> = {
  NoVault: { code: 'NoVault', retryable: false, allowedActions: ['reprovision'] },
  UnsupportedVaultVersion: { code: 'UnsupportedVaultVersion', retryable: false, allowedActions: [] },
  MalformedEnvelope: { code: 'MalformedEnvelope', retryable: true, allowedActions: ['reprovision'] },
  WrongPasswordOrDamagedData: { code: 'WrongPasswordOrDamagedData', retryable: true, allowedActions: ['retry', 'reprovision'] },
  Throttled: { code: 'Throttled', retryable: true, allowedActions: ['retry'] },
  KdfResourceLimit: { code: 'KdfResourceLimit', retryable: true, allowedActions: ['verifyOnline'] },
  PlatformProtectionUnavailable: { code: 'PlatformProtectionUnavailable', retryable: true, allowedActions: ['unlockPlatformProtection', 'retry'] },
  PlatformProtectionInvalidated: { code: 'PlatformProtectionInvalidated', retryable: false, allowedActions: ['reprovision'] },
  IdentityBindingMismatch: { code: 'IdentityBindingMismatch', retryable: false, allowedActions: ['reprovision'] },
  MigrationFailedRollbackAvailable: { code: 'MigrationFailedRollbackAvailable', retryable: true, allowedActions: ['retry'] },
  GenerationConflict: { code: 'GenerationConflict', retryable: true, allowedActions: ['retry'] },
  StorageUnavailable: { code: 'StorageUnavailable', retryable: true, allowedActions: ['retry'] },
  StorageQuotaExceeded: { code: 'StorageQuotaExceeded', retryable: true, allowedActions: ['requestPersistence'] },
  PersistenceDenied: { code: 'PersistenceDenied', retryable: true, allowedActions: ['requestPersistence'] },
  StaleSession: { code: 'StaleSession', retryable: true, allowedActions: ['retry'] },
  OperationForbidden: { code: 'OperationForbidden', retryable: false, allowedActions: [] },
  CleanupFailed: { code: 'CleanupFailed', retryable: true, allowedActions: ['retry', 'resumeRemoval'] },
  ExtensionUnsupported: { code: 'ExtensionUnsupported', retryable: false, allowedActions: [] },
} as const;

/** Random per-occurrence support code (bounded, safe for local diagnostics). */
export type SupportCode = string;

/** One typed vault failure — the only shape crossing the core boundary on expected failure. */
export interface VaultFailure {
  readonly ok: false;
  readonly code: VaultResultCode;
  readonly retryable: boolean;
  readonly allowedActions: readonly AllowedRecoveryAction[];
  /** Optional bounded retry deadline (epoch ms); present when retryable with a cooldown. */
  readonly retryDeadlineMs?: number;
  /** Optional random per-occurrence support code for sanitized local diagnostics. */
  readonly supportCode?: SupportCode;
}

/** One typed vault success — closed shape with only safe public fields. */
export interface VaultSuccess<T> {
  readonly ok: true;
  readonly value: T;
}

/** Closed discriminated result union. */
export type VaultResult<T> = VaultSuccess<T> | VaultFailure;

/** Construct a safe typed failure from the closed registry. */
export function failure(
  code: VaultResultCode,
  extra: { readonly retryDeadlineMs?: number; readonly supportCode?: SupportCode } = {},
): VaultFailure {
  const meta = VAULT_RESULT_REGISTRY[code];
  return {
    ok: false,
    code,
    retryable: meta.retryable,
    allowedActions: meta.allowedActions,
    ...(extra.retryDeadlineMs !== undefined ? { retryDeadlineMs: extra.retryDeadlineMs } : {}),
    ...(extra.supportCode !== undefined ? { supportCode: extra.supportCode } : {}),
  };
}

/** Construct a safe typed success. */
export function success<T>(value: T): VaultSuccess<T> {
  return { ok: true, value };
}

/** Exhaustive registry check used by tests: every code has exactly one meta entry. */
export function assertRegistryExhaustive(): void {
  const registered = Object.keys(VAULT_RESULT_REGISTRY).sort();
  const declared = [...VAULT_RESULT_CODES].sort();
  if (JSON.stringify(registered) !== JSON.stringify(declared)) {
    throw new Error('vault result registry is not exhaustive: codes must match VAULT_RESULT_CODES');
  }
}
