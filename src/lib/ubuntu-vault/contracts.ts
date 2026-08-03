/**
 * FEAT-005 Ubuntu vault bridge — closed native projection vocabulary.
 *
 * The WebView consumes ONLY these safe projections from the Tauri native
 * boundary. Every name is the exact serde camelCase form produced by
 * `src-tauri/src/ubuntu_vault/contracts/*` (Phase 2 Rust contracts), so the
 * TypeScript mirror and the Rust serializers share one closed vocabulary.
 * No raw provider, path, identity, or secret detail may ever appear here.
 *
 * Normative source: FEAT-005 FeatureDescription "Availability state model",
 * "Protection Modes", "Error Handling", "Closed operation registry".
 */

/** Closed provider availability states (Rust `ProviderAvailability`). */
export type ProviderAvailability =
  | 'availableUnlocked'
  | 'availableLocked'
  | 'promptCancelled'
  | 'temporarilyUnavailable'
  | 'unavailable'
  | 'unqualifiedProvider'
  | 'protectionInvalidated';

/** Closed provider actions (Rust `ProviderAction`). */
export type ProviderAction =
  | 'unlockKeyring'
  | 'retry'
  | 'enableOsProtection'
  | 'passwordOnlyFallback'
  | 'portableRecovery'
  | 'cancel';

/** Coarse protection class (Rust `ProtectionClass`). Never provider-name proof. */
export type ProtectionClass = 'secretService' | 'passwordOnly';

/** Persistent protection mode (Rust `ProtectionMode`). */
export type ProtectionMode = 'osBacked' | 'passwordOnly';

/** FEAT-003 capability phase (Rust `CapabilityPhase`). */
export type CapabilityPhase = 'provisioning' | 'verificationOnly' | 'authenticated' | 'locked' | 'removal';

/** Closed native operation kinds (Rust `OperationKind`). No generic access. */
export type NativeOperationKind =
  | 'inspectPreview'
  | 'provision'
  | 'replace'
  | 'unlock'
  | 'lock'
  | 'changeDevicePassword'
  | 'removeLocalUser'
  | 'revealMnemonic'
  | 'generateIdentity'
  | 'restoreIdentity'
  | 'verifyOnline'
  | 'createFullIdentitySign'
  | 'importDatV1'
  | 'exportDatV1';

/** Closed native error codes (Rust `NativeErrorCode`). */
export type NativeErrorCode =
  | 'noVault'
  | 'unsupportedVaultVersion'
  | 'malformedEnvelope'
  | 'wrongPasswordOrDamagedData'
  | 'throttled'
  | 'kdfResourceLimit'
  | 'platformProtectionUnavailable'
  | 'platformProtectionInvalidated'
  | 'identityBindingMismatch'
  | 'migrationFailedRollbackAvailable'
  | 'generationConflict'
  | 'storageUnavailable'
  | 'storageQuotaExceeded'
  | 'persistenceDenied'
  | 'staleSession'
  | 'operationForbidden'
  | 'cleanupFailed'
  | 'extensionUnsupported'
  | 'providerAbsent'
  | 'providerLocked'
  | 'promptCancelled'
  | 'promptTimedOut'
  | 'providerTemporarilyUnavailable'
  | 'unqualifiedProvider'
  | 'wrapperAmbiguous'
  | 'wrapperVersionUnsupported'
  | 'buildVersionMismatch'
  | 'networkTimeout'
  | 'profileNotFound'
  | 'keyMismatch'
  | 'removalIncomplete';

/** Safe recovery actions (Rust `RecoveryAction`). */
export type NativeRecoveryAction =
  | 'retry'
  | 'reprovision'
  | 'verifyOnline'
  | 'unlockPlatformProtection'
  | 'enableOsProtection'
  | 'portableRecovery'
  | 'clearRemovalTombstone'
  | 'resumeRemoval'
  | 'cancel';

/** Safe success payload kinds (Rust `OutcomeKind`). */
export type NativeOutcomeKind =
  | 'locked'
  | 'unlocked'
  | 'provisioned'
  | 'verified'
  | 'removed'
  | 'preview'
  | 'revealPrepared'
  | 'signed'
  | 'datImported'
  | 'datExported';

/** Closed native outcome (Rust `NativeOutcome`; serde tag `outcome`). */
export type NativeOutcome =
  | { readonly outcome: 'ok'; readonly kind: NativeOutcomeKind }
  | { readonly outcome: 'err'; readonly code: NativeErrorCode; readonly supportCode?: number };

/** Sanitized diagnostic record (Rust `SafeDiagnostic`). */
export interface SafeDiagnostic {
  readonly category: DiagnosticCategory;
  readonly supportCode?: number;
  readonly coarseDuration: CoarseDuration;
}

/** Coarse operation categories (Rust `DiagnosticCategory`). */
export type DiagnosticCategory =
  | 'preflight'
  | 'keyringAccess'
  | 'passwordSubmit'
  | 'kdf'
  | 'onlineVerify'
  | 'storageCommit'
  | 'lock'
  | 'removal'
  | 'reveal';

/** Coarse duration buckets (Rust `CoarseDuration`). Never exact timestamps. */
export type CoarseDuration = 'under100Ms' | 'under500Ms' | 'under1s' | 'under3s' | 'over3s';

/** Closed diagnostic codes (Rust `DiagnosticCode`). */
export type DiagnosticCode =
  | 'providerAbsent'
  | 'providerLocked'
  | 'promptCancelled'
  | 'promptTimedOut'
  | 'providerTemporarilyUnavailable'
  | 'unqualifiedProvider'
  | 'protectionInvalidated'
  | 'wrapperAmbiguous'
  | 'wrapperVersionUnsupported'
  | 'buildVersionMismatch'
  | 'wrongPasswordOrDamagedData'
  | 'kdfResourceLimit'
  | 'generationConflict'
  | 'rollbackAvailable'
  | 'storageUnavailable'
  | 'storageQuotaExceeded'
  | 'filesystemPolicyViolation'
  | 'networkTimeout'
  | 'profileNotFound'
  | 'keyMismatch'
  | 'staleSession'
  | 'operationForbidden'
  | 'cleanupFailed'
  | 'removalIncomplete';

/** Deterministic item-set classification (Rust `ItemCardinality`). */
export type ItemCardinality =
  | 'none'
  | 'oneActive'
  | 'activeWithStaged'
  | 'duplicatesOneValid'
  | 'ambiguous'
  | 'orphan'
  | 'missingWithFiles'
  | 'staleOrUnsupported';

/**
 * Fixed production vocabulary (Rust `ubuntu_vault` module constants). Shared by
 * `.deb` and AppImage; release-channel separated.
 */
export const UBUNTU_VAULT_VOCABULARY = {
  applicationId: 'com.hushvoting.client',
  adapterId: 'ubuntu-secret-service-v1',
  itemLabel: 'HushVoting! Device Vault',
  itemPurpose: 'vault-wrapper',
  wrapperFormatVersion: 1,
} as const;

/** Exhaustive vocabulary lists for closed validation and registry tests. */
export const PROVIDER_AVAILABILITY_STATES: readonly ProviderAvailability[] = [
  'availableUnlocked',
  'availableLocked',
  'promptCancelled',
  'temporarilyUnavailable',
  'unavailable',
  'unqualifiedProvider',
  'protectionInvalidated',
];

export const NATIVE_ERROR_CODES: readonly NativeErrorCode[] = [
  'noVault',
  'unsupportedVaultVersion',
  'malformedEnvelope',
  'wrongPasswordOrDamagedData',
  'throttled',
  'kdfResourceLimit',
  'platformProtectionUnavailable',
  'platformProtectionInvalidated',
  'identityBindingMismatch',
  'migrationFailedRollbackAvailable',
  'generationConflict',
  'storageUnavailable',
  'storageQuotaExceeded',
  'persistenceDenied',
  'staleSession',
  'operationForbidden',
  'cleanupFailed',
  'extensionUnsupported',
  'providerAbsent',
  'providerLocked',
  'promptCancelled',
  'promptTimedOut',
  'providerTemporarilyUnavailable',
  'unqualifiedProvider',
  'wrapperAmbiguous',
  'wrapperVersionUnsupported',
  'buildVersionMismatch',
  'networkTimeout',
  'profileNotFound',
  'keyMismatch',
  'removalIncomplete',
];

/** Fail-closed lookup: an unknown string is never a valid code. */
export function isNativeErrorCode(value: unknown): value is NativeErrorCode {
  return typeof value === 'string' && (NATIVE_ERROR_CODES as readonly string[]).includes(value);
}

/** Fail-closed lookup: an unknown string is never a valid availability state. */
export function isProviderAvailability(value: unknown): value is ProviderAvailability {
  return typeof value === 'string' && (PROVIDER_AVAILABILITY_STATES as readonly string[]).includes(value);
}
