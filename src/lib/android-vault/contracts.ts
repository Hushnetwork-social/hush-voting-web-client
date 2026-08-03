/**
 * FEAT-006 Android adapter — closed safe WebView vocabulary (Phase 2, Task 2.1).
 *
 * Mirrors the Rust `android_vault::contracts` vocabulary exhaustively. The
 * WebView receives only safe projections: closed categories, retryability,
 * allowed actions, bounded deadlines, and optional random non-correlating
 * support codes. Unknown fields/values fail closed. WebView types cannot
 * represent platform secrets or generic capabilities.
 *
 * Normative source: FEAT-006 FeatureDescription "Typed platform outcomes" and
 * the canonical planning report §11.
 */

/** Broad security level of the wrapping key origin (API-appropriate KeyInfo). */
export type SecurityLevel = 'strongBox' | 'trustedEnvironment' | 'softwareOrUnknown';

export const SECURITY_LEVELS: readonly SecurityLevel[] = [
  'strongBox',
  'trustedEnvironment',
  'softwareOrUnknown',
] as const;

export function isSecurityLevel(value: unknown): value is SecurityLevel {
  return typeof value === 'string' && (SECURITY_LEVELS as readonly string[]).includes(value);
}

/** Device capability class under the signed-release policy. */
export type CapabilityClass = 'qualified' | 'capabilityCompatible' | 'blocked';

export const CAPABILITY_CLASSES: readonly CapabilityClass[] = [
  'qualified',
  'capabilityCompatible',
  'blocked',
] as const;

export function isCapabilityClass(value: unknown): value is CapabilityClass {
  return typeof value === 'string' && (CAPABILITY_CLASSES as readonly string[]).includes(value);
}

/** State of the per-vault Android Keystore wrapping key. */
export type KeyState = 'absent' | 'active' | 'staged' | 'invalidated' | 'propertyMismatch';

export const KEY_STATES: readonly KeyState[] = [
  'absent',
  'active',
  'staged',
  'invalidated',
  'propertyMismatch',
] as const;

/** Non-mutating Android capability/status projection (safe for the WebView). */
export interface CapabilityStatus {
  readonly secureLockConfigured: boolean;
  readonly deviceLocked: boolean;
  readonly securityLevel: SecurityLevel;
  readonly strongBoxAdvertised: boolean;
  readonly capabilityClass: CapabilityClass;
  readonly knownBadBuildMatch: boolean;
}

export function isCapabilityStatus(value: unknown): value is CapabilityStatus {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v);
  const allowed = [
    'secureLockConfigured',
    'deviceLocked',
    'securityLevel',
    'strongBoxAdvertised',
    'capabilityClass',
    'knownBadBuildMatch',
  ];
  return (
    keys.every((k) => allowed.includes(k)) &&
    typeof v.secureLockConfigured === 'boolean' &&
    typeof v.deviceLocked === 'boolean' &&
    isSecurityLevel(v.securityLevel) &&
    typeof v.strongBoxAdvertised === 'boolean' &&
    isCapabilityClass(v.capabilityClass) &&
    typeof v.knownBadBuildMatch === 'boolean'
  );
}

/** Closed Rust-internal mobile-bridge operations (no generic capabilities). */
export type BridgeOperation =
  | 'queryCapability'
  | 'createWrappingKey'
  | 'inspectWrappingKey'
  | 'wrapSlot'
  | 'unwrapSlot'
  | 'rotateWrappingKey'
  | 'deleteWrappingKey'
  | 'querySecureLock'
  | 'queryLifecycleEvidence'
  | 'shieldSensitiveState'
  | 'unshieldSensitiveState'
  | 'clearClipboard'
  | 'openDocument'
  | 'createDocument';

export const BRIDGE_OPERATIONS: readonly BridgeOperation[] = [
  'queryCapability',
  'createWrappingKey',
  'inspectWrappingKey',
  'wrapSlot',
  'unwrapSlot',
  'rotateWrappingKey',
  'deleteWrappingKey',
  'querySecureLock',
  'queryLifecycleEvidence',
  'shieldSensitiveState',
  'unshieldSensitiveState',
  'clearClipboard',
  'openDocument',
  'createDocument',
] as const;

/** Recovery actions the UI may offer for a typed Android failure. */
export type RecoveryAction =
  | 'retry'
  | 'openSecuritySettings'
  | 'updateApp'
  | 'removeLocalUser'
  | 'portableRecovery'
  | 'resumeRemoval'
  | 'cancel';

export const RECOVERY_ACTIONS: readonly RecoveryAction[] = [
  'retry',
  'openSecuritySettings',
  'updateApp',
  'removeLocalUser',
  'portableRecovery',
  'resumeRemoval',
  'cancel',
] as const;

/** Closed Android result codes (v1). Outer Keystore/AAD failure is never
 * wrong-password; inner decryption uses FEAT-003's combined result. */
export type AndroidResultCode =
  | 'ok'
  | 'secureLockRequired'
  | 'deviceLocked'
  | 'hardwareBackedKeystoreUnavailable'
  | 'unsupportedKnownBadBuild'
  | 'temporaryKeystoreFailure'
  | 'platformProtectionInvalidated'
  | 'wrapperIntegrityFailure'
  | 'buildProtocolMismatch'
  | 'storageUnavailable'
  | 'storageQuotaExceeded'
  | 'unsupportedWrapperVersion'
  | 'staleSession'
  | 'cleanupRemovalIncomplete'
  | 'kdfResourceLimit'
  | 'networkTimeout'
  | 'wrongPasswordOrDamagedData';

export const ANDROID_RESULT_CODES: readonly AndroidResultCode[] = [
  'ok',
  'secureLockRequired',
  'deviceLocked',
  'hardwareBackedKeystoreUnavailable',
  'unsupportedKnownBadBuild',
  'temporaryKeystoreFailure',
  'platformProtectionInvalidated',
  'wrapperIntegrityFailure',
  'buildProtocolMismatch',
  'storageUnavailable',
  'storageQuotaExceeded',
  'unsupportedWrapperVersion',
  'staleSession',
  'cleanupRemovalIncomplete',
  'kdfResourceLimit',
  'networkTimeout',
  'wrongPasswordOrDamagedData',
] as const;

/** Canonical safe recovery actions per closed code. */
export const RECOVERY_ACTIONS_BY_CODE: Readonly<Record<AndroidResultCode, readonly RecoveryAction[]>> = {
  ok: [],
  secureLockRequired: ['openSecuritySettings', 'retry', 'removeLocalUser', 'portableRecovery'],
  deviceLocked: ['retry'],
  hardwareBackedKeystoreUnavailable: ['updateApp', 'removeLocalUser', 'portableRecovery'],
  unsupportedKnownBadBuild: ['updateApp', 'removeLocalUser', 'portableRecovery'],
  temporaryKeystoreFailure: ['retry'],
  platformProtectionInvalidated: ['updateApp', 'removeLocalUser', 'portableRecovery'],
  wrapperIntegrityFailure: ['cancel'],
  buildProtocolMismatch: ['updateApp'],
  storageUnavailable: ['retry'],
  storageQuotaExceeded: ['retry'],
  unsupportedWrapperVersion: ['updateApp', 'cancel'],
  staleSession: ['retry'],
  cleanupRemovalIncomplete: ['retry', 'resumeRemoval'],
  kdfResourceLimit: ['updateApp', 'retry'],
  networkTimeout: ['retry'],
  wrongPasswordOrDamagedData: ['retry', 'portableRecovery'],
} as const;

/** Whether the code is retryable without user intervention. */
export function isRetryableCode(code: AndroidResultCode): boolean {
  return (
    code === 'deviceLocked' ||
    code === 'temporaryKeystoreFailure' ||
    code === 'storageUnavailable' ||
    code === 'storageQuotaExceeded' ||
    code === 'staleSession' ||
    code === 'cleanupRemovalIncomplete' ||
    code === 'kdfResourceLimit' ||
    code === 'networkTimeout' ||
    code === 'wrongPasswordOrDamagedData'
  );
}

/** Closed payload kind for a successful platform outcome. */
export type OutcomeKind =
  | 'capabilityStatus'
  | 'keyInspection'
  | 'wrappedSlot'
  | 'unwrappedSlot'
  | 'secureLockState'
  | 'lifecycleEvidence'
  | 'shieldState'
  | 'clipboardCleared'
  | 'documentHandle';

export const OUTCOME_KINDS: readonly OutcomeKind[] = [
  'capabilityStatus',
  'keyInspection',
  'wrappedSlot',
  'unwrappedSlot',
  'secureLockState',
  'lifecycleEvidence',
  'shieldState',
  'clipboardCleared',
  'documentHandle',
] as const;

/** Safe Android platform outcome (closed). No raw detail can be represented. */
export type AndroidOutcome =
  | { readonly outcome: 'ok'; readonly kind: OutcomeKind }
  | {
      readonly outcome: 'err';
      readonly code: AndroidResultCode;
      readonly retryable: boolean;
      readonly retryDeadlineSecs: number;
      readonly supportCode: string | null;
    };

export function isAndroidOutcome(value: unknown): value is AndroidOutcome {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v);
  if (v.outcome === 'ok') {
    return (
      keys.length === 2 &&
      keys.includes('outcome') &&
      keys.includes('kind') &&
      typeof v.kind === 'string' &&
      (OUTCOME_KINDS as readonly string[]).includes(v.kind)
    );
  }
  if (v.outcome === 'err') {
    const allowed = ['outcome', 'code', 'retryable', 'retryDeadlineSecs', 'supportCode'];
    return (
      keys.every((k) => allowed.includes(k)) &&
      typeof v.code === 'string' &&
      (ANDROID_RESULT_CODES as readonly string[]).includes(v.code) &&
      typeof v.retryable === 'boolean' &&
      typeof v.retryDeadlineSecs === 'number' &&
      (v.supportCode === null || typeof v.supportCode === 'string')
    );
  }
  return false;
}

/** Bounded boot-aware lifecycle evidence (Rust owns session authority). */
export interface LifecycleEvidence {
  readonly bootElapsedMillis: number;
  readonly deviceLocked: boolean;
  readonly allWindowsBackgrounded: boolean;
  readonly mainWindowFocused: boolean;
}

export const MAX_PLAUSIBLE_BOOT_ELAPSED_MILLIS = 60 * 24 * 60 * 60 * 1000;

export function isPlausibleLifecycleEvidence(e: LifecycleEvidence): boolean {
  return (
    e.bootElapsedMillis <= MAX_PLAUSIBLE_BOOT_ELAPSED_MILLIS &&
    !(e.mainWindowFocused && e.allWindowsBackgrounded)
  );
}

/** Typed sensitive state driven by Rust (never arbitrary JavaScript). */
export type SensitiveState =
  | 'none'
  | 'devicePasswordInput'
  | 'newDevicePasswordInput'
  | 'datPasswordInput'
  | 'mnemonicCreation'
  | 'mnemonicReveal'
  | 'mnemonicConfirmation'
  | 'credentialRestore'
  | 'credentialExport'
  | 'operationConfirmation';

export const SENSITIVE_STATES: readonly SensitiveState[] = [
  'none',
  'devicePasswordInput',
  'newDevicePasswordInput',
  'datPasswordInput',
  'mnemonicCreation',
  'mnemonicReveal',
  'mnemonicConfirmation',
  'credentialRestore',
  'credentialExport',
  'operationConfirmation',
] as const;

/** Approved document-picker operations (one bounded URI per operation). */
export type DocumentOperation = 'importDatV1' | 'exportDatV1';

export const DOCUMENT_OPERATIONS: readonly DocumentOperation[] = ['importDatV1', 'exportDatV1'] as const;

/** Sanitized local diagnostics (broad values only). */
export interface SanitizedDiagnostics {
  readonly secureLockConfigured: boolean;
  readonly securityLevelCategory: 'strongBox' | 'tee' | 'softwareOrUnknown';
  readonly capabilityClass: CapabilityClass;
  readonly wrapperVersion: number;
  readonly buildDigestPrefix: string;
  readonly supportCode: string | null;
}

/** Forbidden detail markers never allowed in any diagnostic/digest string. */
export const FORBIDDEN_DIAGNOSTIC_MARKERS: readonly string[] = [
  'alias',
  'address',
  'endpoint',
  'timestamp',
  'serial',
  'androidId',
  'attestationId',
  'ciphertext',
  'uri',
  'path',
  'exception',
  'stack',
  'mnemonic',
  'password',
  'identity',
];

export function diagnosticsAreSanitized(d: SanitizedDiagnostics): boolean {
  const fields = [d.buildDigestPrefix, d.supportCode ?? ''];
  const lower = fields.join(' ').toLowerCase();
  return !FORBIDDEN_DIAGNOSTIC_MARKERS.some((marker) => lower.includes(marker));
}
