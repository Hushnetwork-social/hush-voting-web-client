/**
 * FEAT-003 isolated conformance — independent lifecycle/session/core replay engines.
 *
 * Replays the core-vectors.json families (extension, lifecycle, migration, generation,
 * session, typed-result) using deterministic rules written directly from the FEAT-003
 * FeatureDescription contract — never importing the primary `../lifecycle/`,
 * `../session/`, `../contracts/` implementations. The corpus pins the expected
 * outcomes; independent replay catches implementation drift in either direction.
 */

/** ---------- extension ---------- */
const EXTENSION_NAMESPACE_PATTERN = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const MAX_EXTENSIONS = 16;
const MAX_NAMESPACE_LENGTH = 128;
const MAX_CRITICAL_EXTENSIONS = 16;

export function isolatedExtensionValidate(
  container: { extensions: Record<string, unknown>; criticalExtensions: string[] },
  knownExtensions: readonly string[],
): { code: string; output?: unknown } {
  const { extensions, criticalExtensions } = container;
  if (typeof extensions !== 'object' || extensions === null || Array.isArray(extensions)) {
    return { code: 'INVALID_EXTENSIONS' };
  }
  const keys = Object.keys(extensions);
  if (keys.length > MAX_EXTENSIONS) return { code: 'INVALID_EXTENSIONS' };
  for (const key of keys) {
    if (key.length > MAX_NAMESPACE_LENGTH || !EXTENSION_NAMESPACE_PATTERN.test(key)) return { code: 'INVALID_EXTENSIONS' };
  }
  if (!Array.isArray(criticalExtensions)) return { code: 'INVALID_EXTENSIONS' };
  if (criticalExtensions.length > MAX_CRITICAL_EXTENSIONS) return { code: 'INVALID_EXTENSIONS' };
  const unique = new Set(criticalExtensions);
  if (unique.size !== criticalExtensions.length) return { code: 'INVALID_EXTENSIONS' };
  for (const name of criticalExtensions) {
    if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAMESPACE_LENGTH || !EXTENSION_NAMESPACE_PATTERN.test(name)) {
      return { code: 'INVALID_EXTENSIONS' };
    }
    if (!Object.prototype.hasOwnProperty.call(extensions, name)) return { code: 'INVALID_EXTENSIONS' };
  }
  const unknownCritical = criticalExtensions.some((name) => !knownExtensions.includes(name));
  if (unknownCritical) return { code: 'ExtensionUnsupported' };
  return { code: 'OK', output: container };
}

/** ---------- lifecycle ---------- */
export interface IsolatedLifecycleState {
  readonly status: 'NoVault' | 'PendingRegistration' | 'Active';
  readonly pendingSubmission: boolean;
}

export function isolatedLifecycleReplay(operation: string, input: Record<string, unknown>): { code: string; output?: unknown } {
  const state = input.state as IsolatedLifecycleState;
  switch (operation) {
    case 'stagePendingRegistration': {
      if (state.status !== 'NoVault') return { code: 'INVALID_TRANSITION', output: state };
      if (input.verified !== true) return { code: 'NOT_VERIFIED', output: state };
      return { code: 'OK', output: { status: 'PendingRegistration', pendingSubmission: false } };
    }
    case 'beginSubmission': {
      if (state.status !== 'PendingRegistration') return { code: 'INVALID_TRANSITION', output: state };
      return { code: 'OK', output: { status: 'PendingRegistration', pendingSubmission: true } };
    }
    case 'reconcileToActive': {
      if (state.status !== 'PendingRegistration') return { code: 'INVALID_TRANSITION', output: state };
      if (input.confirmed !== true) return { code: 'VERIFICATION_FAILED', output: state };
      return { code: 'OK', output: { status: 'Active', pendingSubmission: false } };
    }
    case 'completeRemoval': {
      return { code: 'OK', output: { status: 'NoVault', pendingSubmission: false } };
    }
    case 'passwordChange': {
      const rewrappedRecordCount = typeof input.rewrappedRecordCount === 'number' ? input.rewrappedRecordCount : 0;
      return { code: 'OK', output: { rewrappedRecordCount, payloadsReEncrypted: 0, identityChanged: false } };
    }
    default:
      return { code: 'UNKNOWN_OPERATION', output: state };
  }
}

/** ---------- migration (version compatibility) ---------- */
export interface IsolatedVersionSet {
  readonly envelopeFormatVersion: number;
  readonly parameterSuiteVersion: number;
  readonly recordSchemaVersion: number;
  readonly platformWrapperVersion: number;
}

export function isolatedCheckSupportedVersion(version: IsolatedVersionSet): { code: string; output?: unknown } {
  if (
    version.envelopeFormatVersion === 1 &&
    version.parameterSuiteVersion === 1 &&
    version.recordSchemaVersion === 1 &&
    version.platformWrapperVersion === 0
  ) {
    return { code: 'OK', output: version };
  }
  return { code: 'UnsupportedVaultVersion' };
}

/** ---------- generation (two-slot journal CAS) ---------- */
export interface IsolatedGenerationInput {
  readonly state: {
    readonly activeSlotGeneration: number | null;
    readonly rollbackSlotGeneration: number | null;
    readonly activeGeneration: number;
    readonly newSlotVerified: boolean;
  };
  readonly expectedGeneration: number;
  readonly newGeneration: number;
  readonly writeOk: boolean;
  readonly verifyOk: boolean;
  readonly switchOk: boolean;
}

export function isolatedJournalCommit(input: IsolatedGenerationInput): { code: string; output?: unknown } {
  const s = input.state;
  if (s.activeSlotGeneration === null) {
    // First provisioning: no generation constraint.
    if (!input.writeOk) return { code: 'WRITE_FAILED', output: summarize(s) };
    if (!input.verifyOk) return { code: 'VERIFY_FAILED', output: summarize(s) };
    if (!input.switchOk) return { code: 'SWITCH_FAILED', output: summarize(s) };
    return { code: 'OK', output: summarize({ activeSlotGeneration: input.newGeneration, rollbackSlotGeneration: null, activeGeneration: input.newGeneration, newSlotVerified: true }) };
  }
  if (s.activeGeneration !== input.expectedGeneration) return { code: 'GENERATION_CONFLICT', output: summarize(s) };
  if (input.newGeneration <= s.activeGeneration) return { code: 'GENERATION_CONFLICT', output: summarize(s) };
  if (!input.writeOk) return { code: 'WRITE_FAILED', output: summarize(s) };
  if (!input.verifyOk) return { code: 'VERIFY_FAILED', output: summarize(s) };
  if (!input.switchOk) return { code: 'SWITCH_FAILED', output: summarize(s) };
  // Atomic switch succeeded: previous active becomes the bounded rollback slot.
  return {
    code: 'OK',
    output: summarize({ activeSlotGeneration: input.newGeneration, rollbackSlotGeneration: s.activeSlotGeneration, activeGeneration: input.newGeneration, newSlotVerified: false }),
  };
}

function summarize(s: { activeSlotGeneration: number | null; rollbackSlotGeneration: number | null; activeGeneration: number; newSlotVerified: boolean }) {
  return {
    activeSlotGeneration: s.activeSlotGeneration,
    rollbackSlotGeneration: s.rollbackSlotGeneration,
    activeGeneration: s.activeGeneration,
    newSlotVerified: s.newSlotVerified,
  };
}

/** ---------- session capability kernel ---------- */
export type IsolatedPhase = 'Locked' | 'VerificationOnly' | 'Authenticated' | 'FreshPasswordVerified' | 'Invalidated';

export interface IsolatedKernelState {
  readonly epoch: number;
  readonly phase: IsolatedPhase;
  readonly fresh: Record<string, { purpose: string; expiresAtMs: number; consumed: boolean }>;
}

const FRESH_PASSWORD_MAX_AGE_MS = 60_000;
const ELEVATION_PURPOSES = ['mnemonic-reveal', 'password-change'];

export function isolatedSessionReplay(operation: string, input: Record<string, unknown>): { code: string; output?: unknown } {
  const state = input.state as IsolatedKernelState;
  switch (operation) {
    case 'localUnlock': {
      if (state.phase !== 'Locked') return { code: 'INVALID_PHASE_TRANSITION' };
      return { code: 'OK', output: { ...state, phase: 'VerificationOnly' } };
    }
    case 'exactOnlineVerification': {
      if (state.phase !== 'VerificationOnly' && state.phase !== 'Authenticated') {
        return { code: 'INVALID_PHASE_TRANSITION' };
      }
      return { code: 'OK', output: { ...state, phase: 'Authenticated' } };
    }
    case 'invalidate': {
      // Unknown invalidation causes fail closed as authority loss; both outcomes bump
      // the epoch, return to Locked, and drop every fresh-password capability.
      return { code: 'OK', output: { epoch: state.epoch + 1, phase: 'Locked', fresh: {} } };
    }
    case 'freshPassword': {
      const purpose = input.purpose as string;
      const nowMs = input.nowMs as number;
      if (!ELEVATION_PURPOSES.includes(purpose)) return { code: 'OperationForbidden' };
      const channelId = input.channelId as string;
      return {
        code: 'OK',
        output: {
          ...state,
          phase: 'FreshPasswordVerified',
          fresh: { ...state.fresh, [channelId]: { purpose, expiresAtMs: nowMs + FRESH_PASSWORD_MAX_AGE_MS, consumed: false } },
        },
      };
    }
    case 'consumeFreshPassword': {
      const channelId = input.channelId as string;
      const purpose = input.purpose as string;
      const nowMs = input.nowMs as number;
      const fresh = state.fresh[channelId];
      if (!fresh) return { code: 'OperationForbidden' };
      if (fresh.consumed) return { code: 'OperationForbidden' };
      if (nowMs > fresh.expiresAtMs) return { code: 'OperationForbidden' };
      if (fresh.purpose !== purpose) return { code: 'OperationForbidden' };
      return {
        code: 'OK',
        output: { ...state, phase: 'Authenticated', fresh: { ...state.fresh, [channelId]: { ...fresh, consumed: true } } },
      };
    }
    default:
      return { code: 'OperationForbidden' };
  }
}

/** ---------- typed-result registry (closed v1 codes) ---------- */
export const ISOLATED_RESULT_CODES: readonly string[] = [
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

/** Spec-derived safe metadata per v1 code (FeatureDescription "Typed Result Contract"). */
const RESULT_META: Readonly<Record<string, { retryable: boolean; allowedActions: readonly string[] }>> = {
  NoVault: { retryable: false, allowedActions: ['reprovision'] },
  UnsupportedVaultVersion: { retryable: false, allowedActions: [] },
  MalformedEnvelope: { retryable: true, allowedActions: ['reprovision'] },
  WrongPasswordOrDamagedData: { retryable: true, allowedActions: ['retry', 'reprovision'] },
  Throttled: { retryable: true, allowedActions: ['retry'] },
  KdfResourceLimit: { retryable: true, allowedActions: ['verifyOnline'] },
  PlatformProtectionUnavailable: { retryable: true, allowedActions: ['unlockPlatformProtection', 'retry'] },
  PlatformProtectionInvalidated: { retryable: false, allowedActions: ['reprovision'] },
  IdentityBindingMismatch: { retryable: false, allowedActions: ['reprovision'] },
  MigrationFailedRollbackAvailable: { retryable: true, allowedActions: ['retry'] },
  GenerationConflict: { retryable: true, allowedActions: ['retry'] },
  StorageUnavailable: { retryable: true, allowedActions: ['retry'] },
  StorageQuotaExceeded: { retryable: true, allowedActions: ['requestPersistence'] },
  PersistenceDenied: { retryable: true, allowedActions: ['requestPersistence'] },
  StaleSession: { retryable: true, allowedActions: ['retry'] },
  OperationForbidden: { retryable: false, allowedActions: [] },
  CleanupFailed: { retryable: true, allowedActions: ['retry', 'resumeRemoval'] },
  ExtensionUnsupported: { retryable: false, allowedActions: [] },
};

/** Replay one typed-result registry vector. */
export function isolatedTypedResultReplay(code: string): { code: string; output?: unknown } {
  if (!ISOLATED_RESULT_CODES.includes(code)) return { code: 'UNKNOWN_CODE' };
  const meta = RESULT_META[code];
  if (!meta) return { code: 'UNKNOWN_CODE' };
  return { code: 'OK', output: { code, retryable: meta.retryable, allowedActions: meta.allowedActions } };
}
