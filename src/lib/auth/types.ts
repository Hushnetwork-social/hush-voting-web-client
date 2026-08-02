/**
 * FEAT-002 authentication contracts — safe-data vocabulary (core types).
 *
 * Framework-neutral: no React, Next.js, DOM, storage, transport, XState, or
 * state-store dependencies. This module defines the ONLY data shapes that may
 * cross the authentication orchestration boundary. Secrets (device/backup
 * password, mnemonic, private key, raw credential file, decrypted payload,
 * full secret-worker message, signature bytes, stable telemetry identifier,
 * arbitrary URL, election ID in browser history, raw exception, free-form
 * server error) CANNOT be represented here: there is no field for them and
 * opaque branded identifiers prevent smuggling them through generic strings.
 *
 * Normative source: FEAT-002 FeatureDescription "Machine context allowlist"
 * and "Secret submission boundary" sections.
 */

declare const opaque: unique symbol;

/** Opaque identifier for one in-flight actor operation. Never carries content. */
export type OperationId = string & { readonly [opaque]: 'OperationId' };

/** In-memory session epoch; incremented on lock/removal/replacement/takeover/authority loss/invalidation. */
export type SessionEpoch = number & { readonly [opaque]: 'SessionEpoch' };

/** Opaque in-memory navigation token mapped to a per-tab typed destination stack. */
export type NavigationToken = string & { readonly [opaque]: 'NavigationToken' };

/** Random per-occurrence support code for unknown failures; non-correlating. */
export type SupportCode = string & { readonly [opaque]: 'SupportCode' };

/** Opaque reference to the locally provisioned user, safe to hold while locked. */
export type LocalUserRef = string & { readonly [opaque]: 'LocalUserRef' };

/** Runtime target for capability detection (mirrors src/lib/runtime). */
export type RuntimeTarget = 'web' | 'tauri';

/** Fixed, user-visible local-device terminology (normative, EPIC-001). */
export const AUTH_TERMINOLOGY = {
  unlock: 'Unlock HushVoting',
  lock: 'Lock',
  devicePassword: 'Device password',
  removeLocalUser: 'Remove local user',
  forgotDevicePassword: 'Forgot device password?',
} as const;

/** Exact privacy-safe combined error for vault/encrypted-file authenticated-decryption failure. */
export const COMBINED_CREDENTIAL_ERROR =
  'The password is incorrect or the protected data is damaged.';

/** Timing boundaries (normative, FeatureDescription "Progress and timing"). */
export const AUTH_TIMING = {
  /** Accessible progress label threshold. */
  progressThresholdMs: 250,
  /** Shared-session/local-vault initialization timeout. */
  initTimeoutMs: 5000,
  /** Online identity verification timeout. */
  verifyTimeoutMs: 10000,
  /** Device-password KDF hard limit (EPIC-001). */
  kdfHardLimitMs: 1500,
  /** Non-secret lease staleness boundary (fallback ownership). */
  leaseStalenessMs: 15000,
} as const;

/** Authentication region state codes (one deterministic mapping per state). */
export type AuthStateCode =
  | 'initializing'
  | 'noLocalUser'
  | 'onboarding'
  | 'locked'
  | 'unlocking'
  | 'verifyingIdentityOnline'
  | 'missingProfileConfirmation'
  | 'authenticated'
  | 'recoverableError'
  | 'blockedError'
  | 'removingLocalUser';

/** Connectivity region state codes (parallel region; never erases auth context). */
export type ConnectivityStateCode = 'unknown' | 'online' | 'offline' | 'reconnecting';

/** Onboarding child-flow kinds — the ONLY three first-run entry paths. */
export type OnboardingKind = 'createUser' | 'restoreCredentialFile' | 'restoreRecoveryWords';

/** Typed in-memory navigation destinations (never serialized to URL/history). */
export type TypedDestinationKind =
  | 'userElectionsDashboard'
  | 'electionDashboard'
  | 'electionPage'
  | 'rootFallback';

/** Bounded safe public identity metadata shown while locked. */
export interface SafeIdentityMetadata {
  readonly alias: string;
  /** Abbreviated signing address (bounded; no full-address copy while locked). */
  readonly abbreviatedSigningAddress: string;
}

/** Safe environment/server context shown in the Sovereign Shield shell. */
export interface EnvironmentContext {
  readonly runtimeTarget: RuntimeTarget;
  readonly serverContext: string;
}

/** Non-sensitive cooldown deadline (absolute epoch ms) from throttling outcomes. */
export interface CooldownInfo {
  readonly deadlineMs: number;
}

/** Registered capability identifiers implemented by downstream features. */
export type CapabilityId =
  | 'localUserAuthority'
  | 'secretAuthority'
  | 'identityVerification'
  | 'browserCoordination'
  | 'onboardingCreateUser'
  | 'onboardingRestoreCredentialFile'
  | 'onboardingRestoreRecoveryWords'
  | 'temporaryMode';

/** Availability classification used by production registration validation. */
export type CapabilityAvailability = 'mandatory' | 'optional' | 'temporaryMode' | 'unavailable';

/** Why an authenticated session is invalidated (identity-binding invalidation only). */
export type InvalidationReason = 'profileMissing' | 'signingKeyMismatch' | 'encryptionKeyMismatch';

/** Future policy-owned reauthentication extension point (no election logic). */
export type ReauthenticationReason = 'policyRequested' | 'operationScoped';

/**
 * Typed intent vocabulary: user/UI intents and system events accepted by the
 * authentication authority. No secret-bearing field exists in any event.
 */
export type AuthIntent =
  | { readonly type: 'INTENT.CREATE_USER' }
  | { readonly type: 'INTENT.RESTORE_CREDENTIAL_FILE' }
  | { readonly type: 'INTENT.RESTORE_RECOVERY_WORDS' }
  | { readonly type: 'INTENT.BACK_FROM_ONBOARDING' }
  | { readonly type: 'INTENT.UNLOCK' }
  | { readonly type: 'INTENT.LOCK' }
  | { readonly type: 'INTENT.REMOVE_LOCAL_USER' }
  | { readonly type: 'INTENT.CONFIRM_MISSING_PROFILE' }
  | { readonly type: 'INTENT.ENTER_TEMPORARY_MODE' }
  | { readonly type: 'INTENT.RETRY' }
  | { readonly type: 'INTENT.TAKE_OVER_SESSION' }
  | { readonly type: 'INTENT.NAVIGATE'; readonly destination: TypedDestinationKind }
  | { readonly type: 'INTENT.GO_BACK' }
  | { readonly type: 'INTENT.REAUTHENTICATION_REQUIRED'; readonly reason: ReauthenticationReason };

/** Stable machine-readable outcome codes (one per documented typed outcome). */
export type AuthOutcomeCode =
  // initialization results
  | 'INIT_NO_LOCAL_USER'
  | 'INIT_LOCKED_USER'
  | 'INIT_STORAGE_UNAVAILABLE'
  | 'INIT_UNSUPPORTED_VAULT_VERSION'
  | 'INIT_CORRUPT_VAULT'
  | 'INIT_MEMORY_ONLY'
  | 'INIT_UNSAFE_COORDINATION'
  // local unlock results
  | 'UNLOCK_SUCCESS'
  | 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED'
  | 'UNLOCK_THROTTLED'
  // online identity verification results
  | 'VERIFY_SUCCESS'
  | 'VERIFY_PROFILE_MISSING'
  | 'VERIFY_SIGNING_KEY_MISMATCH'
  | 'VERIFY_ENCRYPTION_KEY_MISMATCH'
  | 'VERIFY_TIMEOUT'
  | 'VERIFY_NETWORK_UNAVAILABLE'
  // onboarding child-flow results
  | 'ONBOARDING_COMPLETED'
  | 'ONBOARDING_BACK'
  | 'ONBOARDING_CLEANUP_COMPLETE'
  // removal results
  | 'REMOVAL_COMPLETE'
  | 'REMOVAL_BLOCKED_REMEDIATION'
  // coordination results
  | 'COORDINATION_SAFE'
  | 'COORDINATION_UNSAFE'
  // generic typed outcomes
  | 'MISSING_PLATFORM_PROTECTION'
  | 'INVALID_MNEMONIC'
  | 'TRANSACTION_REJECTED'
  | 'AUTHORITY_LOST'
  | 'SESSION_INVALIDATED'
  | 'UNKNOWN_FAILURE';

/**
 * Machine context allowlist — the complete set of values authentication state
 * may carry. Exactly matches the FeatureDescription "Machine context
 * allowlist". No field may be added without a security review.
 */
export interface AuthMachineContext {
  readonly sessionEpoch: SessionEpoch;
  readonly activeOperationId: OperationId | null;
  readonly registeredCapabilities: ReadonlySet<CapabilityId>;
  readonly safeCoordination: boolean;
  readonly safeIdentity: SafeIdentityMetadata | null;
  readonly environment: EnvironmentContext | null;
  readonly cooldownDeadlineMs: number | null;
  readonly navigationToken: NavigationToken | null;
  readonly supportCode: SupportCode | null;
  readonly outcomeCode: AuthOutcomeCode | null;
  readonly coarseStageStartedAtMs: number | null;
}
