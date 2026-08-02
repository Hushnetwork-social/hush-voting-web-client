/**
 * FEAT-002 authentication contracts — cancellable actor ports.
 *
 * Every actor operation is scoped to one session epoch and one operation ID.
 * State exit aborts invoked actors; late results with a stale epoch or
 * operation ID are ignored by the authority. Ports expose typed results and
 * cancellation, never implementation-specific exceptions.
 *
 * SECRET BOUNDARY: the machine-facing ports NEVER carry secrets. Password,
 * mnemonic, key, or file input is handed directly from the UI to the isolated
 * secret authority through `SecretSubmissionSink` (below) and cleared
 * immediately after accepted transfer. XState receives only an opaque
 * operation ID and later a typed safe result.
 *
 * Normative source: FEAT-002 FeatureDescription "State and actor ownership",
 * "Secret submission boundary", "Stale-result protection".
 */

import type {
  CapabilityId,
  EnvironmentContext,
  LocalUserRef,
  NavigationToken,
  OnboardingKind,
  OperationId,
  SessionEpoch,
  TypedDestinationKind,
} from './types.js';
import type {
  CoordinationResult,
  InitializationResult,
  OnboardingResult,
  RemovalResult,
  UnlockResult,
  VerificationResult,
} from './results.js';

/** One cancellable actor operation bound to an epoch + operation ID. */
export interface ActorOperation<TResult> {
  readonly operationId: OperationId;
  readonly result: Promise<TResult>;
}
/** Base port: every actor must support cancellation by operation ID. */
export interface CancellablePort {
  cancel(operationId: OperationId): void;
}

/** Local capability authority: detect provisioned user + safe metadata (no secrets). */
export interface LocalUserAuthorityPort extends CancellablePort {
  initialize(epoch: SessionEpoch): ActorOperation<InitializationResult>;
}

/**
 * Secret authority port (machine-facing surface).
 * `beginUnlock` creates an opaque operation; the secret itself is delivered
 * through `SecretSubmissionSink` by the UI. The machine never sees the secret.
 */
export interface SecretAuthorityPort extends CancellablePort {
  beginUnlock(epoch: SessionEpoch): ActorOperation<UnlockResult>;
}

/** Online identity verification port (exact profile + both-key binding). */
export interface IdentityVerificationPort extends CancellablePort {
  verifyOnline(epoch: SessionEpoch, localUserRef: LocalUserRef): ActorOperation<VerificationResult>;
}

/** Onboarding child-flow port (one of the three first-run paths). */
export interface OnboardingPort extends CancellablePort {
  start(kind: OnboardingKind, epoch: SessionEpoch): ActorOperation<OnboardingResult>;
  cleanup(epoch: SessionEpoch): ActorOperation<OnboardingResult>;
  confirmMissingProfile(epoch: SessionEpoch): ActorOperation<VerificationResult>;
}

/** Local-user removal port (global destructive cleanup; never changes on-chain identity). */
export interface RemovalPort extends CancellablePort {
  removeLocalUser(epoch: SessionEpoch): ActorOperation<RemovalResult>;
}

/** Browser coordination port (SharedWorker → Web Lock → lease → blocked). */
export interface BrowserCoordinationPort extends CancellablePort {
  acquire(epoch: SessionEpoch): ActorOperation<CoordinationResult>;
  release(epoch: SessionEpoch): Promise<void>;
}

/** Typed in-memory navigation port (never URL/history identifiers). */
export interface NavigationPort {
  push(destination: TypedDestinationKind): NavigationToken;
  resolve(token: NavigationToken): TypedDestinationKind | null;
  clear(): void;
}

/** Opt-in allowlisted aggregate telemetry port (first-party only). */
export interface TelemetryPort {
  emit(event: AllowlistedTelemetryEvent): void;
}

/**
 * Allowlisted telemetry event — the ONLY fields permitted when a general
 * application preference already records explicit opt-in. No stable identity,
 * device, session, credential, file, election, support text, or raw failure.
 */
export interface AllowlistedTelemetryEvent {
  readonly platform: EnvironmentContext['runtimeTarget'];
  readonly applicationVersion: string;
  readonly coarseStage: 'initializing' | 'noLocalUser' | 'locked' | 'authenticated' | 'error' | 'removal';
  readonly typedOutcome: string | null;
  readonly coarseDurationMs: number | null;
}

/**
 * SECRET SUBMISSION SINK — the ONLY secret-bearing surface in the auth
 * contracts. Invoked by the UI directly against the isolated secret
 * authority; never exposed to XState, React business state, logging,
 * telemetry, or snapshots. Input clears immediately after accepted transfer.
 *
 * @deprecated-for-machine — importing this into any machine/state module is a
 * security violation; a dedicated lint/scan rule enforces the boundary.
 */
export interface SecretSubmissionSink {
  /** Transfers the secret directly to the authority for the given operation. */
  submitSecret(operationId: OperationId, secret: string): void;
  /** Clears any transient secret material held by the sink. */
  clearTransient(): void;
}

/** Aggregate of all production-capable actor ports exposed to the authority. */
export interface AuthActors {
  readonly localUserAuthority: LocalUserAuthorityPort | null;
  readonly secretAuthority: SecretAuthorityPort | null;
  readonly identityVerification: IdentityVerificationPort | null;
  readonly onboarding: Record<OnboardingKind, OnboardingPort | null>;
  readonly removal: RemovalPort | null;
  readonly browserCoordination: BrowserCoordinationPort | null;
  readonly navigation: NavigationPort;
  readonly telemetry: TelemetryPort | null;
}

/** Registered capability descriptor used by production registration validation. */
export interface CapabilityRegistration {
  readonly capability: CapabilityId;
  /** Availability classification; mandatory capabilities must be present and safe. */
  readonly availability: 'mandatory' | 'optional' | 'temporaryMode' | 'unavailable';
  /** True only for synthetic/test/demo actors — never valid in production. */
  readonly synthetic: boolean;
}

/** Deterministic safe diagnostics from production registration validation. */
export type RegistrationDiagnosticCode =
  | 'MISSING_MANDATORY'
  | 'DUPLICATE_REGISTRATION'
  | 'SYNTHETIC_IN_PRODUCTION'
  | 'INCOMPATIBLE_AVAILABILITY'
  | 'UNSAFE_COORDINATION';

export interface RegistrationDiagnostic {
  readonly code: RegistrationDiagnosticCode;
  readonly capability: CapabilityId;
}

export interface RegistryValidationResult {
  readonly ok: boolean;
  readonly diagnostics: readonly RegistrationDiagnostic[];
  /** Capabilities that may drive production behavior (mandatory present, non-synthetic). */
  readonly availableCapabilities: ReadonlySet<CapabilityId>;
}
