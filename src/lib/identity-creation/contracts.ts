/**
 * FEAT-007 identity-creation — creation and lifecycle contracts.
 *
 * Framework-neutral (no React, Next.js, DOM, storage, transport, or
 * state-store dependencies). Defines the closed vocabulary for the Create User
 * workflow: safe public review projections, provisional/saved/confirmed
 * lifecycle, opaque operation/epoch references, reconciliation triggers,
 * typed failures, cancellation, and the downstream missing-profile contract.
 *
 * SECRET BOUNDARY: nothing in this module can represent a password, mnemonic,
 * private key, transaction JSON, signature, or generic capability. The page
 * receives only normalized alias, visibility, abbreviated addresses, progress,
 * and typed outcomes. The active secret authority (browser worker / Ubuntu /
 * Android) owns all credential material.
 *
 * Normative source: FEAT-007 FeatureDescription "Provisional Vault and
 * Submission Boundary", "Submission Outcome Contract", "Terminology",
 * "Platform Composition"; FEAT-002 secret-free ports; FEAT-003 lifecycle.
 */

/** Opaque operation identifier issued by the authority (never a secret). */
export type CreationOperationId = string & { readonly __creationOperationId: unique symbol };

/** Opaque creation epoch; results with a stale epoch are ignored. */
export type CreationEpoch = string & { readonly __creationEpoch: unique symbol };

/** Immutable initial visibility choice for a new identity. */
export type CreationVisibility = 'private' | 'public';

/**
 * Local vault lifecycle authority (FEAT-003-compatible vocabulary).
 * Only exact `GetIdentity` confirmation establishes a confirmed identity;
 * `PendingRegistration`/`Active` local flags are never blockchain truth.
 */
export type CreationLifecycle =
  | 'provisional' // sealed createProvision record; not authenticated
  | 'savedWaiting' // ACCEPTED/matching-key PENDING; waiting for block confirmation
  | 'confirmed' // exact signing/encryption pair returned by GetIdentity
  | 'failClosed'; // corruption/terminal rejection/quarantine

/** In-memory workflow screen/stage (typed; URL stays `/`). */
export type CreationStage =
  | 'preflight' // platform security/persistence preflight
  | 'profile' // alias + initial visibility
  | 'generating' // explicit P-01 generation (progress after 150 ms)
  | 'recovery' // transient 24-word reveal + six-position confirmation
  | 'protect' // separate Device-password step
  | 'review' // safe final review before signing
  | 'provisionalResume' // Finish creating your identity
  | 'waiting' // mempool waiting gate (polling)
  | 'delay' // three-minute abnormal confirmation delay
  | 'connection' // Waiting for connection (transport ambiguous)
  | 'correcting' // editable pre-admission alias rejection
  | 'cancelling' // destructive-confirmed cancellation
  | 'locked' // lifecycle lock; returning-user unlock
  | 'terminal'; // fail-closed terminal state

/** Reconciliation trigger vocabulary (one coalesced authority-owned cycle). */
export type ReconciliationTrigger =
  | 'startup'
  | 'provisionalResume'
  | 'unlock'
  | 'foreground'
  | 'connectivityRestored'
  | 'checkAgain'
  | 'pollTick';

/** Closed typed creation failures (safe; never echo secrets). */
export type CreationFailureCode =
  | 'PREFILT_UNSUPPORTED_PLATFORM'
  | 'PREFILT_TEMPORARY_UNAVAILABLE'
  | 'GENERATION_TIMEOUT'
  | 'GENERATION_EXHAUSTED'
  | 'RECOVERY_ATTEMPTS_EXHAUSTED'
  | 'PASSWORD_POLICY'
  | 'PASSWORD_CAPABILITY_EXPIRED'
  | 'CAPABILITY_CONSUMED'
  | 'STALE_EPOCH'
  | 'DOUBLE_DISPATCH'
  | 'PROVISION_FAILED'
  | 'PROMOTION_FAILED'
  | 'CORRUPT_VAULT'
  | 'MISSING_TRANSACTION'
  | 'SIGNING_BINDING_MISMATCH'
  | 'TERMINAL_REJECTION'
  | 'COMPATIBILITY_ERROR'
  | 'CANCELLATION_ROLLBACK_FAILED'
  | 'QUARANTINED'
  | 'UNKNOWN_FAILURE';

export interface CreationFailure {
  readonly ok: false;
  readonly code: CreationFailureCode;
  /** Safe diagnostic text; never contains credentials, addresses, or transaction material. */
  readonly message: string;
  /** Sanitized support code (opaque, safe). */
  readonly supportCode: string;
}

export type CreationResult<T> = { readonly ok: true; readonly value: T } | CreationFailure;

/**
 * Safe public review projection — the ONLY profile data that may cross the
 * authority boundary. Abbreviated addresses follow the design baseline
 * (`<first 8>…<last 6>`). No secret, full address, transaction, or capability
 * is representable.
 */
export interface CreationReviewProjection {
  readonly normalizedAlias: string;
  readonly visibility: CreationVisibility;
  readonly abbreviatedSigningAddress: string;
  readonly abbreviatedEncryptionAddress: string;
  readonly recoveryConfirmed: boolean;
  readonly deviceProtectionReady: boolean;
  readonly stage: CreationStage;
  readonly progress: number; // 0..1 coarse progress within the current stage
}

/** Opaque provisioning authorization reference (purpose/channel/epoch-bound). */
export type ProvisioningAuthorizationRef = string & { readonly __provisioningAuthorizationRef: unique symbol };

/** Signed-transaction retention status (exact bytes, encrypted). */
export type RetainedTransactionStatus = 'retained' | 'cleared' | 'missing' | 'corrupt';

/** Safe operational evidence category (privacy-safe; no secrets, no full transaction). */
export type CreationEvidenceCategory =
  | 'preflight-passed'
  | 'generation-succeeded'
  | 'recovery-confirmed'
  | 'device-protected'
  | 'provision-committed'
  | 'submission-accepted'
  | 'submission-pending'
  | 'submission-already-exists'
  | 'submission-editable-rejection'
  | 'submission-terminal-rejection'
  | 'transport-ambiguous'
  | 'confirmation-exact'
  | 'confirmation-delayed'
  | 'compatibility-error'
  | 'cancelled-before-submit'
  | 'cancelled-ambiguous'
  | 'quarantined';

/**
 * Missing-profile creation contract (published for downstream FEAT-008):
 * an explicit, secret-free seam for creating a new identity when recovery
 * yields no on-chain profile. Contains only safe public fields.
 */
export interface MissingProfileCreationContract {
  readonly version: 1;
  readonly requiresAuthoritativeAbsence: true;
  readonly requiresCredentialVerification: true;
  readonly fields: ReadonlyArray<'normalizedAlias' | 'visibility' | 'abbreviatedSigningAddress' | 'abbreviatedEncryptionAddress'>;
  /** One-use provisioning authorization; expires per adapter policy (≤60 s). */
  readonly authorizationRef: ProvisioningAuthorizationRef;
}

/** Abbreviate a public address to `<first 8>…<last 6>`. */
export function abbreviateAddress(address: string): string {
  if (address.length <= 14) {
    return address;
  }
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

/** Compile-time + runtime proof that no generic secret surface is representable. */
export type ForbiddenCreationSecretSurface = 'password' | 'mnemonic' | 'privateKey' | 'transactionJson' | 'signature' | 'fullAddress' | 'genericCapability';

export function assertNoSecretSurface(projection: CreationReviewProjection): ForbiddenCreationSecretSurface[] {
  const violations: ForbiddenCreationSecretSurface[] = [];
  const json = JSON.stringify(projection);
  // The projection type itself only carries safe fields; this guard catches
  // future accidental widening of the boundary.
  const keys = Object.keys(projection) as ReadonlyArray<keyof CreationReviewProjection>;
  for (const key of keys) {
    if (['password', 'mnemonic', 'privateKey', 'transaction', 'signature'].includes(key)) {
      violations.push(key as ForbiddenCreationSecretSurface);
    }
  }
  if (json.includes('BEGIN') && json.includes('PRIVATE')) {
    violations.push('privateKey');
  }
  return violations;
}
