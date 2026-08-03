/**
 * FEAT-007 identity-creation — device protection and provisional persistence.
 *
 * Platform-neutral policy for the Protect-this-device step and the crash-safe
 * provisional vault boundary: fresh one-use password capabilities (≤60 s),
 * sealed provisional commit before any network call, provisional → saved →
 * confirmed lifecycle promotion, exact-transaction retention/rebuild rules,
 * and cancellation/rollback/quarantine behavior. Secret material never enters
 * this module; the device password travels directly to the active secret
 * authority through the FEAT-002 `SecretSubmissionSink` boundary.
 *
 * Normative source: FEAT-007 FeatureDescription "Provisional Vault and
 * Submission Boundary", "Exact Transaction Retention", "Correctable
 * Rejection", "Cancellation and Removal Boundaries", "Promotion Failure After
 * Submission", "Device protection and review".
 */

/** Fresh one-use provisioning authorization (purpose/channel/epoch-bound, ≤60 s). */
export type ProvisionAuthorizationStatus = 'none' | 'issued' | 'consumed' | 'expired';

export interface ProvisionAuthorization {
  readonly status: ProvisionAuthorizationStatus;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

export const PASSWORD_CAPABILITY_MAX_MS = 60_000 as const;

/** Issue a fresh password capability. */
export function issueProvisionAuthorization(nowMs: number): ProvisionAuthorization {
  return { status: 'issued', issuedAtMs: nowMs, expiresAtMs: nowMs + PASSWORD_CAPABILITY_MAX_MS };
}

/** Consume a capability once; returns fail-closed on wrong state/expiry. */
export function consumeProvisionAuthorization(auth: ProvisionAuthorization, nowMs: number): { readonly ok: true; readonly auth: ProvisionAuthorization } | { readonly ok: false; readonly code: 'EXPIRED' | 'CONSUMED' | 'NONE' } {
  if (auth.status !== 'issued') {
    return { ok: false, code: auth.status === 'consumed' ? 'CONSUMED' : auth.status === 'expired' ? 'EXPIRED' : 'NONE' };
  }
  if (nowMs > auth.expiresAtMs) {
    return { ok: false, code: 'EXPIRED' };
  }
  return { ok: true, auth: { ...auth, status: 'consumed' } };
}

/** Provisional vault record lifecycle (local authority, never blockchain truth). */
export type ProvisionLifecycle = 'provisional' | 'savedWaiting' | 'confirmed' | 'failClosed';

export type PromotionOutcome =
  | { readonly kind: 'promotedToSavedWaiting' }
  | { readonly kind: 'promotedToConfirmed' }
  | { readonly kind: 'localTransitionFailed'; readonly code: 'CORRUPT_RECORD' | 'UNSUPPORTED_SCHEMA' | 'JOURNAL_INCONSISTENT' | 'UNKNOWN' };

/** Retained exact-transaction status. */
export type RetainedTransactionStatus = 'retained' | 'cleared' | 'missing' | 'corrupt';

/**
 * Provisioning boundary ports (implemented by the sealed browser/native
 * authority in Phase 6 integration). No generic sign/decrypt/key access.
 */
export interface ProvisioningPort {
  /** Atomically persist the sealed provisional record BEFORE the network call. */
  createProvision(input: ProvisionInput): Promise<{ readonly ok: true; readonly recordRef: string } | { readonly ok: false; readonly code: string }>;
  /** Local lifecycle promotion only — never touches blockchain state. */
  promoteToSavedWaiting(recordRef: string): Promise<PromotionOutcome>;
  promoteToConfirmed(recordRef: string): Promise<PromotionOutcome>;
  retainExactTransaction(recordRef: string, transactionDigest: string): Promise<{ readonly ok: true } | { readonly ok: false; readonly code: 'CORRUPT' | 'UNKNOWN' }>;
  readRetainedTransactionStatus(recordRef: string): Promise<RetainedTransactionStatus>;
  clearRetainedTransaction(recordRef: string): Promise<{ readonly ok: true } | { readonly ok: false; readonly code: string }>;
  /** Cancellable rollback; must verify storage absence before first-run restore. */
  rollbackProvision(recordRef: string): Promise<{ readonly ok: true; readonly verifiedAbsent: boolean } | { readonly ok: false; readonly code: 'NOT_VERIFIED' | 'UNKNOWN' }>;
}

/** Secret-free inputs for a sealed provisioning operation. */
export interface ProvisionInput {
  readonly normalizedAlias: string;
  readonly visibility: 'private' | 'public';
  readonly publicSigningAddress: string;
  readonly publicEncryptAddress: string;
  /** Reviewed profile is bound to the one-use operation-scoped authorization. */
  readonly authorizationRef: string;
  readonly transactionDigest: string;
}

/** Promotion failure policy: retry only the local transition; never rollback or resubmit. */
export function handlePromotionFailure(outcome: PromotionOutcome): { readonly action: 'retryLocalTransition' } | { readonly action: 'preserveAndReport'; readonly failClosed: true } {
  if (outcome.kind === 'localTransitionFailed') {
    // Never roll back credentials; never resubmit; keep sealed record + exact
    // transaction. Retry only the atomic local lifecycle transition.
    return { action: 'retryLocalTransition' };
  }
  return { action: 'preserveAndReport', failClosed: true };
}

/**
 * Rebuild eligibility for a legitimately missing transaction record:
 * authenticated credential/profile verification AND authoritative absence are
 * both required. Corruption is never "missing".
 */
export function canRebuildMissingTransaction(authenticatedVerification: boolean, authoritativeAbsent: boolean, retainedStatus: RetainedTransactionStatus): boolean {
  if (retainedStatus === 'corrupt') {
    return false; // AEAD failure/digest mismatch/journal inconsistency = corruption, fail closed
  }
  if (retainedStatus !== 'missing') {
    return false; // retained or cleared: no rebuild path
  }
  return authenticatedVerification && authoritativeAbsent;
}

/** Cancellation decision before any submission attempt. */
export type PreSubmitCancellation =
  | { readonly kind: 'safeRollback'; readonly verifiedAbsent: boolean }
  | { readonly kind: 'blocked'; readonly quarantine: true };

export function decidePreSubmitCancellation(rollback: { readonly ok: true; readonly verifiedAbsent: boolean } | { readonly ok: false; readonly code: string }): PreSubmitCancellation {
  if (rollback.ok && rollback.verifiedAbsent) {
    return { kind: 'safeRollback', verifiedAbsent: true };
  }
  // Rollback could not verify absence: quarantine the authority, revoke
  // capabilities, block first-run creation/authentication until verified.
  return { kind: 'blocked', quarantine: true };
}

/** Post-submission cancellation warning (mempool cannot be cancelled). */
export type PostSubmitCancellation = { readonly kind: 'confirmedProfile' } | { readonly kind: 'warnAndRequireAck'; readonly transactionMayConfirm: true };

export function decidePostSubmitCancellation(onlineLookupExactProfile: boolean): PostSubmitCancellation {
  if (onlineLookupExactProfile) {
    // Confirmed profile: setup cancellation is unavailable; use separate
    // local-user removal governance.
    return { kind: 'confirmedProfile' };
  }
  return { kind: 'warnAndRequireAck', transactionMayConfirm: true };
}
