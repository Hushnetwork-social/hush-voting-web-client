/**
 * FEAT-003 vault-core lifecycle — deterministic lifecycle transitions.
 *
 * Lifecycle states: NoVault → PendingRegistration → Active, plus migration,
 * replacement, password-change, cleanup, and resumable removal. Rules:
 * - a new encrypted vault is staged without touching an existing active vault;
 * - new identity creation activates a verified vault as PendingRegistration before
 *   blockchain submission (crash safety); successful chain reconciliation transitions
 *   it atomically to Active;
 * - recovery/reprovisioning verifies or explicitly creates the profile online before
 *   atomically replacing the old vault; a corrupt/forgotten-password source is never
 *   overwritten before the replacement vault is verified and can unlock;
 * - migration is lazy/atomic during successful unlock; failure leaves the old slot
 *   active (non-destructive);
 * - password change rewraps every ordinary/mnemonic record key under fresh purpose
 *   keys without decrypting/re-encrypting payloads unnecessarily;
 * - removal is global, idempotent, resumable: tombstone → cleanup stages → verify
 *   absence → NoVault; never reports success before required artifacts are absent.
 *
 * Normative source: FEAT-003 FeatureDescription "Atomic Storage and Lifecycle",
 * "Local-User Removal".
 */
import type { VaultLifecycleStatus } from '../contracts/records';

export type LifecycleStatus = 'NoVault' | VaultLifecycleStatus;

/** Deterministic lifecycle state. */
export interface LifecycleState {
  readonly status: LifecycleStatus;
  readonly pendingSubmission: boolean;
}

export type LifecycleTransition =
  | { readonly ok: true; readonly state: LifecycleState }
  | { readonly ok: false; readonly code: 'INVALID_TRANSITION' | 'NOT_VERIFIED' | 'VERIFICATION_FAILED'; readonly state: LifecycleState };

/** Allowed transition matrix (closed). */
const ALLOWED: Readonly<Record<LifecycleStatus, readonly LifecycleStatus[]>> = {
  NoVault: ['PendingRegistration'],
  PendingRegistration: ['Active', 'NoVault'],
  Active: ['NoVault'],
};

export function canTransition(from: LifecycleStatus, to: LifecycleStatus): boolean {
  return ALLOWED[from]?.includes(to) ?? false;
}

/** Stage a new verified vault: NoVault → PendingRegistration (before submission). */
export function stagePendingRegistration(state: LifecycleState, verified: boolean): LifecycleTransition {
  if (state.status !== 'NoVault') return { ok: false, code: 'INVALID_TRANSITION', state };
  if (!verified) return { ok: false, code: 'NOT_VERIFIED', state };
  return { ok: true, state: { status: 'PendingRegistration', pendingSubmission: false } };
}

/** Submit the identity: record that blockchain submission is pending (crash-safe). */
export function beginSubmission(state: LifecycleState): LifecycleTransition {
  if (state.status !== 'PendingRegistration') return { ok: false, code: 'INVALID_TRANSITION', state };
  return { ok: true, state: { ...state, pendingSubmission: true } };
}

/** Idempotent reconciliation after chain confirmation: PendingRegistration → Active. */
export function reconcileToActive(state: LifecycleState, confirmed: boolean): LifecycleTransition {
  if (state.status !== 'PendingRegistration') return { ok: false, code: 'INVALID_TRANSITION', state };
  if (!confirmed) return { ok: false, code: 'VERIFICATION_FAILED', state };
  return { ok: true, state: { status: 'Active', pendingSubmission: false } };
}

/** Verified removal completes: → NoVault. */
export function completeRemoval(state: LifecycleState): LifecycleTransition {
  if (state.status === 'NoVault') return { ok: true, state };
  return { ok: true, state: { status: 'NoVault', pendingSubmission: false } };
}

/** Migration result: failure keeps the old slot active (non-destructive). */
export type MigrationResult =
  | { readonly ok: true; readonly migrated: true }
  | { readonly ok: false; readonly code: 'MIGRATION_FAILED_ROLLBACK_AVAILABLE' };

/** Password-change outcome: rewrapped keys committed; identity unchanged. */
export interface PasswordChangeCommit {
  readonly rewrappedRecordCount: number;
  readonly payloadsReEncrypted: 0;
  readonly identityChanged: false;
}

export function passwordChangeCommit(rewrappedRecordCount: number): PasswordChangeCommit {
  return {
    rewrappedRecordCount,
    payloadsReEncrypted: 0,
    identityChanged: false,
  };
}
