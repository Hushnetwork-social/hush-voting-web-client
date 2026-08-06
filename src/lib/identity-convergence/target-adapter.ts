/**
 * FEAT-011 Task 4.7 — cross-target coordinator adapter contract and handoff.
 *
 * One target-neutral coordinator contract over Browser worker, Ubuntu Rust,
 * and Android Rust/Kotlin operation-specific authorities. All targets emit
 * the same closed public outcomes and state transitions; secret transfer,
 * signing, and storage stay inside the selected target authority. A partial
 * or incompatible target fails closed BEFORE sensitive entry — no Browser or
 * software fallback is ever attempted.
 */

import { CONVERGENCE_OPERATIONS, type ConvergenceOperationId } from './contracts';
import { sha256Hex } from '../identity-compatibility/crypto';

/** Target classes recognized by the closed composition. */
export type CoordinatorTargetClass = 'web' | 'ubuntu' | 'android';

/** Versioned target adapter descriptor (the immutable Phase 6 composition handoff). */
export interface TargetCoordinatorHandoff {
  readonly contractVersion: 1;
  readonly targetClass: CoordinatorTargetClass;
  /** The exact set of convergence operations the target implements. */
  readonly operations: ReadonlyArray<ConvergenceOperationId>;
  /** Digest over the handoff JSON (integrity pin for the composition). */
  readonly handoffDigest: string;
  /** True only for dev/test harness actors — never valid in production. */
  readonly synthetic: boolean;
}

/** Closed target capability validation outcomes. */
export type TargetValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'UNKNOWN_TARGET' | 'MISSING_OPERATION' | 'FORBIDDEN_OPERATION' | 'SIGNING_UNSUPPORTED' | 'SYNTHETIC_IN_PRODUCTION' | 'DIGEST_MISMATCH' | 'UNSUPPORTED_VERSION' };

/** Digest of the handoff JSON (sha-256 hex via the canonical FEAT-001 primitive). */
export function computeHandoffDigest(handoff: Omit<TargetCoordinatorHandoff, 'handoffDigest'>): string {
  const { handoffDigest: _, ...rest } = handoff as TargetCoordinatorHandoff;
  void _;
  return sha256Hex(new TextEncoder().encode(JSON.stringify(rest)));
}

/**
 * Validate a target adapter handoff against the frozen composition rules:
 * known target, all mandatory operations, no forbidden/generic operation,
 * signing operations require native custody (web target may only sign inside
 * its worker authority — enforced by the composition, not by this check for
 * web), no synthetic actors in production, digest integrity, version match.
 */
export function validateTargetHandoff(
  handoff: TargetCoordinatorHandoff,
  production: boolean,
): TargetValidationResult {
  if (handoff.contractVersion !== 1) {
    return { ok: false, code: 'UNSUPPORTED_VERSION' };
  }
  if (!['web', 'ubuntu', 'android'].includes(handoff.targetClass)) {
    return { ok: false, code: 'UNKNOWN_TARGET' };
  }
  if (production && handoff.synthetic) {
    return { ok: false, code: 'SYNTHETIC_IN_PRODUCTION' };
  }
  if (handoff.handoffDigest !== computeHandoffDigest(handoff)) {
    return { ok: false, code: 'DIGEST_MISMATCH' };
  }
  for (const operation of CONVERGENCE_OPERATIONS) {
    if (!handoff.operations.includes(operation)) {
      return { ok: false, code: 'MISSING_OPERATION' };
    }
  }
  for (const operation of handoff.operations) {
    if (!(CONVERGENCE_OPERATIONS as readonly string[]).includes(operation)) {
      return { ok: false, code: 'FORBIDDEN_OPERATION' };
    }
  }
  // Native targets own signing/custody through the mandatory operations above;
  // any missing operation (including signing) fails as MISSING_OPERATION.
  return { ok: true };
}

/** sha-256 hex (canonical FEAT-001 primitive, imported above). */
