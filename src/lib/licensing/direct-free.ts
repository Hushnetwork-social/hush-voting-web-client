/**
 * FEAT-016 Task 3.3/3.4 — Direct Free construction and exact submission policy.
 *
 * Builds the canonical FEAT-015 baseline licence transaction from the
 * server-authoritative no-active template ONLY. The payload is exactly
 * `{TransitionIntent: baseline_free, RequestedPlanId: hushvoting.direct.free,
 * ObservedCatalogueVersion: <template>}` — the two upgrade-only members are
 * absent. Rejects template mismatch/omission/unknown values before signing;
 * no beneficiary, terms, constraints, catalogue facts, or local Direct Free
 * fallback is ever client-authored.
 *
 * Submission outcome mapping (FEAT-015 admission vocabulary):
 *   ACCEPTED / PENDING   -> query-only reconciliation (never access)
 *   ALREADY_EXISTS       -> indexed; immediately issue a fresh query
 *   terminal validation  -> fail closed with safe guidance (never loop)
 *   timeout/cancellation -> preserve the exact record; reconcile truth first
 *
 * Normative source: FEAT-016 FeatureDescription "Licence Transaction and
 * Pending Journal" (construction and seal-before-submit, admission outcomes);
 * FEAT-015 frozen payload/fixture corpus.
 */

import {
  LICENCE_CATALOGUE_VERSION_V1,
  LICENCE_PLAN_DIRECT_FREE,
  LICENCE_TRANSITION_INTENT_BASELINE_FREE,
  type LicenceDirectFreeTemplate,
} from './contracts';
import {
  licencePayloadSizeBytes,
  licenceTransactionDigest,
  serializeLicenceUnsignedTransaction,
  type LicencePayload,
} from './canonical';

export type DirectFreeBuildResult =
  | {
      readonly ok: true;
      readonly payload: LicencePayload;
      readonly payloadSize: number;
      readonly canonicalUnsignedJson: string;
      readonly digest: string;
    }
  | { readonly ok: false; readonly reason: 'not-server-template' | 'stale-or-unbounded-catalogue' };

/**
 * Validate the parsed server template and construct the canonical unsigned
 * baseline envelope with the exact transaction id + UTC timestamp supplied by
 * the authority (one transaction: one id/time). `canonicalUnsignedJson` is
 * byte-exact against the FEAT-015 corpus for the frozen fixed inputs.
 */
export function buildDirectFreeUnsignedTransaction(
  template: LicenceDirectFreeTemplate,
  transactionId: string,
  transactionTimestampUtc: string,
): DirectFreeBuildResult {
  if (
    template.TransitionIntent !== LICENCE_TRANSITION_INTENT_BASELINE_FREE ||
    template.RequestedPlanId !== LICENCE_PLAN_DIRECT_FREE
  ) {
    return { ok: false, reason: 'not-server-template' };
  }
  if (template.ObservedCatalogueVersion.length === 0 || template.ObservedCatalogueVersion.length > 256) {
    return { ok: false, reason: 'stale-or-unbounded-catalogue' };
  }
  const payload: LicencePayload = {
    TransitionIntent: LICENCE_TRANSITION_INTENT_BASELINE_FREE,
    RequestedPlanId: LICENCE_PLAN_DIRECT_FREE,
    ObservedCatalogueVersion: template.ObservedCatalogueVersion,
  };
  const payloadSize = licencePayloadSizeBytes(payload);
  const canonicalUnsignedJson = serializeLicenceUnsignedTransaction({
    TransactionId: transactionId,
    PayloadKind: '71370664-5eb4-4ce9-b96a-d7e7ffe53db5',
    TransactionTimeStamp: transactionTimestampUtc,
    Payload: payload,
    PayloadSize: payloadSize,
  });
  return {
    ok: true,
    payload,
    payloadSize,
    canonicalUnsignedJson,
    digest: licenceTransactionDigest(canonicalUnsignedJson),
  };
}

/** Frozen supported catalogue version the client baseline builder pins. */
export function isSupportedCatalogueVersion(observed: string): boolean {
  return observed === LICENCE_CATALOGUE_VERSION_V1;
}

/** Typed admission outcomes surfaced by the transaction ingress (FEAT-015). */
export type LicenceAdmissionOutcome =
  | 'accepted'
  | 'pending'
  | 'alreadyExists'
  | 'terminalRejected'
  | 'uncertain';

/** Closed submission decision (never grants access by itself). */
export type SubmissionDecision =
  | { readonly kind: 'reconcileByQuery' } // ACCEPTED/PENDING -> query-only waiting
  | { readonly kind: 'queryImmediately' } // ALREADY_EXISTS -> indexed; fresh query now
  | { readonly kind: 'failClosed' } // terminal validation -> safe guidance; exact record preserved
  | { readonly kind: 'preserveAndReconcile' }; // timeout/cancel/unknown -> keep exact record; query first

export function decideSubmissionOutcome(outcome: LicenceAdmissionOutcome): SubmissionDecision {
  switch (outcome) {
    case 'accepted':
    case 'pending':
      return { kind: 'reconcileByQuery' };
    case 'alreadyExists':
      return { kind: 'queryImmediately' };
    case 'terminalRejected':
      return { kind: 'failClosed' };
    case 'uncertain':
      return { kind: 'preserveAndReconcile' };
  }
}
