/**
 * FEAT-016 Task 2.1 — canonical licence unsigned-transaction serialization.
 *
 * Byte-exact writer for the sole FEAT-015 licence assignment envelope:
 * `{TransactionId, PayloadKind, TransactionTimeStamp, Payload, PayloadSize}`
 * with a 3-digit-millisecond UTC ISO timestamp and PayloadSize = UTF-8 byte
 * length of the Payload JSON. The Payload object is serialized in its declared
 * member order (FEAT-015 canonical writer semantics); no JCS reordering is
 * applied to the licence envelope.
 *
 * Canonical digests are proven byte-exact against the public FEAT-015 corpus
 * (`licence-transaction-vectors.json`, LIC-FIX-001…003) in the fixture tests.
 *
 * Normative source: FEAT-015 fixture corpus; FEAT-016 FeatureDescription
 * "Licence Transaction and Pending Journal".
 */

import { sha256Hex } from '../identity-compatibility/crypto';

/** Payload member order follows FEAT-015 declaration order (baseline shape). */
export interface LicenceBaselinePayload {
  readonly TransitionIntent: 'baseline_free';
  readonly RequestedPlanId: string;
  readonly ObservedCatalogueVersion: string;
}

/** Upgrade payload adds the two expected-current members (FEAT-017 later). */
export interface LicenceUpgradePayload {
  readonly TransitionIntent: 'confirmed_upgrade';
  readonly RequestedPlanId: string;
  readonly ObservedCatalogueVersion: string;
  readonly ExpectedCurrentLicenceTransactionId: string;
  readonly ExpectedCurrentPlanId: string;
}

export type LicencePayload = LicenceBaselinePayload | LicenceUpgradePayload;

/** Inputs for canonical unsigned-transaction serialization. */
export interface LicenceCanonicalUnsignedTransaction {
  readonly TransactionId: string;
  readonly PayloadKind: string;
  readonly TransactionTimeStamp: string; // UTC ISO-8601 with .fff milliseconds
  readonly Payload: LicencePayload;
  readonly PayloadSize: number;
}

/** UTF-8 byte length of the payload's JSON serialization (declaration order). */
export function licencePayloadSizeBytes(payload: LicencePayload): number {
  return new TextEncoder().encode(JSON.stringify(payload)).length;
}

/** Serialize an unsigned licence transaction exactly as the FEAT-015 writer. */
export function serializeLicenceUnsignedTransaction(
  tx: LicenceCanonicalUnsignedTransaction,
): string {
  return JSON.stringify({
    TransactionId: tx.TransactionId,
    PayloadKind: tx.PayloadKind,
    TransactionTimeStamp: tx.TransactionTimeStamp,
    Payload: tx.Payload,
    PayloadSize: tx.PayloadSize,
  });
}

/** SHA-256 hex digest over the canonical UTF-8 bytes. */
export function licenceTransactionDigest(canonicalJson: string): string {
  return sha256Hex(new TextEncoder().encode(canonicalJson));
}
