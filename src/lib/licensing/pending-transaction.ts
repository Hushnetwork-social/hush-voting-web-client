/**
 * FEAT-016 Task 2.3 — purpose-bound pending licence transaction record.
 *
 * The encrypted authority-custody record for one exact Direct Free (or later
 * upgrade) licence transaction. It reuses the FEAT-011 two-slot
 * read-back/CAS discipline conceptually but is purpose-isolated: distinct
 * purpose string, AAD label, key-derivation label, and store namespace so
 * licence records and identity records can never open each other.
 *
 * SECRET BOUNDARY: `transaction.exactJson` holds the exact signed licence
 * transaction bytes and exists ONLY inside approved encrypted authority
 * custody (browser SharedWorker sealed store / native encrypted journal).
 * Page/WebView state receives only safe progress and the runtime projection.
 * This module exposes no encryption, no storage adapter, and no export path.
 *
 * The canonical JSON serialization order is frozen and shared byte-for-byte
 * with the Rust codec (`src-tauri/src/licensing_record.rs`) — parity is proven
 * by cross-language fixture tests in Task 2.4.
 *
 * Normative source: FEAT-016 FeatureDescription "Licence Transaction and
 * Pending Journal", "Restart and Recovery"; FEAT-011 sealed pending-store
 * discipline; planning-analysis-report §6.
 */

import { sha256Hex } from '../identity-compatibility/crypto';

/** Distinct journal purpose so licence records cannot alias identity records. */
export const LICENCE_PENDING_PURPOSE = 'pending_licence_transaction' as const;

/** Distinct AAD/key-derivation/store-namespace labels (approved custody). */
export const LICENCE_PENDING_AAD_LABEL = 'hushvoting-licence-pending-v1' as const;
export const LICENCE_PENDING_KEY_LABEL = 'licence-pending-journal' as const;
export const LICENCE_PENDING_STORE_NAMESPACE = 'hushvoting-licence-journal' as const;

export const LICENCE_PENDING_SCHEMA_VERSION = 1 as const;

export const LICENCE_PENDING_MAX_JSON_BYTES = 65_536 as const;
export const LICENCE_PENDING_MAX_ATTEMPT_EVIDENCE = 64 as const;
export const LICENCE_PENDING_ID_MAX_LENGTH = 128 as const;

/** Exact signed transaction (sealed): canonical JSON + sha-256 digest. */
export interface LicenceExactSignedTransaction {
  readonly exactJson: string;
  readonly digest: string; // lowercase sha-256 hex over UTF-8 bytes
}

/** Bounded attempt evidence for one admission/reconciliation outcome. */
export type LicencePendingAttemptOutcome =
  | 'accepted'
  | 'pending'
  | 'alreadyExists'
  | 'uncertain'
  | 'terminalRejected'
  | 'superseded';

export interface LicencePendingAttemptEvidence {
  readonly at: string; // ISO-8601 UTC
  readonly outcome: LicencePendingAttemptOutcome;
}

/**
 * Durable recovery state (never authentication). Query-first reconciliation
 * (Phase 3) drives transitions; these are the only legal values.
 */
export type LicencePendingRecoveryState =
  | 'sealed' // exact transaction sealed, not yet confirmed indexed
  | 'waitingAccepted' // ACCEPTED observed; query-only reconciliation
  | 'waitingPending' // PENDING reservation observed; query-only reconciliation
  | 'confirmedIndexed' // fresh query returned this licence active
  | 'superseded' // another valid (higher/other-device) assignment is active
  | 'retired' // no-active truth + explicit safe cleanup after exact resolution
  | 'unrecoverable'; // proven journal loss pending controlled repair

/** Closed native/browser custody target for the record. */
export type LicencePendingTargetBinding = 'web-sharedworker' | 'ubuntu-native' | 'android-native';

/** Purpose-bound sealed pending licence record (frozen field order). */
export interface LicencePendingTransactionRecord {
  readonly schemaVersion: typeof LICENCE_PENDING_SCHEMA_VERSION;
  readonly purpose: typeof LICENCE_PENDING_PURPOSE;
  readonly transaction: LicenceExactSignedTransaction;
  /** Public licence transaction reference (uuid). */
  readonly transactionId: string;
  /** Canonical signatory actor (invariant lower). */
  readonly identityBinding: string;
  /** Closed deployment/network manifest id. */
  readonly networkBinding: string;
  /** Custody target that sealed this record. */
  readonly targetBinding: LicencePendingTargetBinding;
  readonly createdUtc: string;
  readonly submittedUtc?: string;
  readonly indexObservedUtc?: string;
  readonly attemptEvidence: ReadonlyArray<LicencePendingAttemptEvidence>;
  readonly recoveryState: LicencePendingRecoveryState;
}

/**
 * Journal outcomes shared by browser and native authorities. Concrete
 * encrypted two-slot storage adapters are registered in Phase 6; the contract
 * and validating codec are frozen here.
 */
export type LicenceJournalOpOutcome =
  | { readonly ok: true; readonly record: LicencePendingTransactionRecord }
  | { readonly ok: false; readonly reason: 'not-found' | 'storage-unavailable' | 'corrupt' | 'binding-mismatch' };

/** Strict validating codec shared by TS and Rust. */

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const TARGET_BINDINGS: ReadonlyArray<string> = ['web-sharedworker', 'ubuntu-native', 'android-native'];
const RECOVERY_STATES: ReadonlyArray<string> = [
  'sealed',
  'waitingAccepted',
  'waitingPending',
  'confirmedIndexed',
  'superseded',
  'retired',
  'unrecoverable',
];
const ATTEMPT_OUTCOMES: ReadonlyArray<string> = [
  'accepted',
  'pending',
  'alreadyExists',
  'uncertain',
  'terminalRejected',
  'superseded',
];

export function digestOfPendingLicence(exactJson: string): string {
  return sha256Hex(new TextEncoder().encode(exactJson));
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, max: number = LICENCE_PENDING_MAX_JSON_BYTES): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function isIsoUtc(value: unknown): value is string {
  return typeof value === 'string' && ISO_UTC_RE.test(value);
}

/**
 * Parse + validate an untrusted record payload into the typed record.
 * Returns null on any corruption/malformed/mismatched value (data, not
 * exceptions); never coerces unknown enums.
 */
export function parsePendingLicenceRecord(value: unknown): LicencePendingTransactionRecord | null {
  if (!isRecordValue(value)) {
    return null;
  }
  if (value.schemaVersion !== LICENCE_PENDING_SCHEMA_VERSION || value.purpose !== LICENCE_PENDING_PURPOSE) {
    return null;
  }
  const tx = value.transaction;
  if (
    !isRecordValue(tx) ||
    !isBoundedString(tx.exactJson) ||
    !isBoundedString(tx.digest, 64) ||
    !SHA256_HEX_RE.test(tx.digest)
  ) {
    return null;
  }
  if (digestOfPendingLicence(tx.exactJson as string) !== tx.digest) {
    return null;
  }
  if (
    !isBoundedString(value.transactionId, LICENCE_PENDING_ID_MAX_LENGTH) ||
    !UUID_RE.test(value.transactionId as string)
  ) {
    return null;
  }
  if (!isBoundedString(value.identityBinding, LICENCE_PENDING_ID_MAX_LENGTH) ||
      !isBoundedString(value.networkBinding, LICENCE_PENDING_ID_MAX_LENGTH)) {
    return null;
  }
  const target = value.targetBinding;
  if (typeof target !== 'string' || !TARGET_BINDINGS.includes(target)) {
    return null;
  }
  if (!isIsoUtc(value.createdUtc)) {
    return null;
  }
  if (value.submittedUtc !== undefined && value.submittedUtc !== null && !isIsoUtc(value.submittedUtc)) {
    return null;
  }
  if (value.indexObservedUtc !== undefined && value.indexObservedUtc !== null && !isIsoUtc(value.indexObservedUtc)) {
    return null;
  }
  const recoveryState = value.recoveryState;
  if (typeof recoveryState !== 'string' || !RECOVERY_STATES.includes(recoveryState)) {
    return null;
  }
  const attempts = value.attemptEvidence;
  if (!Array.isArray(attempts) || attempts.length > LICENCE_PENDING_MAX_ATTEMPT_EVIDENCE) {
    return null;
  }
  for (const attempt of attempts) {
    if (
      !isRecordValue(attempt) ||
      !isIsoUtc(attempt.at) ||
      typeof attempt.outcome !== 'string' ||
      !ATTEMPT_OUTCOMES.includes(attempt.outcome)
    ) {
      return null;
    }
  }
  return {
    schemaVersion: LICENCE_PENDING_SCHEMA_VERSION,
    purpose: LICENCE_PENDING_PURPOSE,
    transaction: { exactJson: tx.exactJson as string, digest: tx.digest as string },
    transactionId: value.transactionId as string,
    identityBinding: value.identityBinding as string,
    networkBinding: value.networkBinding as string,
    targetBinding: target as LicencePendingTargetBinding,
    createdUtc: value.createdUtc as string,
    submittedUtc: value.submittedUtc === undefined || value.submittedUtc === null ? undefined : (value.submittedUtc as string),
    indexObservedUtc:
      value.indexObservedUtc === undefined || value.indexObservedUtc === null
        ? undefined
        : (value.indexObservedUtc as string),
    attemptEvidence: attempts.map((attempt) => ({
      at: (attempt as Record<string, unknown>).at as string,
      outcome: (attempt as Record<string, unknown>).outcome as LicencePendingAttemptEvidence['outcome'],
    })),
    recoveryState: recoveryState as LicencePendingRecoveryState,
  };
}

/**
 * Parse + validate a canonical JSON string (mirror of the Rust
 * `parse_record_json`). Returns null on malformed JSON or invalid records.
 */
export function parsePendingLicenceRecordJson(json: string): LicencePendingTransactionRecord | null {
  try {
    return parsePendingLicenceRecord(JSON.parse(json) as unknown);
  } catch {
    return null;
  }
}

/**
 * Serialize a record to canonical JSON with the FROZEN field order shared
 * byte-for-byte with the Rust codec. Optional fields serialize as absent
 * (never null) to keep TS and Rust output identical.
 */
export function serializePendingLicenceRecord(
  record: LicencePendingTransactionRecord,
): string {
  const json: Record<string, unknown> = {
    schemaVersion: record.schemaVersion,
    purpose: record.purpose,
    transaction: { exactJson: record.transaction.exactJson, digest: record.transaction.digest },
    transactionId: record.transactionId,
    identityBinding: record.identityBinding,
    networkBinding: record.networkBinding,
    targetBinding: record.targetBinding,
    createdUtc: record.createdUtc,
    attemptEvidence: record.attemptEvidence.map((attempt) => ({
      at: attempt.at,
      outcome: attempt.outcome,
    })),
    recoveryState: record.recoveryState,
  };
  if (record.submittedUtc !== undefined) {
    json.submittedUtc = record.submittedUtc;
  }
  if (record.indexObservedUtc !== undefined) {
    json.indexObservedUtc = record.indexObservedUtc;
  }
  return JSON.stringify(json);
}
