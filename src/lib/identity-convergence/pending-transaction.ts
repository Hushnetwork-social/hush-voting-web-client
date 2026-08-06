/**
 * FEAT-011 Task 2.3 — additive sealed pending-transaction and reconciliation contracts.
 *
 * Framework-neutral contract for the sealed pending registration record: the
 * exact signed transaction (byte-for-byte), its digest, transaction ID, safe
 * reviewed metadata, lifecycle/status, attempt evidence, epoch/network
 * binding, and rollback state. Version 2 is ADDITIVE over the browser-vault
 * v1 `CurrentRecordPlaintext` (which carries only `transactionDigest`); v1
 * meaning is never reinterpreted as containing retry bytes.
 *
 * SECRET BOUNDARY: the exact signed transaction JSON exists ONLY inside sealed
 * authority storage (encrypted at rest). Page/WebView code receives only an
 * opaque pending reference and safe progress. Nothing here can represent a
 * password, mnemonic, private key, or generic capability; no `.dat` export.
 *
 * Normative source: FEAT-011 FeatureDescription "Missing identity" and
 * "Reconcile submission and confirmation"; transition-fault-matrix T10–T21,
 * §2 fault points; planning-analysis-report §5 decision 12, §8.3–8.5;
 * FEAT-007 reconciliation constants.
 */

import { ABNORMAL_DELAY_MS, POLL_INTERVAL_MS } from '../identity-creation/reconciliation';
import { sha256Hex } from '../identity-compatibility/crypto';

/** Additive schema version; v1 records migrate without changing sealed meaning. */
export const PENDING_TRANSACTION_SCHEMA_VERSION = 2 as const;

/** Hard bounds (defense in depth; authority storage enforces them). */
export const PENDING_TRANSACTION_MAX_JSON_BYTES = 65_536 as const;
export const PENDING_TRANSACTION_MAX_ATTEMPT_EVIDENCE = 64 as const;
export const PENDING_TRANSACTION_ID_MAX_LENGTH = 128 as const;

/** Canonical digest over the exact signed transaction bytes (hex sha-256). */
export type PendingTransactionDigest = string & { readonly __pendingTransactionDigest: unique symbol };

/** Exact signed transaction JSON — sealed inside authority storage only. */
export interface ExactSignedTransaction {
  readonly exactJson: string;
  readonly digest: PendingTransactionDigest;
}

/** Safe reviewed metadata (chain-authoritative after confirmation). */
export interface PendingReviewedMetadata {
  readonly alias: string;
  readonly visibility: 'private' | 'public';
}

/** Typed structured submission outcomes (never free-form message parsing). */
export type PendingSubmitOutcome =
  | 'accepted'
  | 'pending'
  | 'alreadyExists'
  | 'rejectedEditable'
  | 'rejectedTerminal'
  | 'transportUncertain';

/** One immutable attempt record (bounded; safe evidence). */
export interface PendingAttemptEvidence {
  readonly at: string; // ISO-8601 UTC
  readonly outcome: PendingSubmitOutcome;
}

/**
 * Additive sealed pending-transaction record (v2). All fields except
 * `schemaVersion` and `attemptEvidence` are immutable after seal; rollback
 * state tracks the irreversible boundary for cancellation disclosure.
 */
export interface SealedPendingTransactionV2 {
  readonly schemaVersion: typeof PENDING_TRANSACTION_SCHEMA_VERSION;
  /** Exact signed transaction bytes + canonical digest (sealed, encrypted at rest). */
  readonly transaction: ExactSignedTransaction;
  /** Server transaction ID (bounded). */
  readonly transactionId: string;
  /** Safe reviewed metadata that produced this transaction. */
  readonly reviewedMetadata: PendingReviewedMetadata;
  readonly lifecycle: PendingLifecycle;
  readonly attemptEvidence: ReadonlyArray<PendingAttemptEvidence>;
  /** Authority epoch binding; stale epochs reject late completions. */
  readonly epochBinding: string;
  /** Closed deployment/network manifest id; mismatch fails before lookup/signing. */
  readonly networkBinding: string;
  /** Irreversible-boundary tracker for pre/post-submit cancellation disclosure. */
  readonly rollbackState: 'preSeal' | 'postSeal' | 'postSubmit';
}

/** Sealed pending lifecycle (never authentication). */
export type PendingLifecycle =
  | 'sealed' // sealed, not yet submitted (or retry-eligible after uncertainty)
  | 'waitingAccepted' // structured ACCEPTED
  | 'waitingPending' // matching-key PENDING
  | 'confirmed' // exact both-key indexed lookup; retire safely
  | 'rejectedEditable' // allowlisted editable code; correction creates a new reviewed transaction
  | 'discarded'; // other-device confirmation or explicit safe cleanup

/** Retry eligibility: exact bytes only; digest-only v1 records are never eligible. */
export function isRetryEligible(record: SealedPendingTransactionV2): boolean {
  if (record.rollbackState !== 'postSeal' && record.rollbackState !== 'postSubmit') {
    return false;
  }
  return record.lifecycle === 'sealed' || record.lifecycle === 'waitingAccepted' || record.lifecycle === 'waitingPending';
}

/** Canonical digest must equal the digest of the exact JSON bytes. */
export function verifyDigest(record: SealedPendingTransactionV2): boolean {
  return digestOf(record.transaction.exactJson) === record.transaction.digest;
}

export function digestOf(exactJson: string): PendingTransactionDigest {
  // SHA-256 over UTF-8 bytes via the canonical FEAT-001 hashing primitive.
  return sha256Hex(new TextEncoder().encode(exactJson)) as PendingTransactionDigest;
}

/** Bounds check (returns data, never throws). */
export function validatePendingTransaction(record: SealedPendingTransactionV2): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  if (record.schemaVersion !== PENDING_TRANSACTION_SCHEMA_VERSION) {
    return { ok: false, reason: 'unsupported schema version' };
  }
  if (new TextEncoder().encode(record.transaction.exactJson).length > PENDING_TRANSACTION_MAX_JSON_BYTES) {
    return { ok: false, reason: 'exact transaction exceeds size bound' };
  }
  if (record.transactionId.length === 0 || record.transactionId.length > PENDING_TRANSACTION_ID_MAX_LENGTH) {
    return { ok: false, reason: 'transaction id out of bounds' };
  }
  if (record.attemptEvidence.length > PENDING_TRANSACTION_MAX_ATTEMPT_EVIDENCE) {
    return { ok: false, reason: 'attempt evidence exceeds bound' };
  }
  if (record.epochBinding.length === 0 || record.networkBinding.length === 0) {
    return { ok: false, reason: 'epoch/network binding missing' };
  }
  if (!verifyDigest(record)) {
    return { ok: false, reason: 'digest mismatch' };
  }
  return { ok: true };
}

/**
 * Reconciliation contract (frozen): one coalesced 3 s lookup loop while
 * eligible; 3-minute abnormal-delay boundary; restart/foreground/reconnect
 * always lookup-first; other-device confirmation discards the unused local
 * transaction after chain metadata sync.
 */
export const RECONCILIATION_POLL_INTERVAL_MS = POLL_INTERVAL_MS;
export const RECONCILIATION_ABNORMAL_DELAY_MS = ABNORMAL_DELAY_MS;

/** Epoch/network binding match — mismatch fails before lookup/signing. */
export function matchesBinding(record: SealedPendingTransactionV2, epoch: string, networkBinding: string): boolean {
  return record.epochBinding === epoch && record.networkBinding === networkBinding;
}

/** Cancellation disclosure contract. */
export type CancellationDisclosure =
  | { readonly kind: 'preSubmit'; readonly safeToDestroyTransient: true }
  | { readonly kind: 'postSubmit'; readonly blockchainCannotBeCancelled: true; readonly reconcileBeforeCleanup: true };

export function disclosureFor(rollbackState: SealedPendingTransactionV2['rollbackState']): CancellationDisclosure {
  if (rollbackState === 'preSeal' || rollbackState === 'postSeal') {
    return { kind: 'preSubmit', safeToDestroyTransient: true };
  }
  return { kind: 'postSubmit', blockchainCannotBeCancelled: true, reconcileBeforeCleanup: true };
}

/** sha-256 hex via the canonical FEAT-001 primitive (imported above). */
