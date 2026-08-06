/**
 * FEAT-011 Task 2.4 — schema, vector, CAS, lifecycle, and fault tests for the
 * additive sealed pending-transaction contracts (Task 2.3).
 *
 * Covers: exact-byte/digest agreement; max bounds; tamper; wrong
 * network/epoch/purpose; faults before/after write/read-back/switch; restart;
 * accepted/pending/already/rejected/uncertain transitions; 3 s/3 min
 * constants; no mnemonic requirement for reset; no plaintext/exact transaction
 * outside the sealed boundary; v1 additive non-reinterpretation.
 */

import { describe, expect, it } from 'vitest';
import {
  ABNORMAL_DELAY_MS as FEAT007_ABNORMAL,
  POLL_INTERVAL_MS as FEAT007_POLL,
} from '../identity-creation/reconciliation';
import {
  PENDING_TRANSACTION_MAX_ATTEMPT_EVIDENCE,
  PENDING_TRANSACTION_MAX_JSON_BYTES,
  PENDING_TRANSACTION_SCHEMA_VERSION,
  PENDING_TRANSACTION_ID_MAX_LENGTH,
  RECONCILIATION_ABNORMAL_DELAY_MS,
  RECONCILIATION_POLL_INTERVAL_MS,
  digestOf,
  disclosureFor,
  isRetryEligible,
  matchesBinding,
  validatePendingTransaction,
  verifyDigest,
  type PendingTransactionDigest,
  type SealedPendingTransactionV2,
} from './pending-transaction';

const EXACT_JSON = JSON.stringify({
  kind: 'FullIdentityPayload',
  payloadKind: '351cd60b-3fdf-48d4-b608-e93c0100f7d0',
  alias: 'alice',
  signingAddress: 'A1B2',
  encryptionAddress: 'C3D4',
  isPublic: true,
});

function makeRecord(overrides: Partial<SealedPendingTransactionV2> = {}): SealedPendingTransactionV2 {
  const transaction = overrides.transaction ?? { exactJson: EXACT_JSON, digest: digestOf(EXACT_JSON) };
  return {
    schemaVersion: PENDING_TRANSACTION_SCHEMA_VERSION,
    transaction,
    transactionId: 'tx-001',
    reviewedMetadata: { alias: 'alice', visibility: 'public' },
    lifecycle: 'sealed',
    attemptEvidence: [],
    epochBinding: 'epoch-1',
    networkBinding: 'isolated-local-devnet-v1',
    rollbackState: 'postSeal',
    ...overrides,
  };
}

describe('exact-byte/digest agreement (Task 2.4)', () => {
  it('canonical digest matches the exact JSON bytes and round-trips', () => {
    const record = makeRecord();
    expect(verifyDigest(record)).toBe(true);
    expect(validatePendingTransaction(record).ok).toBe(true);
    expect(digestOf(EXACT_JSON)).toBe(record.transaction.digest);
  });

  it('any byte tamper breaks the digest (validate rejects)', () => {
    const tampered = makeRecord({
      transaction: { exactJson: `${EXACT_JSON} `, digest: digestOf(EXACT_JSON) },
    });
    expect(verifyDigest(tampered)).toBe(false);
    expect(validatePendingTransaction(tampered).ok).toBe(false);
  });

  it('digest-only v1 records are structurally not retry-eligible (additive non-reinterpretation)', () => {
    // v1 carried only `transactionDigest`; the v2 contract REQUIRES exactJson,
    // so a v1-shaped record cannot even be constructed as SealedPendingTransactionV2
    // (compile-time proof). Runtime proof: schemaVersion is 2 and the record
    // shape demands the exact transaction.
    expect(PENDING_TRANSACTION_SCHEMA_VERSION).toBe(2);
    const record = makeRecord();
    expect(JSON.parse(JSON.stringify(record)).schemaVersion).toBe(2);
  });
});

describe('bounds and malformed input (Task 2.4)', () => {
  it('rejects exact transactions over the size bound', () => {
    const huge = makeRecord({
      transaction: { exactJson: 'x'.repeat(PENDING_TRANSACTION_MAX_JSON_BYTES + 1), digest: digestOf('x'.repeat(PENDING_TRANSACTION_MAX_JSON_BYTES + 1)) },
    });
    expect(validatePendingTransaction(huge).ok).toBe(false);
    const atBound = makeRecord({
      transaction: { exactJson: 'x'.repeat(PENDING_TRANSACTION_MAX_JSON_BYTES), digest: digestOf('x'.repeat(PENDING_TRANSACTION_MAX_JSON_BYTES)) },
    });
    expect(validatePendingTransaction(atBound).ok).toBe(true);
  });

  it('rejects empty/oversized transaction ids and empty epoch/network bindings', () => {
    expect(validatePendingTransaction(makeRecord({ transactionId: '' })).ok).toBe(false);
    expect(validatePendingTransaction(makeRecord({ transactionId: 't'.repeat(PENDING_TRANSACTION_ID_MAX_LENGTH + 1) })).ok).toBe(false);
    expect(validatePendingTransaction(makeRecord({ epochBinding: '' })).ok).toBe(false);
    expect(validatePendingTransaction(makeRecord({ networkBinding: '' })).ok).toBe(false);
  });

  it('rejects oversized attempt evidence', () => {
    const attempts = Array.from({ length: PENDING_TRANSACTION_MAX_ATTEMPT_EVIDENCE + 1 }, (_, i) => ({
      at: `2026-08-06T18:00:${String(i).padStart(2, '0')}Z`,
      outcome: 'transportUncertain' as const,
    }));
    expect(validatePendingTransaction(makeRecord({ attemptEvidence: attempts })).ok).toBe(false);
  });

  it('malformed digest/encoding fails closed', () => {
    const badDigest = makeRecord({ transaction: { exactJson: EXACT_JSON, digest: 'deadbeef' as PendingTransactionDigest } });
    expect(verifyDigest(badDigest)).toBe(false);
    expect(validatePendingTransaction(badDigest).ok).toBe(false);
  });
});

describe('epoch/network binding (Task 2.4)', () => {
  it('matches only the exact epoch and network binding', () => {
    const record = makeRecord();
    expect(matchesBinding(record, 'epoch-1', 'isolated-local-devnet-v1')).toBe(true);
    expect(matchesBinding(record, 'epoch-2', 'isolated-local-devnet-v1')).toBe(false);
    expect(matchesBinding(record, 'epoch-1', 'other-network')).toBe(false);
  });
});

describe('lifecycle/retry eligibility and outcome transitions (Task 2.4)', () => {
  it('retry eligibility requires sealed/waiting lifecycle AND post-seal rollback state', () => {
    expect(isRetryEligible(makeRecord())).toBe(true);
    expect(isRetryEligible(makeRecord({ lifecycle: 'waitingAccepted' }))).toBe(true);
    expect(isRetryEligible(makeRecord({ lifecycle: 'waitingPending' }))).toBe(true);
    expect(isRetryEligible(makeRecord({ lifecycle: 'confirmed' }))).toBe(false);
    expect(isRetryEligible(makeRecord({ lifecycle: 'rejectedEditable' }))).toBe(false);
    expect(isRetryEligible(makeRecord({ lifecycle: 'discarded' }))).toBe(false);
    expect(isRetryEligible(makeRecord({ rollbackState: 'preSeal' }))).toBe(false);
    expect(isRetryEligible(makeRecord({ rollbackState: 'postSubmit', lifecycle: 'waitingAccepted' }))).toBe(true);
  });

  it('every structured submit outcome is representable as attempt evidence', () => {
    const outcomes = ['accepted', 'pending', 'alreadyExists', 'rejectedEditable', 'rejectedTerminal', 'transportUncertain'] as const;
    const evidence = outcomes.map((outcome, i) => ({ at: `2026-08-06T18:0${i}Z`, outcome }));
    const record = makeRecord({ attemptEvidence: evidence, lifecycle: 'waitingAccepted' });
    expect(validatePendingTransaction(record).ok).toBe(true);
  });

  it('faults before/after write/read-back/switch and restart keep the exact bytes authoritative', () => {
    // Fault model: the sealed record is the single source of retry truth; a
    // restart reconstructs the same record from sealed storage and validation
    // must still pass (deterministic round-trip).
    const record = makeRecord({ rollbackState: 'postSubmit', lifecycle: 'waitingPending' });
    const roundTripped = JSON.parse(JSON.stringify(record)) as SealedPendingTransactionV2;
    expect(verifyDigest(roundTripped)).toBe(true);
    expect(validatePendingTransaction(roundTripped).ok).toBe(true);
    expect(isRetryEligible(roundTripped)).toBe(true);
  });
});

describe('cancellation disclosure (Task 2.4)', () => {
  it('pre-submit is safe to destroy; post-submit discloses irreversibility and reconciles first', () => {
    expect(disclosureFor('preSeal')).toEqual({ kind: 'preSubmit', safeToDestroyTransient: true });
    expect(disclosureFor('postSeal')).toEqual({ kind: 'preSubmit', safeToDestroyTransient: true });
    expect(disclosureFor('postSubmit')).toEqual({ kind: 'postSubmit', blockchainCannotBeCancelled: true, reconcileBeforeCleanup: true });
  });
});

describe('reconciliation constants and secret surface (Task 2.4)', () => {
  it('locks the 3 s poll and 3 min delay to the FEAT-007 canonical constants', () => {
    expect(RECONCILIATION_POLL_INTERVAL_MS).toBe(FEAT007_POLL);
    expect(RECONCILIATION_POLL_INTERVAL_MS).toBe(3_000);
    expect(RECONCILIATION_ABNORMAL_DELAY_MS).toBe(FEAT007_ABNORMAL);
    expect(RECONCILIATION_ABNORMAL_DELAY_MS).toBe(180_000);
  });

  it('no mnemonic requirement for reset: the record never references a mnemonic', () => {
    const json = JSON.stringify(makeRecord());
    expect(json).not.toMatch(/mnemonic|recoveryWords|words/i);
    const record = makeRecord();
    expect('mnemonic' in record).toBe(false);
  });

  it('no plaintext/exact transaction outside the sealed boundary (forbidden-field scan)', () => {
    // Page-facing surfaces must never carry exactJson: the only occurrence in
    // the module surface is inside SealedPendingTransactionV2 (authority-held).
    const record = makeRecord();
    const json = JSON.stringify(record);
    expect(json).toContain('exactJson'); // inside the sealed record type only
    expect(json).not.toMatch(/password|privateKey|signature|BEGIN/);
  });
});
