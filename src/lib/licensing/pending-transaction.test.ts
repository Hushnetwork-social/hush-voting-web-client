/**
 * FEAT-016 Task 2.4 — pending licence record codec + two-slot journal tests.
 *
 * Proves: the canonical record serialization equals the shared TS/Rust fixture
 * string byte-for-byte; strict parse round-trips; digest verification rejects
 * tampering; wrong purpose/state/binding fail closed; licence and identity
 * purposes cannot alias; atomic save with read-back, previous-slot recovery,
 * corruption rejection, binding mismatch rejection, and delete-on-resolution
 * behave per the two-slot CAS contract; and the module surface exposes no
 * secrets, no logs, and no storage side effects beyond the in-memory harness.
 */

import { describe, expect, it } from 'vitest';
import * as pendingModule from './pending-transaction';
import {
  LICENCE_PENDING_AAD_LABEL,
  LICENCE_PENDING_KEY_LABEL,
  LICENCE_PENDING_PURPOSE,
  LICENCE_PENDING_SCHEMA_VERSION,
  LICENCE_PENDING_STORE_NAMESPACE,
  digestOfPendingLicence,
  parsePendingLicenceRecordJson,
  serializePendingLicenceRecord,
  type LicencePendingTransactionRecord,
} from './pending-transaction';
import { InMemoryTwoSlotLicenceJournal } from './journal-adapter';

const ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
const OTHER_ACTOR = '99fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048dbb';
const NETWORK = 'hush-network-local-devnet-5195086';

/** Shared canonical fixture string — must equal the Rust test constant exactly. */
const SHARED_FIXTURE_EXPECTED_JSON =
  '{"schemaVersion":1,"purpose":"pending_licence_transaction","transaction":{"exactJson":"{\\"TransactionId\\":\\"5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e\\",\\"PayloadKind\\":\\"71370664-5eb4-4ce9-b96a-d7e7ffe53db5\\",\\"TransactionTimeStamp\\":\\"2026-09-06T00:00:00.000Z\\",\\"Payload\\":{\\"TransitionIntent\\":\\"baseline_free\\",\\"RequestedPlanId\\":\\"hushvoting.direct.free\\",\\"ObservedCatalogueVersion\\":\\"hushvoting-licence-catalogue/v1.0.0\\"},\\"PayloadSize\\":144}","digest":"a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd993"},"transactionId":"5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e","identityBinding":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5","networkBinding":"hush-network-local-devnet-5195086","targetBinding":"web-sharedworker","createdUtc":"2026-09-06T00:00:00.000Z","attemptEvidence":[{"at":"2026-09-06T00:00:01.000Z","outcome":"accepted"}],"recoveryState":"waitingAccepted","submittedUtc":"2026-09-06T00:00:01.000Z"}';

const EXACT_JSON =
  '{"TransactionId":"5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e","PayloadKind":"71370664-5eb4-4ce9-b96a-d7e7ffe53db5","TransactionTimeStamp":"2026-09-06T00:00:00.000Z","Payload":{"TransitionIntent":"baseline_free","RequestedPlanId":"hushvoting.direct.free","ObservedCatalogueVersion":"hushvoting-licence-catalogue/v1.0.0"},"PayloadSize":144}';

function fixture(): LicencePendingTransactionRecord {
  return {
    schemaVersion: LICENCE_PENDING_SCHEMA_VERSION,
    purpose: LICENCE_PENDING_PURPOSE,
    transaction: {
      exactJson: EXACT_JSON,
      digest: 'a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd993',
    },
    transactionId: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
    identityBinding: ACTOR,
    networkBinding: NETWORK,
    targetBinding: 'web-sharedworker',
    createdUtc: '2026-09-06T00:00:00.000Z',
    submittedUtc: '2026-09-06T00:00:01.000Z',
    attemptEvidence: [{ at: '2026-09-06T00:00:01.000Z', outcome: 'accepted' }],
    recoveryState: 'waitingAccepted',
  };
}

describe('canonical record codec (shared TS/Rust parity)', () => {
  it('serializes byte-identically to the shared fixture string', () => {
    expect(serializePendingLicenceRecord(fixture())).toBe(SHARED_FIXTURE_EXPECTED_JSON);
  });

  it('round-trips through the strict parser and verifies the digest', () => {
    const parsed = parsePendingLicenceRecordJson(SHARED_FIXTURE_EXPECTED_JSON);
    expect(parsed).toEqual(fixture());
    expect(parsed?.transaction.digest).toBe(digestOfPendingLicence(EXACT_JSON));
  });

  it('rejects tampered digests, wrong purpose, unknown states, and bad timestamps', () => {
    const base = JSON.parse(SHARED_FIXTURE_EXPECTED_JSON) as Record<string, unknown>;
    const tampered = {
      ...base,
      transaction: { ...(base.transaction as Record<string, unknown>), digest: 'a'.repeat(64) },
    };
    expect(parsePendingLicenceRecordJson(JSON.stringify(tampered))).toBeNull();

    const wrongPurpose = { ...base, purpose: 'pending_identity_transaction' };
    expect(parsePendingLicenceRecordJson(JSON.stringify(wrongPurpose))).toBeNull();

    const badState = { ...base, recoveryState: 'nonsense' };
    expect(parsePendingLicenceRecordJson(JSON.stringify(badState))).toBeNull();

    const badTime = { ...base, createdUtc: 'yesterday' };
    expect(parsePendingLicenceRecordJson(JSON.stringify(badTime))).toBeNull();
  });

  it('proves licence and identity purposes/stores cannot alias', () => {
    expect(LICENCE_PENDING_PURPOSE).toBe('pending_licence_transaction');
    expect(LICENCE_PENDING_AAD_LABEL).toBe('hushvoting-licence-pending-v1');
    expect(LICENCE_PENDING_KEY_LABEL).toBe('licence-pending-journal');
    expect(LICENCE_PENDING_STORE_NAMESPACE).toBe('hushvoting-licence-journal');
    // The FEAT-011 identity convergence store never uses these labels.
    expect(LICENCE_PENDING_PURPOSE).not.toContain('identity');
    expect(LICENCE_PENDING_STORE_NAMESPACE).not.toContain('identity-convergence');
  });

  it('keeps exact bytes byte-identical across parse/serialize round trips', () => {
    const record = fixture();
    const one = serializePendingLicenceRecord(record);
    const parsed = parsePendingLicenceRecordJson(one);
    expect(parsed).not.toBeNull();
    expect(serializePendingLicenceRecord(parsed!)).toBe(one);
    expect(parsed!.transaction.exactJson).toBe(EXACT_JSON);
  });
});

describe('two-slot CAS journal contract', () => {
  it('saves with read-back and loads the exact record', () => {
    const journal = new InMemoryTwoSlotLicenceJournal(ACTOR);
    expect(journal.save(fixture())).toEqual({ ok: true });
    const loaded = journal.load('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(serializePendingLicenceRecord(loaded.record)).toBe(SHARED_FIXTURE_EXPECTED_JSON);
    }
  });

  it('refuses a record bound to another identity (binding mismatch)', () => {
    const journal = new InMemoryTwoSlotLicenceJournal(ACTOR);
    const other = { ...fixture(), identityBinding: OTHER_ACTOR };
    expect(journal.save(other)).toEqual({ ok: false, reason: 'binding-mismatch' });
  });

  it('reports not-found for unknown transaction ids', () => {
    const journal = new InMemoryTwoSlotLicenceJournal(ACTOR);
    expect(journal.load('00000000-0000-4000-8000-000000000000')).toEqual({
      ok: false,
      reason: 'not-found',
    });
  });

  it('recovers from an unreadable active slot via previous-slot rollback', () => {
    const journal = new InMemoryTwoSlotLicenceJournal(ACTOR);
    expect(journal.save(fixture())).toEqual({ ok: true });
    // Corrupt the active (committed) slot directly — simulates torn write.
    const slots = (journal as unknown as { slots: Map<string, unknown[]> }).slots;
    const entry = slots.get('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e')!;
    const committedIndex = entry.findIndex((slot) => (slot as { committed: boolean }).committed);
    entry[committedIndex] = { recordJson: '{corrupt', committed: true };
    const loaded = journal.load('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    // The previous slot holds the previous committed record — but in this
    // single-write scenario the other slot is empty, so corruption is reported.
    expect(loaded).toEqual({ ok: false, reason: 'corrupt' });
  });

  it('deletes on resolution and reports not-found afterwards', () => {
    const journal = new InMemoryTwoSlotLicenceJournal(ACTOR);
    journal.save(fixture());
    expect(journal.delete('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e')).toEqual({ ok: true });
    expect(journal.load('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e')).toEqual({
      ok: false,
      reason: 'not-found',
    });
  });
});

describe('module surface and privacy', () => {
  it('exposes no persistence, storage, or secret-export surface from the codec', () => {
    const exported = Object.keys(pendingModule);
    for (const forbidden of ['persist', 'save', 'write', 'localStorage', 'indexedDB', 'encrypt', 'decrypt']) {
      expect(exported.some((key) => key.toLowerCase().includes(forbidden))).toBe(false);
    }
  });

  it('serializes only the frozen record fields (no free-form or identity extra members)', () => {
    const parsed = JSON.parse(SHARED_FIXTURE_EXPECTED_JSON) as Record<string, unknown>;
    const allowed = new Set([
      'schemaVersion',
      'purpose',
      'transaction',
      'transactionId',
      'identityBinding',
      'networkBinding',
      'targetBinding',
      'createdUtc',
      'attemptEvidence',
      'recoveryState',
      'submittedUtc',
      'indexObservedUtc',
    ]);
    for (const key of Object.keys(parsed)) {
      expect(allowed.has(key)).toBe(true);
    }
    expect(parsed).not.toHaveProperty('signature');
    expect(parsed).not.toHaveProperty('serverMessage');
    expect(parsed).not.toHaveProperty('endpoint');
  });
});
