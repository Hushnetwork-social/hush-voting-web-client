/**
 * FEAT-016 Task 2.3/2.4 — two-slot CAS licence journal contract adapter.
 *
 * Validating in-memory two-slot journal proving the storage semantics shared
 * by browser and native authorities: atomic write with read-back, previous
 * slot recovery, corruption rejection, binding mismatch rejection, and
 * delete-on-resolution. This adapter is deliberately storage-free (no
 * encryption, no IndexedDB/native files): it is the pure contract harness.
 * Phase 6 binds the same discipline to the approved encrypted browser sealed
 * store and native vault journals.
 *
 * SECRET BOUNDARY: records passed to this adapter may contain exact signed
 * bytes; real deployments must only ever call the encrypted adapters. This
 * in-memory harness is for contract tests only.
 *
 * Normative source: FEAT-016 FeatureDescription "Licence Transaction and
 * Pending Journal" (seal-before-submit, exact retry, unrecoverable-corruption
 * rules); FEAT-011 two-slot sealed-pending-store discipline.
 */

import {
  LICENCE_PENDING_STORE_NAMESPACE,
  parsePendingLicenceRecordJson,
  serializePendingLicenceRecord,
  type LicencePendingTransactionRecord,
} from './pending-transaction';

export type LicenceJournalSaveResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: 'storage-unavailable' | 'binding-mismatch' | 'corrupt' };

export type LicenceJournalDeleteResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: 'storage-unavailable' };

interface SlotState {
  readonly recordJson: string;
  readonly committed: boolean;
}

/**
 * Two-slot CAS journal keyed by transaction id. `identityBinding` is fixed at
 * construction: records bound to another identity are refused (mismatch).
 */
export class InMemoryTwoSlotLicenceJournal {
  public readonly namespace = LICENCE_PENDING_STORE_NAMESPACE;
  private readonly slots = new Map<string, [SlotState, SlotState]>();

  constructor(private readonly identityBinding: string) {}

  /** Save (or overwrite) one record using atomic two-slot CAS with read-back. */
  save(record: LicencePendingTransactionRecord): LicenceJournalSaveResult {
    if (record.identityBinding !== this.identityBinding) {
      return { ok: false, reason: 'binding-mismatch' };
    }
    const slots = this.slots.get(record.transactionId) ?? [
      { recordJson: '', committed: false },
      { recordJson: '', committed: false },
    ];
    const nextJson = serializePendingLicenceRecord(record);
    // Find the inactive slot (never clobber the committed slot mid-write).
    const targetIndex = slots[0].committed ? 1 : 0;
    const previousJson = slots[targetIndex].recordJson;
    slots[targetIndex] = { recordJson: nextJson, committed: false };
    // Read-back verification: the slot must return exactly the written bytes.
    if (slots[targetIndex].recordJson !== nextJson) {
      slots[targetIndex] = { recordJson: previousJson, committed: false };
      return { ok: false, reason: 'corrupt' };
    }
    const parsed = parsePendingLicenceRecordJson(nextJson);
    if (parsed === null) {
      slots[targetIndex] = { recordJson: previousJson, committed: false };
      return { ok: false, reason: 'corrupt' };
    }
    // Commit flip is atomic per key (single-threaded authority contract).
    slots[targetIndex] = { recordJson: nextJson, committed: true };
    this.slots.set(record.transactionId, slots);
    return { ok: true };
  }

  /** Load the committed record; corruption rolls back to the other slot. */
  load(transactionId: string): { ok: true; record: LicencePendingTransactionRecord } | { ok: false; reason: 'not-found' | 'corrupt' | 'binding-mismatch' } {
    const slots = this.slots.get(transactionId);
    if (!slots) {
      return { ok: false, reason: 'not-found' };
    }
    const committed = slots.find((slot) => slot.committed);
    if (committed && committed.recordJson.length > 0) {
      const parsed = parsePendingLicenceRecordJson(committed.recordJson);
      if (parsed !== null) {
        if (parsed.identityBinding !== this.identityBinding) {
          return { ok: false, reason: 'binding-mismatch' };
        }
        return { ok: true, record: parsed };
      }
    }
    // Active slot corrupt/unreadable: try previous-slot rollback.
    const other = slots.find((slot) => !slot.committed && slot.recordJson.length > 0);
    if (other) {
      const parsed = parsePendingLicenceRecordJson(other.recordJson);
      if (parsed !== null) {
        if (parsed.identityBinding !== this.identityBinding) {
          return { ok: false, reason: 'binding-mismatch' };
        }
        return { ok: true, record: parsed };
      }
    }
    return { ok: false, reason: 'corrupt' };
  }

  /** Delete all slots for a transaction (indexed/terminal resolution). */
  delete(transactionId: string): LicenceJournalDeleteResult {
    this.slots.delete(transactionId);
    return { ok: true };
  }
}
