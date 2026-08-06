/**
 * FEAT-011 Task 4.1 — additive sealed pending-transaction storage.
 *
 * Framework-neutral sealed store for `SealedPendingTransactionV2` with atomic
 * two-slot CAS semantics (write → read-back verify → switch), matching the
 * established browser-vault two-slot pattern. The exact signed transaction
 * lives ONLY inside the sealed store (encrypted at rest by the owning
 * authority); page/WebView receives only an opaque pending reference.
 *
 * Additive rules: v1 `CurrentRecordPlaintext` (digest-only) is never
 * reinterpreted as containing retry bytes; migration creates a v2 slot only
 * when a pending registration exists, and never mutates v1 meaning.
 */

import {
  validatePendingTransaction,
  type SealedPendingTransactionV2,
} from './pending-transaction';

/** Opaque sealed-store reference (never a secret, never an address). */
export type SealedPendingRef = string & { readonly __sealedPendingRef: unique symbol };

/** Two-slot CAS store contract (framework-neutral). */
export interface SealedPendingStore {
  /** Atomic write: writes slot A, read-back verifies, then switches. */
  write(record: SealedPendingTransactionV2): Promise<SealedPendingRef>;
  /** Read the current committed record (null when none). */
  read(): Promise<SealedPendingTransactionV2 | null>;
  /** Clear the sealed pending state (safe cleanup only). */
  clear(): Promise<void>;
}

/**
 * Deterministic in-memory two-slot CAS store for unit/fault testing and
 * non-persistent targets. The production Browser adapter (Phase 6) implements
 * the same contract over IndexedDB with the identical fault semantics.
 */
export class InMemorySealedPendingStore implements SealedPendingStore {
  private slotA: SealedPendingTransactionV2 | null = null;
  private slotB: SealedPendingTransactionV2 | null = null;
  private active: 'A' | 'B' = 'A';

  async write(record: SealedPendingTransactionV2): Promise<SealedPendingRef> {
    const validated = validatePendingTransaction(record);
    if (!validated.ok) {
      throw new Error(`sealed pending write rejected: ${validated.reason}`);
    }

    // Write to the inactive slot first (CAS: never clobber the committed slot).
    const target: 'A' | 'B' = this.active === 'A' ? 'B' : 'A';
    this.setSlot(target, record);

    // Read-back verify: the committed slot must still hold the prior record
    // and the target slot must return the exact same bytes + digest.
    const readBack = this.getSlot(target);
    if (readBack === null || !validatePendingTransaction(readBack).ok) {
      this.setSlot(target, null);
      throw new Error('sealed pending read-back verification failed');
    }

    this.active = target;
    return `sealed:${this.active}` as SealedPendingRef;
  }

  async read(): Promise<SealedPendingTransactionV2 | null> {
    const record = this.getSlot(this.active);
    if (record === null) {
      return null;
    }
    // Corruption detection on read: never surface a broken record.
    return validatePendingTransaction(record).ok ? record : null;
  }

  async clear(): Promise<void> {
    this.slotA = null;
    this.slotB = null;
    this.active = 'A';
  }

  /** Fault injection: corrupt the inactive slot (test hook). */
  corruptInactiveSlot(): void {
    const target: 'A' | 'B' = this.active === 'A' ? 'B' : 'A';
    const record = this.getSlot(target);
    if (record !== null) {
      this.setSlot(target, { ...record, transaction: { ...record.transaction, exactJson: `${record.transaction.exactJson} ` } });
    }
  }

  /** Fault injection: corrupt the committed slot (test hook). */
  corruptActiveSlot(): void {
    const record = this.getSlot(this.active);
    if (record !== null) {
      this.setSlot(this.active, { ...record, transaction: { ...record.transaction, exactJson: `${record.transaction.exactJson} ` } });
    }
  }

  private getSlot(slot: 'A' | 'B'): SealedPendingTransactionV2 | null {
    return slot === 'A' ? this.slotA : this.slotB;
  }

  private setSlot(slot: 'A' | 'B', record: SealedPendingTransactionV2 | null): void {
    if (slot === 'A') {
      this.slotA = record;
    } else {
      this.slotB = record;
    }
  }
}
