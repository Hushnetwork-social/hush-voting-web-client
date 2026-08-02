/**
 * FEAT-003 vault-core lifecycle — deterministic two-slot atomic journal.
 *
 * Maintain at most one active encrypted slot, one rollback encrypted slot, and a
 * non-secret active-pointer/journal sidecar. A mutation:
 *   1. reads the expected active generation;
 *   2. constructs a complete new slot;
 *   3. writes it to the inactive position;
 *   4. reads back and verifies schema, canonical bytes, ciphertext authentication,
 *      and required invariants;
 *   5. atomically switches the active pointer/generation;
 *   6. retains the previous verified slot only for bounded rollback cleanup.
 *
 * The shared authority is the only writer. Every mutation declares an expected active
 * generation; a generation mismatch returns a typed conflict and reloads authoritative
 * state. Last-write-wins and arbitrary JSON merges are forbidden. Lock can preempt a
 * mutation by invalidating its epoch before the pointer switch.
 *
 * Complete rollback of all browser storage cannot be detected without an external
 * trusted monotonic counter — a recorded residual risk.
 *
 * This is a deterministic REFERENCE model: storage/verification primitives are injected
 * so fault injection can exercise every write/verify/switch/cleanup step.
 *
 * Normative source: FEAT-003 FeatureDescription "Atomic Storage and Lifecycle".
 */

/** One encrypted slot (opaque bytes at this layer). */
export interface Slot {
  readonly generation: number;
  readonly bytes: Uint8Array;
}

/** Deterministic journal state. */
export interface JournalState {
  readonly activeSlot: Slot | null;
  readonly rollbackSlot: Slot | null;
  readonly activeGeneration: number;
  /** True once the next successful startup verified the new slot (obsolete-slot cleanup). */
  readonly newSlotVerified: boolean;
}

/** Typed journal outcomes. */
export type JournalOutcome =
  | { readonly ok: true; readonly state: JournalState }
  | { readonly ok: false; readonly code: 'NO_ACTIVE_SLOT' | 'GENERATION_CONFLICT' | 'WRITE_FAILED' | 'VERIFY_FAILED' | 'SWITCH_FAILED'; readonly state: JournalState };

export interface JournalPorts {
  /** Write the inactive position (may be injected to fail). */
  readonly writeInactive: (slot: Slot) => boolean;
  /** Read-back verification of the inactive slot (may be injected to fail). */
  readonly verifyInactive: (slot: Slot) => boolean;
  /** Atomic active-pointer switch (may be injected to fail before commit). */
  readonly switchActive: (newGeneration: number) => boolean;
}

/**
 * Commit a newly constructed slot with an expected generation. Deterministic under
 * fault injection at every step: on failure the state retains the last verified slots.
 */
export function journalCommit(
  state: JournalState,
  expectedGeneration: number,
  newSlot: Slot,
  ports: JournalPorts,
): JournalOutcome {
  if (state.activeSlot === null) {
    // First provisioning: no generation constraint.
    if (!ports.writeInactive(newSlot)) return { ok: false, code: 'WRITE_FAILED', state };
    if (!ports.verifyInactive(newSlot)) return { ok: false, code: 'VERIFY_FAILED', state };
    if (!ports.switchActive(newSlot.generation)) return { ok: false, code: 'SWITCH_FAILED', state };
    return {
      ok: true,
      state: { activeSlot: newSlot, rollbackSlot: null, activeGeneration: newSlot.generation, newSlotVerified: true },
    };
  }
  if (state.activeGeneration !== expectedGeneration) {
    return { ok: false, code: 'GENERATION_CONFLICT', state };
  }
  if (newSlot.generation <= state.activeGeneration) {
    return { ok: false, code: 'GENERATION_CONFLICT', state };
  }
  if (!ports.writeInactive(newSlot)) return { ok: false, code: 'WRITE_FAILED', state };
  if (!ports.verifyInactive(newSlot)) return { ok: false, code: 'VERIFY_FAILED', state };
  if (!ports.switchActive(newSlot.generation)) return { ok: false, code: 'SWITCH_FAILED', state };
  // Atomic switch succeeded: the previous active becomes the rollback slot.
  // Rollback is retained until the NEXT successful startup/unlock verifies the new
  // slot (obsolete-slot cleanup rule); `newSlotVerified` starts false after commit.
  return {
    ok: true,
    state: {
      activeSlot: newSlot,
      rollbackSlot: state.activeSlot,
      activeGeneration: newSlot.generation,
      newSlotVerified: false,
    },
  };
}

/**
 * Mark the new slot verified on the next successful startup/unlock. This is the
 * event that authorizes obsolete-rollback cleanup (or the 24-hour fallback).
 */
export function verifyNewSlotOnStartup(state: JournalState): JournalState {
  return { ...state, newSlotVerified: true };
}

/**
 * Obsolete-slot cleanup: remove the rollback slot immediately after the next
 * successful startup/unlock verifies the new slot, or on the first application
 * execution after 24 hours — whichever the application observes first.
 */
export function cleanupObsoleteSlot(
  state: JournalState,
  nowMs: number,
  lastStartupMs: number,
): JournalState {
  if (state.rollbackSlot === null) return state;
  const ageMs = nowMs - lastStartupMs;
  if (state.newSlotVerified || ageMs >= 24 * 60 * 60 * 1000) {
    return { ...state, rollbackSlot: null };
  }
  return state;
}
