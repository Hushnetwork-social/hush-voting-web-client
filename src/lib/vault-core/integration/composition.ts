/**
 * FEAT-003 vault integration — additive fail-closed composition (Task 6.3).
 *
 * The vault core contracts integrate into the UNCHANGED FEAT-002 production
 * composition through thin data-only registrations. While no production storage
 * adapter exists (FEAT-004/005/006 pending), every vault capability slot is
 * `unavailable` so the composition fails closed with explicit, safe diagnostics —
 * and no reference/conformance implementation can ever be selected as an actor.
 *
 * The Deep-Dive decision applies: FEAT-002 remains the sole UI/orchestration
 * authority and receives safe projections only; this module only declares which
 * capability slots the vault core backs and validates the fail-closed posture.
 * Synthetic-actor rejection itself is owned by the unchanged FEAT-002 registry
 * (`validateProductionRegistry`); this module's tests assert it end-to-end.
 *
 * Normative source: FEAT-003 FeatureDescription "Session Core", planning analysis
 * report §4 (FEAT-002 integration: additive core API with thin adapters).
 */
import type { CapabilityAvailability, CapabilityId } from '../../auth/types';

/** One vault-backed capability slot in the FEAT-002 registry vocabulary. */
export interface VaultCapabilitySlot {
  readonly capability: CapabilityId;
  readonly availability: CapabilityAvailability;
}

/**
 * Vault-backed capability slots. `localUserAuthority` and `secretAuthority` are the
 * storage and secret-container authorities the vault core contracts will back once a
 * production adapter (FEAT-004/005/006) registers. Today both are `unavailable`, so
 * production composition fails closed until an adapter contract is published.
 */
export const VAULT_CAPABILITY_SLOTS: readonly VaultCapabilitySlot[] = [
  { capability: 'localUserAuthority', availability: 'unavailable' },
  { capability: 'secretAuthority', availability: 'unavailable' },
] as const;

/** Deterministic fail-closed check over the declared vault slots. */
export type VaultCompositionDiagnostic =
  | { readonly code: 'AVAILABLE_WITHOUT_ADAPTER'; readonly capability: string }
  | { readonly code: 'UNDECLARED_VAULT_SLOT'; readonly capability: string }
  | { readonly code: 'DUPLICATE_SLOT'; readonly capability: string };

export interface VaultCompositionValidation {
  readonly ok: boolean;
  readonly diagnostics: readonly VaultCompositionDiagnostic[];
}

/**
 * Validate a registration list against the vault slot contract:
 * - every vault slot must be declared exactly once;
 * - no slot may claim availability other than `unavailable` until a production
 *   adapter contract is registered (fail closed; a reference/test implementation
 *   must never satisfy a vault slot).
 */
export function validateVaultCapabilitySlots(
  slots: readonly VaultCapabilitySlot[],
): VaultCompositionValidation {
  const diagnostics: VaultCompositionDiagnostic[] = [];
  const declared = new Map<string, VaultCapabilitySlot>();
  for (const slot of slots) {
    if (declared.has(slot.capability)) {
      diagnostics.push({ code: 'DUPLICATE_SLOT', capability: slot.capability });
      continue;
    }
    declared.set(slot.capability, slot);
  }
  for (const required of VAULT_CAPABILITY_SLOTS) {
    const slot = declared.get(required.capability);
    if (!slot) {
      diagnostics.push({ code: 'UNDECLARED_VAULT_SLOT', capability: required.capability });
      continue;
    }
    if (slot.availability !== 'unavailable') {
      // No production adapter contract exists yet; anything else is a defect.
      diagnostics.push({ code: 'AVAILABLE_WITHOUT_ADAPTER', capability: required.capability });
    }
  }
  return { ok: diagnostics.length === 0, diagnostics };
}
