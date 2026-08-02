/**
 * FEAT-003 integration tests — FEAT-001 pin admission + FEAT-002 fail-closed
 * composition (Task 6.4).
 *
 * Proves the additive core boundary:
 * - pinned FEAT-001 bundles are admitted only with exact revision/digest/contract
 *   and evidence; any mismatch rejects the COMPLETE bundle atomically;
 * - admission outcomes are closed typed data and never echo credentials;
 * - vault capability slots fail closed while no production adapter is registered;
 * - the unchanged FEAT-002 production composition rejects vault slots (missing
 *   mandatory, unavailable) and synthetic registrations — reference/test actors
 *   are unreachable.
 */
import { describe, expect, it } from 'vitest';
import { createProductionComposition } from '../../auth/composition';
import { registerCapability } from '../../auth/registry';
import { VAULT_CAPABILITY_SLOTS, validateVaultCapabilitySlots } from './composition';
import { admitBundleAtBoundary, FEAT_001_PIN } from './admission';
import type { BundleAdmissionEvidence, ValidatedCredentialBundle } from '../contracts/ports';

function bundle(overrides: Partial<ValidatedCredentialBundle> = {}): ValidatedCredentialBundle {
  return {
    __bundle: Symbol('test-bundle') as ValidatedCredentialBundle['__bundle'],
    producerId: 'hush-voting-ts',
    producerVersion: '1.0.0',
    featiContractVersion: '1.0.0',
    ...overrides,
  };
}

function evidence(overrides: Partial<BundleAdmissionEvidence> = {}): BundleAdmissionEvidence {
  return {
    producerId: 'hush-voting-ts',
    producerVersion: '1.0.0',
    exactKeyConsistency: true,
    mnemonicConsistency: 'none',
    signingAddressPrefix: '01234567',
    signingAddressSuffix: '89abcd',
    lifecycleStatus: 'PendingRegistration',
    ...overrides,
  };
}

describe('FEAT-003 ↔ FEAT-001 validated-bundle admission boundary', () => {
  it('admits a bundle with the exact recorded FEAT-001 pin and consistent evidence', () => {
    const result = admitBundleAtBoundary(bundle(), evidence());
    expect(result).toEqual({ ok: true });
  });

  it('rejects an unsupported FEAT-001 contract version without echoing credentials', () => {
    const result = admitBundleAtBoundary(bundle({ featiContractVersion: '2.0.0' as never }), evidence());
    expect(result).toEqual({ ok: false, code: 'UNSUPPORTED_CONTRACT' });
  });

  it('rejects a producer/version mismatch (UNSUPPORTED_PRODUCER)', () => {
    const result = admitBundleAtBoundary(bundle({ producerId: 'other-producer' }), evidence());
    expect(result).toEqual({ ok: false, code: 'UNSUPPORTED_PRODUCER' });
  });

  it('rejects evidence without exact key consistency atomically', () => {
    const result = admitBundleAtBoundary(bundle(), evidence({ exactKeyConsistency: false }));
    expect(result).toEqual({ ok: false, code: 'KEY_CONSISTENCY_FAILED' });
  });

  it('rejects a structurally invalid pin (PIN_MISMATCH)', () => {
    const result = admitBundleAtBoundary(
      bundle(),
      evidence(),
      { revision: 'not-a-revision', manifestSha256: '0'.repeat(64), contractVersion: '1.0.0' },
    );
    expect(result).toEqual({ ok: false, code: 'PIN_MISMATCH' });
  });

  it('outcomes contain only closed codes — no free-form credential content', () => {
    const outcomes = [
      admitBundleAtBoundary(bundle(), evidence()),
      admitBundleAtBoundary(bundle({ producerId: 'x' }), evidence()),
      admitBundleAtBoundary(bundle(), evidence({ exactKeyConsistency: false })),
      admitBundleAtBoundary(bundle(), evidence(), { revision: 'bad', manifestSha256: 'bad', contractVersion: '1.0.0' }),
    ];
    for (const o of outcomes) {
      expect(Object.keys(o).sort()).toEqual(['ok', ...(o.ok ? [] : ['code'])].sort());
      if (!o.ok) expect(typeof o.code).toBe('string');
    }
  });

  it('the recorded pin matches the immutable FEAT-001 pin constants', () => {
    expect(FEAT_001_PIN.revision).toMatch(/^[0-9a-f]{40}$/);
    expect(FEAT_001_PIN.manifestSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(FEAT_001_PIN.contractVersion).toBe('1.0.0');
  });
});

describe('FEAT-003 ↔ FEAT-002 fail-closed composition boundary', () => {
  it('vault capability slots validate as declared and all unavailable', () => {
    const validation = validateVaultCapabilitySlots(VAULT_CAPABILITY_SLOTS);
    expect(validation.ok).toBe(true);
    expect(validation.diagnostics).toHaveLength(0);
    expect(VAULT_CAPABILITY_SLOTS.every((s) => s.availability === 'unavailable')).toBe(true);
  });

  it('an undeclared vault slot is a defect', () => {
    const validation = validateVaultCapabilitySlots([]);
    expect(validation.ok).toBe(false);
    expect(validation.diagnostics.map((d) => d.code)).toContain('UNDECLARED_VAULT_SLOT');
  });

  it('a duplicate vault slot declaration is a defect', () => {
    const validation = validateVaultCapabilitySlots([...VAULT_CAPABILITY_SLOTS, VAULT_CAPABILITY_SLOTS[0]]);
    expect(validation.ok).toBe(false);
    expect(validation.diagnostics.map((d) => d.code)).toContain('DUPLICATE_SLOT');
  });

  it('an available vault slot without a production adapter is a defect', () => {
    const validation = validateVaultCapabilitySlots([
      { capability: 'localUserAuthority', availability: 'mandatory' },
      { capability: 'secretAuthority', availability: 'unavailable' },
    ]);
    expect(validation.ok).toBe(false);
    expect(validation.diagnostics).toContainEqual({ code: 'AVAILABLE_WITHOUT_ADAPTER', capability: 'localUserAuthority' });
  });

  it('FEAT-002 production composition fails closed with explicit vault diagnostics (no adapter)', () => {
    const registrations = VAULT_CAPABILITY_SLOTS.map((slot) => registerCapability(slot.capability, slot.availability));
    const composition = createProductionComposition(registrations, () => null);
    expect(composition.ok).toBe(false);
    // Unavailable vault slots cannot satisfy mandatory capabilities: the machine
    // stays blocked until a production adapter registers.
    const codes = composition.diagnostics.map((d) => d.code);
    expect(codes).toContain('MISSING_MANDATORY');
    // No diagnostic carries free-form content.
    for (const d of composition.diagnostics) {
      expect(typeof d.code).toBe('string');
      expect(typeof d.capability).toBe('string');
    }
  });

  it('synthetic vault registrations are rejected by the unchanged FEAT-002 registry', () => {
    const registrations = VAULT_CAPABILITY_SLOTS.map((slot) => registerCapability(slot.capability, slot.availability, true));
    const composition = createProductionComposition(registrations, () => null);
    expect(composition.ok).toBe(false);
    expect(composition.diagnostics.map((d) => d.code)).toContain('SYNTHETIC_IN_PRODUCTION');
  });

  it('the app production composition never resolves a vault actor to a reference implementation', () => {
    // The production actor provider is `() => null` (AuthRoot): no reference or
    // conformance module can be selected. The import-graph scan independently
    // proves vault-core/conformance is unreachable from production source.
    const registrations = VAULT_CAPABILITY_SLOTS.map((slot) => registerCapability(slot.capability, slot.availability));
    const composition = createProductionComposition(registrations, () => null);
    expect(composition.actors.localUserAuthority).toBeNull();
    expect(composition.actors.secretAuthority).toBeNull();
  });
});
