/**
 * FEAT-016 Task 2.2 — safe-projection builder tests.
 *
 * Proves only a compatible active indexed transport view becomes a safe
 * projection; unknown families, incompatible catalogue versions, missing or
 * malformed fields, unbounded values, and non-record options fail closed;
 * identity/network bindings are carried; and the public serialization shape
 * excludes credentials, signatures, bytes, endpoints, and storage keys.
 */

import { describe, expect, it } from 'vitest';
import type { LicenceActiveEntitlementTransportView } from './contracts';
import * as projectionModule from './projection';
import { buildLicenceSafeProjection, projectionPublicShape } from './projection';

const ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
const NETWORK = 'hush-network-local-devnet-5195086';
const CATALOGUE_V1 = 'hushvoting-licence-catalogue/v1.0.0';

function activeView(overrides: Partial<LicenceActiveEntitlementTransportView> = {}): LicenceActiveEntitlementTransportView {
  return {
    LicenceReference: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
    PlanId: 'hushvoting.veritas.2000',
    PlanFamily: 'veritas',
    DisplayName: 'HushVoting! Veritas 2k',
    SafeDescription: 'Annual Veritas licence',
    EligibleVoterCap: 2000,
    UnlimitedElections: true,
    TermKind: 'annual',
    TermYears: 1,
    EffectiveFromUtc: '2026-01-01T00:00:00.000Z',
    ExpiresAtUtc: '2027-01-01T00:00:00.000Z',
    AssignedCatalogueVersion: CATALOGUE_V1,
    AllowedGovernanceOptionIds: ['gov-trustees-7-of-10'],
    HigherOptions: [],
    ...overrides,
  };
}

function build(view: LicenceActiveEntitlementTransportView) {
  return buildLicenceSafeProjection(ACTOR as never, NETWORK as never, view);
}

describe('buildLicenceSafeProjection', () => {
  it('accepts a compatible active indexed view into a bounded safe projection', () => {
    const result = build(activeView());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.projection.kind).toBe('licence-safe-projection');
    expect(result.projection.identityBinding).toBe(ACTOR);
    expect(result.projection.networkBinding).toBe(NETWORK);
    expect(result.projection.licenceReference).toBe('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    expect(result.projection.planFamily).toBe('veritas');
    expect(result.projection.provenance).toBe('indexed-query');
    expect(result.projection.allowedGovernanceOptionIds).toEqual(['gov-trustees-7-of-10']);
  });

  it('accepts active direct-free and enterprise families without coercion', () => {
    for (const family of ['direct', 'enterprise'] as const) {
      const result = build(activeView({ PlanFamily: family }));
      expect(result.ok).toBe(true);
    }
  });

  it('rejects an unknown plan family as incompatible (never Direct Free)', () => {
    const result = build(activeView({ PlanFamily: 'mystery-2027' }));
    expect(result).toEqual({ ok: false, reason: 'unknown-plan-family' });
  });

  it('rejects an incompatible/future catalogue version', () => {
    const result = build(activeView({ AssignedCatalogueVersion: 'hushvoting-licence-catalogue/v2.0.0' }));
    expect(result).toEqual({ ok: false, reason: 'incompatible-catalogue-version' });
  });

  it('rejects malformed required fields (missing reference, bad timestamps)', () => {
    expect(build(activeView({ LicenceReference: '' }))).toEqual({
      ok: false,
      reason: 'malformed-required-field',
    });
    expect(build(activeView({ EffectiveFromUtc: 'not-a-date' }))).toEqual({
      ok: false,
      reason: 'malformed-required-field',
    });
    expect(build(activeView({ ExpiresAtUtc: '2027/01/01' }))).toEqual({
      ok: false,
      reason: 'malformed-required-field',
    });
  });

  it('rejects non-array option members and unbounded option counts', () => {
    const junk = activeView() as unknown as Record<string, unknown>;
    const nonArray = { ...junk, HigherOptions: 'nope', AllowedGovernanceOptionIds: 'nope' };
    expect(build(nonArray as never)).toEqual({ ok: false, reason: 'malformed-required-field' });

    const many = activeView({
      AllowedGovernanceOptionIds: Array.from({ length: 65 }, (_, i) => `gov-${i}`),
    });
    expect(build(many)).toEqual({ ok: false, reason: 'unbounded-value' });
  });

  it('rejects a malformed higher option record', () => {
    const view = activeView();
    const junk = { ...view, HigherOptions: ['not-a-record'] } as unknown as LicenceActiveEntitlementTransportView;
    expect(build(junk)).toEqual({ ok: false, reason: 'malformed-required-field' });
  });

  it('rejects non-record input (junk transport payload)', () => {
    expect(build(null as never)).toEqual({ ok: false, reason: 'missing-active-view' });
    expect(build('string' as never)).toEqual({ ok: false, reason: 'missing-active-view' });
  });
});

describe('projectionPublicShape (privacy boundary)', () => {
  it('contains only allowlisted fields — never credentials/bytes/keys/endpoints', () => {
    const result = build(activeView());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const serialized = JSON.stringify(projectionPublicShape(result.projection));
    for (const forbidden of [
      'signature',
      'password',
      'mnemonic',
      'privateKey',
      'transaction',
      'digest',
      'vaultHandle',
      'endpoint',
      'localStorage',
      'indexedDB',
      'serverMessage',
      'cacheProvenance',
      'identityBinding', // bindings stay machine-internal
      'networkBinding',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(JSON.parse(serialized)).not.toHaveProperty('identityBinding');
  });

  it('has no persistence adapter by construction (no storage exports)', () => {
    // The module only exports builder/shape helpers; nothing can write storage.
    const exported = Object.keys(projectionModule);
    expect(exported).not.toContain('persist');
    expect(exported).not.toContain('save');
    expect(exported).not.toContain('write');
  });
});
