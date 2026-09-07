/**
 * FEAT-016 Task 2.2 + FEAT-017 Task 2.2 — safe-projection builder tests.
 *
 * Proves only a compatible active indexed transport view becomes a safe
 * projection; unknown families, incompatible catalogue versions, missing or
 * malformed fields, unbounded values, and non-record options fail closed;
 * identity/network bindings are carried; the public serialization shape
 * excludes credentials, signatures, bytes, endpoints, and storage keys; and
 * the FEAT-017 safe-option boundary preserves server order and display facts
 * while omitting current/duplicate/Enterprise-disguised option entries and
 * never leaking raw template or exact-bytes material.
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

describe('FEAT-017 safe-option boundary (higher options, Enterprise, catalogue)', () => {
  function option(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
    return {
      PlanId: 'hushvoting.veritas.2000',
      DisplayName: 'HushVoting! Veritas 2k',
      SafeDescription: 'Up to 2,000 voters',
      EligibleVoterCap: 2000,
      UnlimitedElections: true,
      TermKind: 'annual',
      TermYears: 1,
      ...overrides,
    };
  }

  function viewWithOptions(
    higher: unknown[],
    extra: Partial<LicenceActiveEntitlementTransportView> = {},
  ): LicenceActiveEntitlementTransportView {
    return activeView({
      PlanId: 'hushvoting.direct.free',
      PlanFamily: 'direct',
      DisplayName: 'HushVoting! Direct Free',
      SafeDescription: 'A perpetual licence for admin-controlled elections.',
      EligibleVoterCap: 100,
      TermKind: 'perpetual',
      HigherOptions: higher as LicenceActiveEntitlementTransportView['HigherOptions'],
      ...extra,
    });
  }

  it('retains server-ordered higher options and Enterprise as safe display facts', () => {
    const result = build(
      viewWithOptions(
        [
          option({ PlanId: 'hushvoting.veritas.500', DisplayName: 'HushVoting! Veritas 500' }),
          option({ PlanId: 'hushvoting.veritas.2000', DisplayName: 'HushVoting! Veritas 2k' }),
          option({ PlanId: 'hushvoting.veritas.10000', DisplayName: 'HushVoting! Veritas 10k' }),
        ],
        {
          Enterprise: {
            PlanId: 'hushvoting.enterprise',
            DisplayName: 'HushVoting! Enterprise',
            SafeDescription: 'Contact provider — not yet available',
          },
        },
      ),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const p = result.projection;
    expect(p.safeDescription).toBe('A perpetual licence for admin-controlled elections.');
    expect(p.catalogueVersion).toBe(CATALOGUE_V1);
    expect(p.higherOptions.map((o) => o.planId)).toEqual([
      'hushvoting.veritas.500',
      'hushvoting.veritas.2000',
      'hushvoting.veritas.10000',
    ]);
    expect(p.higherOptions[1]).toEqual({
      planId: 'hushvoting.veritas.2000',
      displayName: 'HushVoting! Veritas 2k',
      safeDescription: 'Up to 2,000 voters',
      eligibleVoterCap: 2000,
      unlimitedElections: true,
      termKind: 'annual',
      termYears: 1,
    });
    expect(p.enterprise).toEqual({
      planId: 'hushvoting.enterprise',
      displayName: 'HushVoting! Enterprise',
      safeDescription: 'Contact provider — not yet available',
    });
    // Governance ids of the current licence remain presentation facts.
    expect(p.allowedGovernanceOptionIds).toEqual(['gov-trustees-7-of-10']);
  });



  it('omits current-plan, duplicate, and Enterprise-disguised option entries safely, preserving order', () => {
    const result = build(
      viewWithOptions(
        [
          option({ PlanId: 'hushvoting.direct.free', DisplayName: 'HushVoting! Direct Free' }), // current
          option({ PlanId: 'hushvoting.veritas.500' }),
          option({ PlanId: 'hushvoting.enterprise', DisplayName: 'HushVoting! Enterprise' }), // disguised
          option({ PlanId: 'hushvoting.veritas.500' }), // duplicate
          option({ PlanId: 'hushvoting.veritas.10000' }),
        ],
        {
          Enterprise: {
            PlanId: 'hushvoting.enterprise',
            DisplayName: 'HushVoting! Enterprise',
            SafeDescription: 'Contact provider — not yet available',
          },
        },
      ),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.projection.higherOptions.map((o) => o.planId)).toEqual([
      'hushvoting.veritas.500',
      'hushvoting.veritas.10000',
    ]);
  });

  it('preserves an empty (no-higher) option list and no Enterprise entry', () => {
    const result = build(viewWithOptions([]));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.projection.higherOptions).toEqual([]);
    expect(result.projection.enterprise).toBeNull();
  });

  it('accepts an active Enterprise or retired/historical current plan for display only', () => {
    for (const family of ['enterprise', 'veritas'] as const) {
      const planId =
        family === 'enterprise' ? 'hushvoting.enterprise' : 'hushvoting.veritas.500';
      const result = build(
        activeView({
          PlanId: planId,
          PlanFamily: family,
          DisplayName: 'HushVoting! Display',
          HigherOptions: [],
        }),
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.projection.planId).toBe(planId);
        // Never offered as a self-service option (options stay empty).
        expect(result.projection.higherOptions).toEqual([]);
      }
    }
  });

  it('fails closed when any option member is unbounded or malformed (never partial)', () => {
    const junkOptions = [
      option({ PlanId: '' }),
      option({ DisplayName: '' }),
      option({ SafeDescription: '' }),
      option({ SafeDescription: 'x'.repeat(600) }),
      option({ EligibleVoterCap: -1 }),
      option({ EligibleVoterCap: Number.MAX_SAFE_INTEGER + 2 }),
      option({ EligibleVoterCap: '2000' }),
      option({ UnlimitedElections: 'yes' }),
      option({ TermYears: -1 }),
      option({ TermYears: 1.5 }),
      option({ TermKind: 42 }),
      { PlanId: 'hushvoting.veritas.500' }, // missing display/description
      'hushvoting.veritas.500',
      null,
      42,
    ];
    for (const bad of junkOptions) {
      expect(build(viewWithOptions([option(), bad]))).toEqual({
        ok: false,
        reason: 'malformed-required-field',
      });
    }
  });

  it('fails closed on a malformed Enterprise entry', () => {
    expect(
      build(
        viewWithOptions([], {
          Enterprise: { PlanId: '', DisplayName: 'HushVoting! Enterprise', SafeDescription: 'x' },
        }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-required-field' });
    expect(
      build(
        viewWithOptions([], {
          Enterprise: null as never,
        }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-required-field' });
  });

  it('rejects unbounded option counts (defense in depth)', () => {
    const many = Array.from({ length: 65 }, (_, i) =>
      option({ PlanId: `hushvoting.veritas.${i}` }),
    );
    expect(build(viewWithOptions(many))).toEqual({ ok: false, reason: 'unbounded-value' });
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

  it('never leaks raw template/exact-bytes material through options or Enterprise', () => {
    const result = build(
      (() => {
        const view = activeView();
        const raw = {
          PlanId: 'hushvoting.veritas.2000',
          DisplayName: 'HushVoting! Veritas 2k',
          SafeDescription: 'Annual',
          EligibleVoterCap: 2000,
          TermYears: 1,
          // Injected junk that must never cross the allowlist:
          TransitionIntent: 'confirmed_upgrade',
          RequestedPlanId: 'hushvoting.veritas.2000',
          ExpectedCurrentLicenceTransactionId: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
          UserSignature: { Signatory: '0x', Signature: 'deadbeef' },
        };
        return {
          ...view,
          PlanId: 'hushvoting.direct.free',
          PlanFamily: 'direct',
          DisplayName: 'HushVoting! Direct Free',
          SafeDescription: 'Annual',
          HigherOptions: [raw],
          Enterprise: {
            PlanId: 'hushvoting.enterprise',
            DisplayName: 'HushVoting! Enterprise',
            SafeDescription: 'Contact provider',
          },
        } as unknown as LicenceActiveEntitlementTransportView;
      })(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const serialized = JSON.stringify(projectionPublicShape(result.projection));
    for (const forbidden of [
      'TransitionIntent',
      'RequestedPlanId',
      'ExpectedCurrent',
      'UserSignature',
      'signature',
      'exactJson',
      'digest',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    const shape = JSON.parse(serialized) as {
      higherOptions: Array<Record<string, unknown>>;
      enterprise: Record<string, unknown> | null;
      catalogueVersion: string;
      safeDescription: string;
    };
    expect(shape.catalogueVersion).toBe(CATALOGUE_V1);
    expect(shape.safeDescription).toBe('Annual');
    expect(Object.keys(shape.higherOptions[0]).sort()).toEqual([
      'displayName',
      'eligibleVoterCap',
      'planId',
      'safeDescription',
      'termYears',
    ]);
    expect(shape.enterprise).not.toBeNull();
    expect(Object.keys(shape.enterprise!).sort()).toEqual([
      'displayName',
      'planId',
      'safeDescription',
    ]);
  });

  it('has no persistence adapter by construction (no storage exports)', () => {
    // The module only exports builder/shape helpers; nothing can write storage.
    const exported = Object.keys(projectionModule);
    expect(exported).not.toContain('persist');
    expect(exported).not.toContain('save');
    expect(exported).not.toContain('write');
  });
});
