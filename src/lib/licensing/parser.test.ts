/**
 * FEAT-016 Task 2.2 — parser outcome tests.
 *
 * Proves the closed outcome vocabulary: ready only from compatible active
 * indexed truth; no-active only from a valid server Direct Free template;
 * unavailable never becomes no-active/Free; UNAUTHENTICATED stays typed for
 * the one-retry policy; PERMISSION_DENIED/INVALID_ARGUMENT/UNIMPLEMENTED/
 * transport statuses map deterministically; unsupported (unknown family /
 * incompatible catalogue) never fabricates a plan; malformed/unknown data
 * fails closed without throwing.
 */

import { describe, expect, it } from 'vitest';
import type {
  LicenceActiveEntitlementTransportView,
  LicenceQueryTransportResult,
} from './contracts';
import { parseEntitlementQueryResult } from './parser';

const ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
const NETWORK = 'hush-network-local-devnet-5195086';
const CATALOGUE_V1 = 'hushvoting-licence-catalogue/v1.0.0';

function activeResult(
  overrides: Partial<LicenceActiveEntitlementTransportView> = {},
): LicenceQueryTransportResult {
  return {
    ok: true,
    state: 'active',
    active: {
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
      AllowedGovernanceOptionIds: [],
      HigherOptions: [],
      ...overrides,
    },
  };
}

function parse(result: LicenceQueryTransportResult) {
  return parseEntitlementQueryResult(result, ACTOR as never, NETWORK as never);
}

describe('parseEntitlementQueryResult', () => {
  it('maps a compatible active result to ready with a safe projection', () => {
    const outcome = parse(activeResult());
    expect(outcome.outcome).toBe('ready');
    if (outcome.outcome === 'ready') {
      expect(outcome.projection.planFamily).toBe('veritas');
      expect(outcome.projection.identityBinding).toBe(ACTOR);
    }
  });

  it('maps no-active to noActive with the exact server template', () => {
    const outcome = parse({
      ok: true,
      state: 'noActive',
      template: {
        TransitionIntent: 'baseline_free',
        RequestedPlanId: 'hushvoting.direct.free',
        ObservedCatalogueVersion: CATALOGUE_V1,
      },
    });
    expect(outcome).toEqual({
      outcome: 'noActive',
      template: {
        TransitionIntent: 'baseline_free',
        RequestedPlanId: 'hushvoting.direct.free',
        ObservedCatalogueVersion: CATALOGUE_V1,
      },
    });
  });

  it('rejects a malformed no-active template as malformed (never client-authored)', () => {
    for (const template of [
      { TransitionIntent: 'confirmed_upgrade', RequestedPlanId: 'hushvoting.direct.free', ObservedCatalogueVersion: CATALOGUE_V1 },
      { TransitionIntent: 'baseline_free', RequestedPlanId: 'hushvoting.veritas.2000', ObservedCatalogueVersion: CATALOGUE_V1 },
      { TransitionIntent: 'baseline_free', RequestedPlanId: 'hushvoting.direct.free', ObservedCatalogueVersion: '' },
      null,
      'free',
    ]) {
      expect(parse({ ok: true, state: 'noActive', template: template as never }).outcome).toBe(
        'malformed',
      );
    }
  });

  it('maps unavailable to a typed outcome and never to no-active/Free', () => {
    const outcome = parse({ ok: true, state: 'unavailable', code: 'licence_index_unavailable' });
    expect(outcome).toEqual({ outcome: 'unavailable', code: 'licence_index_unavailable' });
  });

  it('maps transport statuses deterministically', () => {
    expect(parse({ ok: false, status: 'UNAUTHENTICATED' })).toEqual({ outcome: 'unauthenticated' });
    expect(parse({ ok: false, status: 'PERMISSION_DENIED' })).toEqual({ outcome: 'permissionDenied' });
    expect(parse({ ok: false, status: 'INVALID_ARGUMENT' })).toEqual({ outcome: 'invalidArgument' });
    expect(parse({ ok: false, status: 'UNIMPLEMENTED' })).toEqual({ outcome: 'unimplemented' });
    expect(parse({ ok: false, status: 'UNAVAILABLE' })).toEqual({
      outcome: 'unavailable',
      code: 'licence_authority_unavailable',
    });
    expect(parse({ ok: false, status: 'DEADLINE_EXCEEDED' })).toEqual({ outcome: 'transportFailure' });
    expect(parse({ ok: false, status: 'UNKNOWN' })).toEqual({ outcome: 'transportFailure' });
  });

  it('never coerces an unknown/future plan family into Direct Free or known Veritas', () => {
    const outcome = parse(activeResult({ PlanFamily: 'hyperion-2099' }));
    expect(outcome.outcome).toBe('unsupported');
    if (outcome.outcome === 'unsupported') {
      expect(outcome.reason).toBe('unknown-plan-family');
    }
  });

  it('gates an incompatible catalogue version without creating a baseline', () => {
    const outcome = parse(activeResult({ AssignedCatalogueVersion: 'hushvoting-licence-catalogue/v9.0.0' }));
    expect(outcome.outcome).toBe('unsupported');
    if (outcome.outcome === 'unsupported') {
      expect(outcome.reason).toBe('incompatible-catalogue-version');
    }
  });

  it('fails closed on malformed/unknown states without throwing', () => {
    expect(parse({ ok: true, state: 'active', active: null as never }).outcome).toBe('malformed');
    expect(parse({ ok: true, state: 'unknownState' as never, template: undefined as never }).outcome).toBe('malformed');
    expect(parse(null as never).outcome).toBe('malformed');
    expect(parse('junk' as never).outcome).toBe('malformed');
    expect(parse({ ok: true } as never).outcome).toBe('malformed');
  });
});
