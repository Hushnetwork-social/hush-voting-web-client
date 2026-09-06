/**
 * FEAT-016 Task 6.2 — licence BFF decode + HTTP-contract tests.
 *
 * Locks: the FEAT-015 wire reply → closed transport vocabulary decode
 * (active / no-active / unavailable), the typed gRPC-status mapping, the
 * bounded same-origin HTTP contract (exactly three headers, no fourth/fifth
 * header, no request ID, bounded content type/length, no-store envelope
 * parsing), and fail-closed behavior for every malformed/unknown case.
 */

import { describe, expect, it } from 'vitest';
import {
  decodeLicenceQueryReply,
  grpcStatusToLicenceStatus,
  licenceQueryFailureFromGrpcError,
} from './bff-decode';
import {
  LICENCE_BFF_MAX_REQUEST_BYTES,
  parseLicenceBffReply,
  validateLicenceBffRequest,
} from './licence-bff-http';

const ACTIVE_WIRE = {
  state: 'LICENCE_ENTITLEMENT_STATE_ACTIVE',
  active: {
    licence_reference: '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e',
    plan_id: 'hushvoting.veritas.2000',
    plan_family: 'veritas',
    display_name: 'HushVoting! Veritas 2k',
    safe_description: 'Annual Veritas licence',
    eligible_voter_cap: '2000',
    unlimited_elections: true,
    term_kind: 'annual',
    term_years: '1',
    allowed_governance_option_ids: ['gov-trustees-7-of-10'],
    effective_from_utc: '2026-01-01T00:00:00.000Z',
    expires_at_utc: '2027-01-01T00:00:00.000Z',
    assigned_catalogue_version: 'hushvoting-licence-catalogue/v1.0.0',
    higher_options: [],
    enterprise: null,
  },
  direct_free_template: null,
  unavailable_code: '',
};

describe('decodeLicenceQueryReply (FEAT-015 wire → closed vocabulary)', () => {
  it('decodes an active reply into the PascalCase transport view', () => {
    const result = decodeLicenceQueryReply(ACTIVE_WIRE);
    expect(result).toEqual({
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
        AssignedCatalogueVersion: 'hushvoting-licence-catalogue/v1.0.0',
        AllowedGovernanceOptionIds: ['gov-trustees-7-of-10'],
        HigherOptions: [],
      },
    });
  });

  it('decodes higher options and enterprise when present', () => {
    const result = decodeLicenceQueryReply({
      state: 'LICENCE_ENTITLEMENT_STATE_ACTIVE',
      active: {
        ...ACTIVE_WIRE.active,
        higher_options: [
          {
            plan_id: 'hushvoting.veritas.10000',
            display_name: 'HushVoting! Veritas 10k',
            safe_description: '10,000 voters',
            eligible_voter_cap: '10000',
            unlimited_elections: true,
            term_kind: 'annual',
            term_years: '1',
          },
        ],
        enterprise: {
          plan_id: 'hushvoting.enterprise',
          display_name: 'HushVoting! Enterprise',
          safe_description: 'Contact provider',
        },
      },
    });
    expect(result).toEqual({
      ok: true,
      state: 'active',
      active: expect.objectContaining({
        HigherOptions: [
          {
            PlanId: 'hushvoting.veritas.10000',
            DisplayName: 'HushVoting! Veritas 10k',
            SafeDescription: '10,000 voters',
            EligibleVoterCap: 10000,
            UnlimitedElections: true,
            TermKind: 'annual',
            TermYears: 1,
          },
        ],
        Enterprise: {
          PlanId: 'hushvoting.enterprise',
          DisplayName: 'HushVoting! Enterprise',
          SafeDescription: 'Contact provider',
        },
      }),
    });
  });

  it('decodes a no-active reply with the exact server Direct Free template', () => {
    const result = decodeLicenceQueryReply({
      state: 'LICENCE_ENTITLEMENT_STATE_NO_ACTIVE',
      active: null,
      direct_free_template: {
        transition_intent: 'baseline_free',
        requested_plan_id: 'hushvoting.direct.free',
        observed_catalogue_version: 'hushvoting-licence-catalogue/v1.0.0',
      },
      unavailable_code: '',
    });
    expect(result).toEqual({
      ok: true,
      state: 'noActive',
      template: {
        TransitionIntent: 'baseline_free',
        RequestedPlanId: 'hushvoting.direct.free',
        ObservedCatalogueVersion: 'hushvoting-licence-catalogue/v1.0.0',
      },
    });
  });

  it('decodes an unspecified state into a typed unavailable with the stable code', () => {
    const result = decodeLicenceQueryReply({
      state: 'LICENCE_ENTITLEMENT_STATE_UNSPECIFIED',
      active: null,
      direct_free_template: null,
      unavailable_code: 'licence_index_unavailable',
    });
    expect(result).toEqual({ ok: true, state: 'unavailable', code: 'licence_index_unavailable' });
  });

  it('fails closed on malformed, unknown, or unbounded replies (never fabricates)', () => {
    expect(decodeLicenceQueryReply(null)).toEqual({ ok: false, status: 'UNKNOWN' });
    expect(decodeLicenceQueryReply('nope')).toEqual({ ok: false, status: 'UNKNOWN' });
    expect(decodeLicenceQueryReply({ state: 'BOGUS_STATE' })).toEqual({ ok: false, status: 'UNKNOWN' });
    // Active with a missing mandatory field.
    expect(decodeLicenceQueryReply({ state: 'LICENCE_ENTITLEMENT_STATE_ACTIVE', active: {} })).toEqual({
      ok: false,
      status: 'UNKNOWN',
    });
    // Active with a non-numeric cap string.
    expect(
      decodeLicenceQueryReply({
        state: 'LICENCE_ENTITLEMENT_STATE_ACTIVE',
        active: { ...ACTIVE_WIRE.active, eligible_voter_cap: 'not-a-number' },
      }),
    ).toEqual({ ok: false, status: 'UNKNOWN' });
    // No-active with a foreign template.
    expect(
      decodeLicenceQueryReply({ state: 'LICENCE_ENTITLEMENT_STATE_NO_ACTIVE', direct_free_template: { transition_intent: 'x' } }),
    ).toEqual({ ok: false, status: 'UNKNOWN' });
    // Unspecified with no stable code.
    expect(decodeLicenceQueryReply({ state: 'LICENCE_ENTITLEMENT_STATE_UNSPECIFIED', unavailable_code: '' })).toEqual({
      ok: false,
      status: 'UNKNOWN',
    });
  });
});

describe('licence transport status mapping', () => {
  it('maps stable gRPC codes onto the closed licence status vocabulary', () => {
    expect(grpcStatusToLicenceStatus(16)).toBe('UNAUTHENTICATED');
    expect(grpcStatusToLicenceStatus(7)).toBe('PERMISSION_DENIED');
    expect(grpcStatusToLicenceStatus(3)).toBe('INVALID_ARGUMENT');
    expect(grpcStatusToLicenceStatus(12)).toBe('UNIMPLEMENTED');
    expect(grpcStatusToLicenceStatus(4)).toBe('DEADLINE_EXCEEDED');
    expect(grpcStatusToLicenceStatus(14)).toBe('UNAVAILABLE');
    expect(grpcStatusToLicenceStatus('UNKNOWN')).toBe('UNKNOWN');
    expect(grpcStatusToLicenceStatus(999)).toBe('UNKNOWN');
    expect(grpcStatusToLicenceStatus(undefined)).toBe('UNKNOWN');
  });

  it('converts a raw gRPC error into a closed failure without exposing details', () => {
    expect(licenceQueryFailureFromGrpcError({ code: 16, details: 'signature expired: alice@example.com' })).toEqual({
      ok: false,
      status: 'UNAUTHENTICATED',
    });
    expect(licenceQueryFailureFromGrpcError({ code: 4 })).toEqual({ ok: false, status: 'DEADLINE_EXCEEDED' });
    expect(licenceQueryFailureFromGrpcError(null)).toEqual({ ok: false, status: 'UNKNOWN' });
  });
});

describe('licence BFF same-origin HTTP contract', () => {
  const goodHeaders = () => ({
    signatory: '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5',
    signedAt: '2026-09-06T00:00:00Z',
    signature: 'c2lnbmF0dXJlLWJ5dGVz',
  });
  const headerNames = ['x-hush-licence-query-signatory', 'x-hush-licence-query-signed-at', 'x-hush-licence-query-signature'];

  it('accepts exactly the three frozen headers with an empty body', () => {
    const result = validateLicenceBffRequest({
      configured: true,
      contentLength: 0,
      contentType: '',
      headerNames,
      headers: goodHeaders(),
    });
    expect(result).toEqual({ ok: true, headers: goodHeaders() });
  });

  it('rejects a missing, extra, or foreign signed-query header (no request ID)', () => {
    const missing = validateLicenceBffRequest({
      configured: true,
      contentLength: 0,
      contentType: '',
      headerNames: headerNames.filter((name) => name !== 'x-hush-licence-query-signed-at'),
      headers: { ...goodHeaders(), signedAt: '' },
    });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.code).toBe('MALFORMED_REQUEST');

    const extra = validateLicenceBffRequest({
      configured: true,
      contentLength: 0,
      contentType: '',
      headerNames: [...headerNames, 'x-hush-licence-query-request-id'],
      headers: goodHeaders(),
    });
    expect(extra.ok).toBe(false);
    if (!extra.ok) expect(extra.code).toBe('MALFORMED_REQUEST');

    const foreign = validateLicenceBffRequest({
      configured: true,
      contentLength: 0,
      contentType: '',
      headerNames: [...headerNames, 'x-hush-protocol'],
      headers: goodHeaders(),
    });
    expect(foreign.ok).toBe(false);
  });

  it('rejects oversized bodies, foreign content types, and missing config', () => {
    const oversized = validateLicenceBffRequest({
      configured: true,
      contentLength: LICENCE_BFF_MAX_REQUEST_BYTES + 1,
      contentType: '',
      headerNames,
      headers: goodHeaders(),
    });
    expect(oversized).toEqual({ ok: false, code: 'TOO_LARGE' });

    const badType = validateLicenceBffRequest({
      configured: true,
      contentLength: 0,
      contentType: 'text/html',
      headerNames,
      headers: goodHeaders(),
    });
    expect(badType).toEqual({ ok: false, code: 'MALFORMED_REQUEST' });

    const notConfigured = validateLicenceBffRequest({
      configured: false,
      contentLength: 0,
      contentType: '',
      headerNames,
      headers: goodHeaders(),
    });
    expect(notConfigured).toEqual({ ok: false, code: 'NOT_CONFIGURED' });
  });

  it('parses the no-store reply envelope and fails closed on malformed bodies', () => {
    expect(parseLicenceBffReply({ reply: { ok: true, state: 'noActive', template: { TransitionIntent: 'baseline_free', RequestedPlanId: 'hushvoting.direct.free', ObservedCatalogueVersion: 'v1' } } })).toEqual({
      ok: true,
      state: 'noActive',
      template: { TransitionIntent: 'baseline_free', RequestedPlanId: 'hushvoting.direct.free', ObservedCatalogueVersion: 'v1' },
    });
    expect(parseLicenceBffReply(null)).toEqual({ ok: false, status: 'UNKNOWN' });
    expect(parseLicenceBffReply({ error: { code: 'SERVER_UNAVAILABLE' } })).toEqual({ ok: false, status: 'UNKNOWN' });
  });
});
