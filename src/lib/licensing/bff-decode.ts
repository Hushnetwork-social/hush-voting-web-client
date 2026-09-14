/**
 * FEAT-016 Task 6.1 — licence-query BFF decode (server-side only).
 *
 * Decodes the FEAT-015 `GetMyEntitlement` binary gRPC reply (snake_case wire
 * keys produced by the pinned proto loader) into the closed
 * `LicenceQueryTransportResult` vocabulary the coordinator/parser consume.
 *
 * The decode is the ONLY place snake_case FEAT-015 wire fields become the
 * PascalCase transport view (`LicenceReference`, `PlanId`, …). Malformed,
 * unknown, empty-string-int64, or out-of-bound values fail closed to a typed
 * `UNKNOWN`/`unavailable` outcome — never fabricated truth, never free-form
 * text. Longs arrive as strings under the pinned loader options and are
 * normalized to bounded safe integers.
 *
 * SECRET BOUNDARY: the reply never contains signatures, vault handles,
 * endpoints, cache provenance, or free-form server messages. This module
 * holds no secrets and is framework-neutral (importable by vitest without a
 * Node/server context).
 *
 * Normative source: FEAT-016 FeatureDescription "Signed Query Contract",
 * FEAT-015 `hushVotingLicence.proto` and server response mapping;
 * `src/lib/licensing/contracts.ts` (frozen transport view vocabulary).
 */

import type {
  LicenceActiveEntitlementTransportView,
  LicenceDirectFreeTemplate,
  LicenceHigherOptionView,
  LicenceQueryTransportResult,
  LicenceTransportStatus,
} from './contracts';

/** Bounded decode guards mirror the parser's own bounds. */
const MAX_TEXT = 512;
const MAX_REFERENCE = 128;
const MAX_OPTIONS = 64;
const MAX_CAP = 9_007_199_254_740_991; // Number.MAX_SAFE_INTEGER

type WireRecord = Record<string, unknown>;

function isRecord(value: unknown): value is WireRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, max: number = MAX_TEXT): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    return null;
  }
  return value;
}

function optionalBoundedString(value: unknown, max: number = MAX_TEXT): string | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  return boundedString(value, max) ?? undefined;
}

/** int64 arrives as a string under loader `longs: String`; normalize safely. */
function safeInt(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  if (typeof value === 'string' && /^\d+$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= MAX_CAP ? parsed : undefined;
  }
  return undefined;
}

/** Present-but-malformed int64 must fail the whole view (never coerce). */
function presentInt(value: unknown): { readonly ok: true; readonly value?: number } | { readonly ok: false } {
  if (value === undefined || value === null) {
    return { ok: true };
  }
  const parsed = safeInt(value);
  return parsed === undefined ? { ok: false } : { ok: true, value: parsed };
}

function decodeHigherOption(value: unknown): LicenceHigherOptionView | null {
  if (!isRecord(value)) {
    return null;
  }
  const planId = boundedString(value.plan_id);
  const displayName = boundedString(value.display_name);
  const safeDescription = boundedString(value.safe_description);
  if (planId === null || displayName === null || safeDescription === null) {
    return null;
  }
  const cap = presentInt(value.eligible_voter_cap);
  if (!cap.ok) {
    return null;
  }
  const termYears = presentInt(value.term_years);
  if (!termYears.ok) {
    return null;
  }
  const termKind = optionalBoundedString(value.term_kind);
  const option: LicenceHigherOptionView = {
    PlanId: planId,
    DisplayName: displayName,
    SafeDescription: safeDescription,
    ...(cap.value !== undefined ? { EligibleVoterCap: cap.value } : {}),
    ...(typeof value.unlimited_elections === 'boolean' ? { UnlimitedElections: value.unlimited_elections } : {}),
    ...(termKind !== undefined ? { TermKind: termKind } : {}),
    ...(termYears.value !== undefined ? { TermYears: termYears.value } : {}),
  };
  return option;
}

function decodeEnterprise(value: unknown): LicenceActiveEntitlementTransportView['Enterprise'] {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!isRecord(value)) {
    return undefined;
  }
  const planId = boundedString(value.plan_id);
  const displayName = boundedString(value.display_name);
  const safeDescription = boundedString(value.safe_description);
  if (planId === null || displayName === null || safeDescription === null) {
    return undefined;
  }
  return { PlanId: planId, DisplayName: displayName, SafeDescription: safeDescription };
}

function decodeActiveView(value: unknown): LicenceActiveEntitlementTransportView | null {
  if (!isRecord(value)) {
    return null;
  }
  const licenceReference = boundedString(value.licence_reference, MAX_REFERENCE);
  const planId = boundedString(value.plan_id);
  const planFamily = boundedString(value.plan_family);
  const displayName = boundedString(value.display_name);
  const safeDescription = boundedString(value.safe_description);
  const effectiveFromUtc = boundedString(value.effective_from_utc, 64);
  const assignedCatalogueVersion = boundedString(value.assigned_catalogue_version);
  if (
    licenceReference === null ||
    planId === null ||
    planFamily === null ||
    displayName === null ||
    safeDescription === null ||
    effectiveFromUtc === null ||
    assignedCatalogueVersion === null
  ) {
    return null;
  }
  const cap = presentInt(value.eligible_voter_cap);
  if (!cap.ok) {
    return null;
  }
  const termYears = presentInt(value.term_years);
  if (!termYears.ok) {
    return null;
  }
  if (value.unlimited_elections !== undefined && value.unlimited_elections !== null && typeof value.unlimited_elections !== 'boolean') {
    return null;
  }
  const expiresAt = optionalBoundedString(value.expires_at_utc, 64);
  const termKind = optionalBoundedString(value.term_kind);

  const governance = value.allowed_governance_option_ids;
  if (!Array.isArray(governance) || governance.length > MAX_OPTIONS) {
    return null;
  }
  const governanceIds: string[] = [];
  for (const id of governance) {
    const bounded = boundedString(id, 256);
    if (bounded === null) {
      return null;
    }
    governanceIds.push(bounded);
  }

  const higher = value.higher_options;
  if (!Array.isArray(higher) || higher.length > MAX_OPTIONS) {
    return null;
  }
  const higherOptions: LicenceHigherOptionView[] = [];
  for (const option of higher) {
    const decoded = decodeHigherOption(option);
    if (decoded === null) {
      return null;
    }
    higherOptions.push(decoded);
  }

  const view: LicenceActiveEntitlementTransportView = {
    LicenceReference: licenceReference,
    PlanId: planId,
    PlanFamily: planFamily,
    DisplayName: displayName,
    SafeDescription: safeDescription,
    EffectiveFromUtc: effectiveFromUtc,
    AssignedCatalogueVersion: assignedCatalogueVersion,
    ...(expiresAt !== undefined ? { ExpiresAtUtc: expiresAt } : {}),
    ...(termKind !== undefined ? { TermKind: termKind } : {}),
    ...(cap.value !== undefined ? { EligibleVoterCap: cap.value } : {}),
    ...(typeof value.unlimited_elections === 'boolean' ? { UnlimitedElections: value.unlimited_elections } : {}),
    ...(termYears.value !== undefined ? { TermYears: termYears.value } : {}),
    AllowedGovernanceOptionIds: governanceIds,
    HigherOptions: higherOptions,
  };
  const enterprise = decodeEnterprise(value.enterprise);
  if (enterprise !== undefined) {
    return { ...view, Enterprise: enterprise };
  }
  return view;
}

function decodeNoActiveTemplate(value: unknown): LicenceDirectFreeTemplate | null {
  if (!isRecord(value)) {
    return null;
  }
  const transitionIntent = boundedString(value.transition_intent, 64);
  const requestedPlanId = boundedString(value.requested_plan_id, 128);
  const observedCatalogueVersion = boundedString(value.observed_catalogue_version, 256);
  if (transitionIntent === null || requestedPlanId === null || observedCatalogueVersion === null) {
    return null;
  }
  // Only the frozen FEAT-015 baseline template is accepted verbatim.
  if (transitionIntent !== 'baseline_free' || requestedPlanId !== 'hushvoting.direct.free') {
    return null;
  }
  return {
    TransitionIntent: transitionIntent as 'baseline_free',
    RequestedPlanId: requestedPlanId as 'hushvoting.direct.free',
    ObservedCatalogueVersion: observedCatalogueVersion,
  };
}

/**
 * Decode one FEAT-015 `GetMyEntitlement` reply into the closed transport
 * result. Any malformed/unknown state or unbounded field fails closed:
 *   - `active` -> typed success with a bounded safe transport view;
 *   - `no_active` -> typed success with the exact server template;
 *   - unavailable/unspecified -> typed `unavailable` with the stable code;
 *   - anything else -> `{ ok: false, status: 'UNKNOWN' }`.
 */
export function decodeLicenceQueryReply(reply: unknown): LicenceQueryTransportResult {
  if (!isRecord(reply)) {
    return { ok: false, status: 'UNKNOWN' };
  }
  switch (reply.state) {
    case 'LICENCE_ENTITLEMENT_STATE_ACTIVE': {
      const active = decodeActiveView(reply.active);
      if (active === null) {
        return { ok: false, status: 'UNKNOWN' };
      }
      return { ok: true, state: 'active', active };
    }
    case 'LICENCE_ENTITLEMENT_STATE_NO_ACTIVE': {
      const template = decodeNoActiveTemplate(reply.direct_free_template);
      if (template === null) {
        return { ok: false, status: 'UNKNOWN' };
      }
      return { ok: true, state: 'noActive', template };
    }
    case 'LICENCE_ENTITLEMENT_STATE_UNSPECIFIED': {
      const code = boundedString(reply.unavailable_code, 128);
      if (code === null) {
        return { ok: false, status: 'UNKNOWN' };
      }
      return { ok: true, state: 'unavailable', code };
    }
    default:
      // Unknown/missing enum fails closed: never coerce to a plan.
      return { ok: false, status: 'UNKNOWN' };
  }
}

/**
 * Map a gRPC status code onto the closed licence transport status
 * vocabulary. Free-form server text never crosses; only the stable status
 * value is produced.
 */
export function grpcStatusToLicenceStatus(code: unknown): LicenceTransportStatus {
  const numeric = typeof code === 'number' ? code : Number(code);
  switch (numeric) {
    case 16:
      return 'UNAUTHENTICATED';
    case 7:
      return 'PERMISSION_DENIED';
    case 3:
      return 'INVALID_ARGUMENT';
    case 12:
      return 'UNIMPLEMENTED';
    case 4:
      return 'DEADLINE_EXCEEDED';
    case 14:
      return 'UNAVAILABLE';
    default:
      return 'UNKNOWN';
  }
}

/** Typed transport failure for an upstream gRPC rejection. */
export function licenceQueryFailureFromGrpcError(error: unknown): LicenceQueryTransportResult {
  const code = (error as { code?: unknown } | null)?.code;
  return { ok: false, status: grpcStatusToLicenceStatus(code) };
}
