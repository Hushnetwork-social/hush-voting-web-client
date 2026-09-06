/**
 * FEAT-016 Task 2.1 — safe runtime entitlement projection.
 *
 * The only entitlement representation that may reach presentation/state: a
 * bounded, in-memory-only view containing identity binding, network binding,
 * licence identifier/type/status, normalized start/expiry boundaries, and a
 * constraint/enforcement projection. It never carries credentials, raw signed
 * bytes, database/cache keys, signatures, endpoints, history, or free-form
 * server text — and it has NO persistence adapter by construction.
 *
 * SECRET/STORAGE BOUNDARY: projection instances are runtime-memory-only.
 * This module exposes no serializer-to-storage, no `.dat` export, and no
 * localStorage/IndexedDB/preferences API. Serialization exists only in the
 * closed `projectionPublicShape` helper used by tests and artifact scans to
 * prove forbidden fields never appear.
 *
 * Normative source: FEAT-016 FeatureDescription "Safe projection", "Rendering
 * and state boundary", "Security, Privacy, Performance, and Observability";
 * planning-analysis-report §6.
 */

import type {
  LicenceActorBinding,
  LicenceActiveEntitlementTransportView,
  LicenceNetworkBinding,
  LicencePlanFamily,
  LicenceReference,
} from './contracts';

/**
 * Safe runtime projection. `licenceReference` is the public on-chain licence
 * reference; no identity address, credential, or raw transaction material is
 * present. Cap/option values are a bounded enforcement projection for FEAT-018
 * presentation only and never authorize anything client-side.
 */
export interface LicenceSafeProjection {
  readonly kind: 'licence-safe-projection';
  readonly schemaVersion: 1;
  readonly identityBinding: LicenceActorBinding;
  readonly networkBinding: LicenceNetworkBinding;
  readonly licenceReference: LicenceReference;
  readonly planId: string;
  readonly planFamily: LicencePlanFamily;
  readonly displayName: string;
  readonly effectiveFromUtc: string; // normalized UTC ISO-8601
  readonly expiresAtUtc?: string; // upper-exclusive; absent = no expiry timer
  readonly termKind?: string;
  readonly termYears?: number;
  readonly eligibleVoterCap?: number;
  readonly unlimitedElections?: boolean;
  readonly allowedGovernanceOptionIds: ReadonlyArray<string>;
  readonly provenance: 'indexed-query';
}

/** Failure-closed reasons for refusing to build a safe projection. */
export type ProjectionRejectionReason =
  | 'missing-active-view'
  | 'unknown-state'
  | 'identity-mismatch'
  | 'network-mismatch'
  | 'unknown-plan-family'
  | 'incompatible-catalogue-version'
  | 'malformed-required-field'
  | 'unbounded-value';

export type ProjectionBuildResult =
  | { readonly ok: true; readonly projection: LicenceSafeProjection }
  | { readonly ok: false; readonly reason: ProjectionRejectionReason };

const MAX_SAFE_TEXT_LENGTH = 512;
const MAX_OPTION_COUNT = 64;
const MAX_OPTION_TEXT_LENGTH = 256;
const MAX_REFERENCE_LENGTH = 128;

function isBoundedText(value: unknown, max = MAX_SAFE_TEXT_LENGTH): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isIsoUtc(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) {
    return false;
  }
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(value);
}

function isKnownFamily(value: string): value is LicencePlanFamily {
  return value === 'direct' || value === 'veritas' || value === 'enterprise';
}

/**
 * Build the safe projection from an active transport view + bindings.
 * Fails closed on any missing/malformed/unknown/incompatible/unbounded value;
 * never coerces unknown enums and never infers catalogue truth.
 */
export function buildLicenceSafeProjection(
  actorBinding: LicenceActorBinding,
  networkBinding: LicenceNetworkBinding,
  active: LicenceActiveEntitlementTransportView,
): ProjectionBuildResult {
  if (!active || typeof active !== 'object') {
    return { ok: false, reason: 'missing-active-view' };
  }
  if (!isBoundedText(active.LicenceReference, MAX_REFERENCE_LENGTH)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (!isBoundedText(active.PlanId) || !isBoundedText(active.PlanFamily)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (!isKnownFamily(active.PlanFamily)) {
    return { ok: false, reason: 'unknown-plan-family' };
  }
  if (active.AssignedCatalogueVersion !== 'hushvoting-licence-catalogue/v1.0.0') {
    return { ok: false, reason: 'incompatible-catalogue-version' };
  }
  if (!isBoundedText(active.DisplayName)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (!isIsoUtc(active.EffectiveFromUtc)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (active.ExpiresAtUtc !== undefined && !isIsoUtc(active.ExpiresAtUtc)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (active.TermKind !== undefined && !isBoundedText(active.TermKind)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (active.TermYears !== undefined && (!Number.isInteger(active.TermYears) || active.TermYears < 0)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (
    active.EligibleVoterCap !== undefined &&
    (!Number.isInteger(active.EligibleVoterCap) || active.EligibleVoterCap < 0)
  ) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (!Array.isArray(active.HigherOptions) || !Array.isArray(active.AllowedGovernanceOptionIds)) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (active.HigherOptions.length > MAX_OPTION_COUNT) {
    return { ok: false, reason: 'unbounded-value' };
  }
  if (active.AllowedGovernanceOptionIds.length > MAX_OPTION_COUNT) {
    return { ok: false, reason: 'unbounded-value' };
  }
  if (
    !active.AllowedGovernanceOptionIds.every(
      (option) => isBoundedText(option, MAX_OPTION_TEXT_LENGTH),
    )
  ) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (active.HigherOptions.length > 0 && typeof active.HigherOptions[0] === 'string') {
    // Defensive: higher options must be records, never raw strings.
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (
    active.HigherOptions.some(
      (option) =>
        !isRecordValue(option) ||
        !isBoundedText(option.PlanId) ||
        !isBoundedText(option.DisplayName) ||
        !isBoundedText(option.SafeDescription),
    )
  ) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (
    active.Enterprise !== undefined &&
    (!isBoundedText(active.Enterprise.PlanId) ||
      !isBoundedText(active.Enterprise.DisplayName) ||
      !isBoundedText(active.Enterprise.SafeDescription))
  ) {
    return { ok: false, reason: 'malformed-required-field' };
  }

  const projection: LicenceSafeProjection = {
    kind: 'licence-safe-projection',
    schemaVersion: 1,
    identityBinding: actorBinding,
    networkBinding,
    licenceReference: active.LicenceReference as LicenceReference,
    planId: active.PlanId,
    planFamily: active.PlanFamily as LicencePlanFamily,
    displayName: active.DisplayName,
    effectiveFromUtc: active.EffectiveFromUtc,
    expiresAtUtc: active.ExpiresAtUtc,
    termKind: active.TermKind,
    termYears: active.TermYears,
    eligibleVoterCap: active.EligibleVoterCap,
    unlimitedElections: active.UnlimitedElections,
    allowedGovernanceOptionIds: [...active.AllowedGovernanceOptionIds],
    provenance: 'indexed-query',
  };
  return { ok: true, projection };
}

/**
 * Closed public serialization shape used by tests/scans to prove the
 * projection excludes forbidden fields. Consumers must never persist it.
 */
export function projectionPublicShape(projection: LicenceSafeProjection): Record<string, unknown> {
  return {
    kind: projection.kind,
    schemaVersion: projection.schemaVersion,
    licenceReference: projection.licenceReference,
    planId: projection.planId,
    planFamily: projection.planFamily,
    displayName: projection.displayName,
    effectiveFromUtc: projection.effectiveFromUtc,
    expiresAtUtc: projection.expiresAtUtc,
    termKind: projection.termKind,
    termYears: projection.termYears,
    eligibleVoterCap: projection.eligibleVoterCap,
    unlimitedElections: projection.unlimitedElections,
    allowedGovernanceOptionIds: projection.allowedGovernanceOptionIds,
    provenance: projection.provenance,
  };
}
