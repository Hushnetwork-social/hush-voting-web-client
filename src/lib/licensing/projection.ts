/**
 * FEAT-016 Task 2.1 + FEAT-017 Task 2.1 — safe runtime entitlement projection.
 *
 * The only entitlement representation that may reach presentation/state: a
 * bounded, in-memory-only view containing identity binding, network binding,
 * licence identifier/type/status, normalized start/expiry boundaries, a
 * constraint/enforcement projection, and (FEAT-017 additive) the validated
 * higher-option/Enterprise display facts and catalogue version. It never
 * carries credentials, raw signed bytes, database/cache keys, signatures,
 * endpoints, history, or free-form server text — and it has NO persistence
 * adapter by construction.
 *
 * FEAT-017 safe-option boundary: the projection preserves ONLY the display
 * metadata the frozen FEAT-015 response supplies per higher option (plan id,
 * display name, safe description, cap, election semantics, term) in exact
 * server order. Exact activation template values (transition intent and
 * precondition members) stay inside the closed credential authority; the
 * option `planId` is the closed server-template handle the authority
 * re-validates against its own fresh query when Activate is confirmed.
 * Entries that are structurally malformed fail the whole view closed;
 * entries that are semantically unusable without any client catalogue
 * (an option naming the current plan, a duplicate plan id, or an Enterprise
 * plan disguised as an option) are omitted safely with the remaining server
 * order preserved. No client rank/catalogue inference is performed, so
 * "lower" claims are never evaluated client-side and no option is ever
 * fabricated.
 *
 * SECRET/STORAGE BOUNDARY: projection instances are runtime-memory-only.
 * This module exposes no serializer-to-storage, no `.dat` export, and no
 * localStorage/IndexedDB/preferences API. Serialization exists only in the
 * closed `projectionPublicShape` helper used by tests and artifact scans to
 * prove forbidden fields never appear.
 *
 * Normative source: FEAT-016 FeatureDescription "Safe projection", "Rendering
 * and state boundary"; FEAT-015 frozen response vocabulary; FEAT-017
 * FeatureDescription (only-higher server order, Enterprise informational,
 * confirmation binds exact server templates) + planning-analysis-report §5(c),
 * §6.2.
 */

import type {
  LicenceActorBinding,
  LicenceActiveEntitlementTransportView,
  LicenceHigherOptionView,
  LicenceNetworkBinding,
  LicencePlanFamily,
  LicenceReference,
} from './contracts';

/**
 * Safe runtime projection. `licenceReference` is the public on-chain licence
 * reference; no identity address, credential, or raw transaction material is
 * present. Cap/option values are a bounded enforcement projection for FEAT-018
 * presentation only and never authorize anything client-side.
 *
 * FEAT-017 additive members (schemaVersion stays 1; additive only, no
 * persistence): `safeDescription`, `catalogueVersion`, `higherOptions`
 * (validated, server-ordered, semantically safe) and `enterprise`
 * (informational; null when the server sent none). All are runtime-memory
 * presentation facts minted from one fresh indexed-query view.
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
  readonly safeDescription: string;
  readonly effectiveFromUtc: string; // normalized UTC ISO-8601
  readonly expiresAtUtc?: string; // upper-exclusive; absent = no expiry timer
  readonly termKind?: string;
  readonly termYears?: number;
  readonly eligibleVoterCap?: number;
  readonly unlimitedElections?: boolean;
  readonly allowedGovernanceOptionIds: ReadonlyArray<string>;
  readonly catalogueVersion: string;
  readonly higherOptions: ReadonlyArray<LicenceSafeHigherOption>;
  readonly enterprise: LicenceSafeEnterprise | null;
  readonly provenance: 'indexed-query';
}

/**
 * One safe higher-option display entry (server-ordered, server-supplied
 * metadata only). `planId` is the public stable FEAT-012 plan id and the
 * closed server-template handle; exact template values never cross.
 */
export interface LicenceSafeHigherOption {
  readonly planId: string;
  readonly displayName: string;
  readonly safeDescription: string;
  readonly eligibleVoterCap?: number;
  readonly unlimitedElections?: boolean;
  readonly termKind?: string;
  readonly termYears?: number;
}

/** Informational Enterprise display entry (never actionable by construction). */
export interface LicenceSafeEnterprise {
  readonly planId: string;
  readonly displayName: string;
  readonly safeDescription: string;
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

function isOptionalSafeInteger(value: unknown): boolean {
  return (
    value === undefined ||
    (Number.isInteger(value) && (value as number) >= 0 && (value as number) <= Number.MAX_SAFE_INTEGER)
  );
}

function isOptionalBoolean(value: unknown): boolean {
  return value === undefined || typeof value === 'boolean';
}

/** Structural validity of one transport higher-option record (defense in depth). */
function isStructurallyValidOption(option: Record<string, unknown>): boolean {
  return (
    isBoundedText(option.PlanId, MAX_OPTION_TEXT_LENGTH) &&
    isBoundedText(option.DisplayName, MAX_OPTION_TEXT_LENGTH) &&
    isBoundedText(option.SafeDescription, MAX_SAFE_TEXT_LENGTH) &&
    isOptionalSafeInteger(option.EligibleVoterCap) &&
    isOptionalBoolean(option.UnlimitedElections) &&
    (option.TermKind === undefined || isBoundedText(option.TermKind, MAX_OPTION_TEXT_LENGTH)) &&
    isOptionalSafeInteger(option.TermYears)
  );
}

/**
 * FEAT-017 safe-option boundary (pure). Input options have already passed
 * structural validation; this step omits only the entries that are
 * semantically unusable without any client catalogue or rank table:
 *   - an option naming the current plan (never re-offer the active plan);
 *   - an Enterprise plan disguised as a higher option (Enterprise is
 *     informational only and may never be self-service);
 *   - a duplicate plan id after the first occurrence (ambiguous ordering).
 * Server order of the retained entries is preserved byte-for-byte, and no
 * entry is ever fabricated, ranked, or re-ordered.
 */
export function projectSafeHigherOptions(
  active: LicenceActiveEntitlementTransportView,
): ReadonlyArray<LicenceSafeHigherOption> {
  const enterprisePlanId =
    active.Enterprise !== undefined && isRecordValue(active.Enterprise)
      ? (active.Enterprise as Record<string, unknown>).PlanId
      : undefined;
  const seen = new Set<string>();
  const options: LicenceSafeHigherOption[] = [];
  for (const raw of active.HigherOptions) {
    if (!isRecordValue(raw)) {
      continue; // structural failure is handled before this projection runs
    }
    const option = raw as unknown as LicenceHigherOptionView;
    // Standalone-call defense in depth: never project an entry whose required
    // safe text members are missing/unbounded (the builder already rejects the
    // whole view for such entries before calling this helper).
    if (
      !isBoundedText(option.PlanId, MAX_OPTION_TEXT_LENGTH) ||
      !isBoundedText(option.DisplayName, MAX_OPTION_TEXT_LENGTH) ||
      !isBoundedText(option.SafeDescription, MAX_SAFE_TEXT_LENGTH)
    ) {
      continue;
    }
    if (option.PlanId === active.PlanId) {
      continue; // current plan must never appear as a higher self-service option
    }
    if (typeof enterprisePlanId === 'string' && option.PlanId === enterprisePlanId) {
      continue; // Enterprise has no self-service activation path
    }
    if (seen.has(option.PlanId)) {
      continue; // ambiguous duplicate; first server occurrence wins
    }
    seen.add(option.PlanId);
    const safe: LicenceSafeHigherOption = {
      planId: option.PlanId,
      displayName: option.DisplayName,
      safeDescription: option.SafeDescription,
      ...(option.EligibleVoterCap !== undefined ? { eligibleVoterCap: option.EligibleVoterCap } : {}),
      ...(option.UnlimitedElections !== undefined ? { unlimitedElections: option.UnlimitedElections } : {}),
      ...(option.TermKind !== undefined ? { termKind: option.TermKind } : {}),
      ...(option.TermYears !== undefined ? { termYears: option.TermYears } : {}),
    };
    options.push(safe);
  }
  return options;
}

/** Informational Enterprise entry (null when the server sent none). */
export function projectSafeEnterprise(
  active: LicenceActiveEntitlementTransportView,
): LicenceSafeEnterprise | null {
  if (
    active.Enterprise === undefined ||
    !isRecordValue(active.Enterprise) ||
    !isBoundedText(active.Enterprise.PlanId) ||
    !isBoundedText(active.Enterprise.DisplayName) ||
    !isBoundedText(active.Enterprise.SafeDescription)
  ) {
    return null;
  }
  const enterprise = active.Enterprise as unknown as {
    PlanId: string;
    DisplayName: string;
    SafeDescription: string;
  };
  return {
    planId: enterprise.PlanId,
    displayName: enterprise.DisplayName,
    safeDescription: enterprise.SafeDescription,
  };
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
  if (!isBoundedText(active.SafeDescription)) {
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
  if (
    active.TermYears !== undefined &&
    (!Number.isInteger(active.TermYears) ||
      active.TermYears < 0 ||
      active.TermYears > Number.MAX_SAFE_INTEGER)
  ) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (
    active.EligibleVoterCap !== undefined &&
    (!Number.isInteger(active.EligibleVoterCap) ||
      active.EligibleVoterCap < 0 ||
      active.EligibleVoterCap > Number.MAX_SAFE_INTEGER)
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
  if (active.HigherOptions.some((option) => !isRecordValue(option) || !isStructurallyValidOption(option))) {
    return { ok: false, reason: 'malformed-required-field' };
  }
  if (
    active.Enterprise !== undefined &&
    (!isRecordValue(active.Enterprise) ||
      !isBoundedText(active.Enterprise.PlanId) ||
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
    safeDescription: active.SafeDescription,
    effectiveFromUtc: active.EffectiveFromUtc,
    expiresAtUtc: active.ExpiresAtUtc,
    termKind: active.TermKind,
    termYears: active.TermYears,
    eligibleVoterCap: active.EligibleVoterCap,
    unlimitedElections: active.UnlimitedElections,
    allowedGovernanceOptionIds: [...active.AllowedGovernanceOptionIds],
    catalogueVersion: active.AssignedCatalogueVersion,
    higherOptions: projectSafeHigherOptions(active),
    enterprise: projectSafeEnterprise(active),
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
    safeDescription: projection.safeDescription,
    effectiveFromUtc: projection.effectiveFromUtc,
    expiresAtUtc: projection.expiresAtUtc,
    termKind: projection.termKind,
    termYears: projection.termYears,
    eligibleVoterCap: projection.eligibleVoterCap,
    unlimitedElections: projection.unlimitedElections,
    allowedGovernanceOptionIds: projection.allowedGovernanceOptionIds,
    catalogueVersion: projection.catalogueVersion,
    higherOptions: projection.higherOptions.map((option) => ({
      planId: option.planId,
      displayName: option.displayName,
      safeDescription: option.safeDescription,
      eligibleVoterCap: option.eligibleVoterCap,
      unlimitedElections: option.unlimitedElections,
      termKind: option.termKind,
      termYears: option.termYears,
    })),
    enterprise:
      projection.enterprise === null
        ? null
        : {
            planId: projection.enterprise.planId,
            displayName: projection.enterprise.displayName,
            safeDescription: projection.enterprise.safeDescription,
          },
    provenance: projection.provenance,
  };
}
