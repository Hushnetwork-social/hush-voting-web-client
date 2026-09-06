/**
 * FEAT-016 Task 2.1 — closed entitlement query and licence contracts.
 *
 * Framework-neutral (no React, Next.js, DOM, storage, transport, or
 * state-store dependencies). Pins the frozen FEAT-015 v1 vocabulary consumed
 * by the entitlement bootstrap:
 *
 *  - exactly three signed metadata headers and the `GetMyEntitlement` method;
 *  - the empty-business-request signed envelope
 *    `{actorAddress, method, request:{}, signedAt}` (ordinal deep sort, compact
 *    JSON, fresh UTC `signedAt`/signature per attempt — never a blockchain
 *    transaction and never a persisted pending record);
 *  - the sole licence payload kind GUID and canonical plan/catalogue ids;
 *  - the closed transport result shape produced by the same-origin BFF after
 *    binary-gRPC decoding (active / no-active / unavailable / typed statuses);
 *  - bounded transport view types whose malformed or unknown values must fail
 *    closed in the parser (never coerced, never fabricated).
 *
 * SECRET BOUNDARY: nothing here can represent a private key, mnemonic,
 * password, raw signature, exact transaction bytes, vault handle, endpoint,
 * or free-form server message. Query signatures live only inside the
 * credential authority; page state receives typed outcomes.
 *
 * Normative source: FEAT-015 (frozen signed-query contract, canonical payload
 * GUID `71370664-5eb4-4ce9-b96a-d7e7ffe53db5`, response mapping, stable result
 * vocabulary); FEAT-012 canonical catalogue release
 * `hushvoting-licence-catalogue/v1.0.0`; FEAT-016 FeatureDescription "Signed
 * Query Contract", "Root State-Machine Contract", "Security, Privacy,
 * Performance, and Observability"; planning-analysis-report §4, §6.
 */

/** Frozen signed-query metadata headers (exactly these three; no request ID). */
export const LICENCE_QUERY_SIGNATORY_HEADER = 'x-hush-licence-query-signatory' as const;
export const LICENCE_QUERY_SIGNED_AT_HEADER = 'x-hush-licence-query-signed-at' as const;
export const LICENCE_QUERY_SIGNATURE_HEADER = 'x-hush-licence-query-signature' as const;

export const LICENCE_QUERY_METHOD = 'GetMyEntitlement' as const;

/** Sole FEAT-015 licence assignment payload kind (frozen; never reinterpreted). */
export const LICENCE_ASSIGNMENT_PAYLOAD_KIND =
  '71370664-5eb4-4ce9-b96a-d7e7ffe53db5' as const;

/** Canonical plan and catalogue identifiers (FEAT-012 catalogue release v1.0.0). */
export const LICENCE_PLAN_DIRECT_FREE = 'hushvoting.direct.free' as const;
export const LICENCE_CATALOGUE_VERSION_V1 = 'hushvoting-licence-catalogue/v1.0.0' as const;

/** Baseline transition intent (FEAT-015 frozen payload member). */
export const LICENCE_TRANSITION_INTENT_BASELINE_FREE = 'baseline_free' as const;

/**
 * Client-recognized plan families published by the v1.0.0 catalogue. A server
 * active view whose family is outside this allowlist is a compatible-client
 * gate (unsupported), never Direct Free coercion.
 */
export const KNOWN_LICENCE_PLAN_FAMILIES = ['direct', 'veritas', 'enterprise'] as const;
export type LicencePlanFamily = (typeof KNOWN_LICENCE_PLAN_FAMILIES)[number];

/** Hard bounds (defense in depth; the parser and coordinator enforce them). */
export const LICENCE_MAX_SAFE_TEXT_LENGTH = 512 as const;
export const LICENCE_MAX_OPTION_COUNT = 64 as const;
export const LICENCE_TRANSACTION_ID_MAX_LENGTH = 128 as const;
export const LICENCE_MAX_JSON_BYTES = 65_536 as const;

/** Bounded stable unavailable-code vocabulary surfaced by the server mapping. */
export const KNOWN_UNAVAILABLE_CODES = [
  'licence_index_unavailable',
  'licence_authority_unavailable',
] as const;
export type LicenceUnavailableCode = (typeof KNOWN_UNAVAILABLE_CODES)[number];

/** gRPC/transport statuses the BFF maps to typed outcomes (no free-form text). */
export type LicenceTransportStatus =
  | 'UNAUTHENTICATED'
  | 'PERMISSION_DENIED'
  | 'INVALID_ARGUMENT'
  | 'UNIMPLEMENTED'
  | 'DEADLINE_EXCEEDED'
  | 'UNAVAILABLE'
  | 'UNKNOWN';

/** Opaque licence transaction reference (public on-chain; not a secret). */
export type LicenceReference = string & { readonly __licenceReference: unique symbol };

/** Opaque canonical actor binding (invariant-lower signatory address). */
export type LicenceActorBinding = string & { readonly __licenceActorBinding: unique symbol };

/** Opaque deployment/network manifest binding (closed target/network id). */
export type LicenceNetworkBinding = string & { readonly __licenceNetworkBinding: unique symbol };

/**
 * One fresh query envelope for the signed metadata. Produced anew for every
 * `GetMyEntitlement` attempt inside the credential authority with a new UTC
 * `signedAt` and signature; the business request is always empty.
 */
export interface LicenceFreshQueryEnvelope {
  readonly actorAddress: LicenceActorBinding;
  readonly method: typeof LICENCE_QUERY_METHOD;
  readonly request: Record<string, never>;
  readonly signedAt: string; // ISO-8601 UTC
  readonly signature: string; // compact base64 signature (authority-owned)
}

/** Canonical compact JSON of the fresh query envelope (ordinal deep sort). */
export function licenceQuerySignedJson(envelope: LicenceFreshQueryEnvelope): string {
  // Ordinal deep sort of {actorAddress, method, request:{}, signedAt}; compact.
  return `{"actorAddress":"${envelope.actorAddress}","method":"${envelope.method}","request":{},"signedAt":"${envelope.signedAt}"}`;
}

/** Server-returned Direct Free template (never client-authored). */
export interface LicenceDirectFreeTemplate {
  readonly TransitionIntent: 'baseline_free';
  readonly RequestedPlanId: typeof LICENCE_PLAN_DIRECT_FREE;
  readonly ObservedCatalogueVersion: string;
}

/** One higher/alternative option (safe, server-returned). */
export interface LicenceHigherOptionView {
  readonly PlanId: string;
  readonly DisplayName: string;
  readonly SafeDescription: string;
  readonly EligibleVoterCap?: number;
  readonly UnlimitedElections?: boolean;
  readonly TermKind?: string;
  readonly TermYears?: number;
}

/** Informational Enterprise assignment (future admin path; display-safe). */
export interface LicenceEnterpriseView {
  readonly PlanId: string;
  readonly DisplayName: string;
  readonly SafeDescription: string;
}

/**
 * Active entitlement transport view (decoded BFF payload). Field names mirror
 * the FEAT-015 response mapping; timestamps are UTC ISO-8601 strings.
 */
export interface LicenceActiveEntitlementTransportView {
  readonly LicenceReference: string;
  readonly PlanId: string;
  readonly PlanFamily: string;
  readonly DisplayName: string;
  readonly SafeDescription: string;
  readonly EligibleVoterCap?: number;
  readonly UnlimitedElections?: boolean;
  readonly TermKind?: string;
  readonly TermYears?: number;
  readonly EffectiveFromUtc: string;
  readonly ExpiresAtUtc?: string;
  readonly AssignedCatalogueVersion: string;
  readonly AllowedGovernanceOptionIds: ReadonlyArray<string>;
  readonly HigherOptions: ReadonlyArray<LicenceHigherOptionView>;
  readonly Enterprise?: LicenceEnterpriseView;
}

/** Successful query transport envelope (post-BFF decode). */
export type LicenceQueryTransportSuccess =
  | { readonly ok: true; readonly state: 'active'; readonly active: LicenceActiveEntitlementTransportView }
  | { readonly ok: true; readonly state: 'noActive'; readonly template: LicenceDirectFreeTemplate }
  | { readonly ok: true; readonly state: 'unavailable'; readonly code: string };

/** Failed/typed query transport result (no free-form server text crosses). */
export type LicenceQueryTransportFailure = {
  readonly ok: false;
  readonly status: LicenceTransportStatus;
};

/** Closed union consumed by the parser (produced by the BFF in Phase 6). */
export type LicenceQueryTransportResult = LicenceQueryTransportSuccess | LicenceQueryTransportFailure;
