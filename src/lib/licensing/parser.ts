/**
 * FEAT-016 Task 2.1 — closed entitlement response parser.
 *
 * Maps the closed BFF transport result to one deterministic, fail-closed
 * entitlement outcome. Expected validation failures are data, never
 * exceptions. The parser never invents a plan, never treats unavailable as
 * no-active, never coerces unknown values, and never lets free-form server
 * text cross the boundary.
 *
 * Normative source: FEAT-016 FeatureDescription "Signed Query Contract",
 * "Admission outcomes", "Offline and unavailable", "User Experience" (exact
 * state vocabulary); planning-analysis-report §6, §9.4.
 */

import {
  LICENCE_PLAN_DIRECT_FREE,
  LICENCE_TRANSITION_INTENT_BASELINE_FREE,
  type LicenceActorBinding,
  type LicenceNetworkBinding,
  type LicenceQueryTransportResult,
} from './contracts';
import { buildLicenceSafeProjection, type ProjectionRejectionReason } from './projection';
import type { LicenceSafeProjection } from './projection';
import type { LicenceDirectFreeTemplate } from './contracts';

/** Closed entitlement outcomes consumed by the coordinator/state machine. */
export type EntitlementQueryOutcome =
  | { readonly outcome: 'ready'; readonly projection: LicenceSafeProjection }
  | { readonly outcome: 'noActive'; readonly template: LicenceDirectFreeTemplate }
  | { readonly outcome: 'unavailable'; readonly code: string }
  | { readonly outcome: 'unauthenticated' }
  | { readonly outcome: 'permissionDenied' }
  | { readonly outcome: 'invalidArgument' }
  | { readonly outcome: 'unimplemented' }
  | { readonly outcome: 'transportFailure' }
  | {
      readonly outcome: 'unsupported';
      readonly reason: Extract<ProjectionRejectionReason, 'unknown-plan-family' | 'incompatible-catalogue-version'>;
    }
  | { readonly outcome: 'malformed' };

const MAX_SAFE_TEXT_LENGTH = 512;

function isBoundedString(value: unknown, max = MAX_SAFE_TEXT_LENGTH): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Validate the server no-active template shape (never client-authored). */
function parseNoActiveTemplate(value: unknown): LicenceDirectFreeTemplate | null {
  if (!isRecord(value)) {
    return null;
  }
  if (value.TransitionIntent !== LICENCE_TRANSITION_INTENT_BASELINE_FREE) {
    return null;
  }
  if (value.RequestedPlanId !== LICENCE_PLAN_DIRECT_FREE) {
    return null;
  }
  if (!isBoundedString(value.ObservedCatalogueVersion)) {
    return null;
  }
  return {
    TransitionIntent: LICENCE_TRANSITION_INTENT_BASELINE_FREE,
    RequestedPlanId: LICENCE_PLAN_DIRECT_FREE,
    ObservedCatalogueVersion: value.ObservedCatalogueVersion,
  };
}

/**
 * Parse one query transport result into the closed outcome vocabulary.
 * `actorBinding`/`networkBinding` are the authority-bound expectations the
 * safe projection is minted against (staleness/epoch enforcement is the
 * coordinator's job).
 */
export function parseEntitlementQueryResult(
  result: LicenceQueryTransportResult,
  actorBinding: LicenceActorBinding,
  networkBinding: LicenceNetworkBinding,
): EntitlementQueryOutcome {
  if (!isRecord(result)) {
    return { outcome: 'malformed' };
  }

  if (result.ok === false) {
    switch (result.status) {
      case 'UNAUTHENTICATED':
        return { outcome: 'unauthenticated' };
      case 'PERMISSION_DENIED':
        return { outcome: 'permissionDenied' };
      case 'INVALID_ARGUMENT':
        return { outcome: 'invalidArgument' };
      case 'UNIMPLEMENTED':
        return { outcome: 'unimplemented' };
      case 'UNAVAILABLE':
        return { outcome: 'unavailable', code: 'licence_authority_unavailable' };
      case 'DEADLINE_EXCEEDED':
      case 'UNKNOWN':
      default:
        return { outcome: 'transportFailure' };
    }
  }

  switch (result.state) {
    case 'active': {
      if (!isRecord(result.active)) {
        return { outcome: 'malformed' };
      }
      const built = buildLicenceSafeProjection(actorBinding, networkBinding, result.active);
      if (!built.ok) {
        if (
          built.reason === 'unknown-plan-family' ||
          built.reason === 'incompatible-catalogue-version'
        ) {
          return { outcome: 'unsupported', reason: built.reason };
        }
        return { outcome: 'malformed' };
      }
      return { outcome: 'ready', projection: built.projection };
    }
    case 'noActive': {
      const template = parseNoActiveTemplate(result.template);
      if (template === null) {
        return { outcome: 'malformed' };
      }
      return { outcome: 'noActive', template };
    }
    case 'unavailable': {
      if (!isBoundedString(result.code)) {
        return { outcome: 'malformed' };
      }
      return { outcome: 'unavailable', code: result.code };
    }
    default:
      return { outcome: 'malformed' };
  }
}
