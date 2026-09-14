/**
 * FEAT-017 Task 3.1/3.3 — confirmed-upgrade construction and binding policy.
 *
 * Authority-side confirmed-upgrade counterpart of `direct-free.ts`. Builds the
 * canonical FEAT-015 `confirmed_upgrade` licence assignment envelope from
 * validated indexed facts ONLY: the expected old current licence reference and
 * plan (the FEAT-015 `ExpectedCurrent*` precondition), the requested target
 * plan, and the observed catalogue release. The payload is exactly
 * `{TransitionIntent: confirmed_upgrade, RequestedPlanId,
 * ObservedCatalogueVersion, ExpectedCurrentLicenceTransactionId,
 * ExpectedCurrentPlanId}` in the frozen FEAT-015 declaration order (see
 * `canonical.ts` `LicenceUpgradePayload`).
 *
 * The module also exposes the closed rule set used by the coordinator to tell a
 * sealed record apart from a baseline (payload transition intent + purpose
 * coherence guard) and to resolve display names ONLY from validated fresh
 * projection data at snapshot time (Phase 2 code-review recommendation #4: no
 * stale or invented copy).
 *
 * SECRET BOUNDARY: like `direct-free.ts`, this module is imported only by the
 * closed credential authorities (SharedWorker/native) and deterministic tests.
 * Page/React code never imports it; the returned `canonicalUnsignedJson` is an
 * unsigned staging envelope that only approved custody may sign and seal.
 *
 * Normative source: FEAT-017 FeatureDescription D017-03/D017-08 + recovery
 * contract (one purpose-bound sealed upgrade op; exact transaction identity;
 * strict fresh re-validation at Activate); FEAT-015 frozen
 * `confirmed_upgrade` payload corpus (LIC-FIX-002); planning-analysis-report
 * §5(f), §6.1.
 */

import {
  LICENCE_ASSIGNMENT_PAYLOAD_KIND,
  LICENCE_CATALOGUE_VERSION_V1,
  LICENCE_PLAN_DIRECT_FREE,
  LICENCE_TRANSITION_INTENT_CONFIRMED_UPGRADE,
} from './contracts';
import {
  licencePayloadSizeBytes,
  licenceTransactionDigest,
  serializeLicenceUnsignedTransaction,
  type LicenceUpgradePayload,
} from './canonical';
import type { LicencePendingTransactionRecord } from './pending-transaction';
import type { LicenceSafeProjection } from './projection';

/** Max id/text length mirrored from the pending-record codec bounds. */
const MAX_PLAN_ID_LENGTH = 128 as const;
const MAX_CATALOGUE_LENGTH = 256 as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

/** Validated inputs for one confirmed-upgrade envelope construction. */
export interface ConfirmedUpgradeBuildInput {
  /** Expected old current licence reference (public on-chain transaction UUID). */
  readonly expectedCurrentLicenceTransactionId: string;
  /** Expected old current plan id (FEAT-012 stable id). */
  readonly expectedCurrentPlanId: string;
  /** Requested strictly-higher Veritas target plan id (server-offered handle). */
  readonly requestedPlanId: string;
  /** Immutable catalogue release used to present the transition. */
  readonly observedCatalogueVersion: string;
  /** One exact transaction identity minted by the authority (uuid). */
  readonly transactionId: string;
  /** UTC ISO-8601 timestamp minted with the identity. */
  readonly transactionTimestampUtc: string;
}

export type ConfirmedUpgradeBuildResult =
  | {
      readonly ok: true;
      readonly payload: LicenceUpgradePayload;
      readonly payloadSize: number;
      readonly canonicalUnsignedJson: string;
      readonly digest: string;
    }
  | {
      readonly ok: false;
      readonly reason:
        | 'malformed-current-reference' // expected current is not a bounded UUID
        | 'malformed-plan-id' // empty/unbounded plan id
        | 'self-target-or-direct-free' // requested == expected or Direct Free target
        | 'stale-or-unbounded-catalogue' // empty/unbounded or not the v1 release
        | 'malformed-transaction-id' // transaction id is not a bounded UUID
        | 'alias-new-transaction' // new transaction id aliases the expected old reference
        | 'malformed-timestamp'; // timestamp is not a bounded UTC ISO-8601 stamp
}

function isBoundedText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

/**
 * Validate the parsed indexed facts and construct the canonical unsigned
 * `confirmed_upgrade` envelope with the exact transaction id + UTC timestamp
 * supplied by the authority (one transaction: one id/time). Rejection rules
 * mirror the pending-record codec cross-field guards so a builder output can
 * never produce a record the codec would refuse (self-target, Direct Free
 * target, unknown catalogue release, alias of the expected current reference).
 * `canonicalUnsignedJson` is byte-exact against the frozen FEAT-015 corpus for
 * the fixed inputs (LIC-FIX-002 asserted in `upgrade.test.ts`).
 */
export function buildConfirmedUpgradeUnsignedTransaction(
  input: ConfirmedUpgradeBuildInput,
): ConfirmedUpgradeBuildResult {
  if (
    !isBoundedText(input.expectedCurrentLicenceTransactionId, MAX_PLAN_ID_LENGTH) ||
    !UUID_RE.test(input.expectedCurrentLicenceTransactionId)
  ) {
    return { ok: false, reason: 'malformed-current-reference' };
  }
  if (
    !isBoundedText(input.expectedCurrentPlanId, MAX_PLAN_ID_LENGTH) ||
    !isBoundedText(input.requestedPlanId, MAX_PLAN_ID_LENGTH)
  ) {
    return { ok: false, reason: 'malformed-plan-id' };
  }
  if (
    input.requestedPlanId === input.expectedCurrentPlanId ||
    input.requestedPlanId === LICENCE_PLAN_DIRECT_FREE
  ) {
    return { ok: false, reason: 'self-target-or-direct-free' };
  }
  if (
    input.observedCatalogueVersion !== LICENCE_CATALOGUE_VERSION_V1 ||
    input.observedCatalogueVersion.length > MAX_CATALOGUE_LENGTH
  ) {
    return { ok: false, reason: 'stale-or-unbounded-catalogue' };
  }
  if (!isBoundedText(input.transactionId, MAX_PLAN_ID_LENGTH) || !UUID_RE.test(input.transactionId)) {
    return { ok: false, reason: 'malformed-transaction-id' };
  }
  if (input.transactionId === input.expectedCurrentLicenceTransactionId) {
    return { ok: false, reason: 'alias-new-transaction' };
  }
  if (!isBoundedText(input.transactionTimestampUtc, 64) || !ISO_UTC_RE.test(input.transactionTimestampUtc)) {
    return { ok: false, reason: 'malformed-timestamp' };
  }

  const payload: LicenceUpgradePayload = {
    TransitionIntent: LICENCE_TRANSITION_INTENT_CONFIRMED_UPGRADE,
    RequestedPlanId: input.requestedPlanId,
    ObservedCatalogueVersion: input.observedCatalogueVersion,
    ExpectedCurrentLicenceTransactionId: input.expectedCurrentLicenceTransactionId,
    ExpectedCurrentPlanId: input.expectedCurrentPlanId,
  };
  const payloadSize = licencePayloadSizeBytes(payload);
  const canonicalUnsignedJson = serializeLicenceUnsignedTransaction({
    TransactionId: input.transactionId,
    PayloadKind: LICENCE_ASSIGNMENT_PAYLOAD_KIND,
    TransactionTimeStamp: input.transactionTimestampUtc,
    Payload: payload,
    PayloadSize: payloadSize,
  });
  return {
    ok: true,
    payload,
    payloadSize,
    canonicalUnsignedJson,
    digest: licenceTransactionDigest(canonicalUnsignedJson),
  };
}

/** True when the value is a bounded candidate plan id (input guard). */
export function isBoundedPlanId(value: unknown): value is string {
  return isBoundedText(value, MAX_PLAN_ID_LENGTH);
}

/**
 * Read the frozen transition intent of a sealed/staged pending record payload.
 * Authority-side only: `record.transaction.exactJson` exists only inside
 * approved custody. Returns `null` when the envelope cannot be parsed — the
 * coordinator treats that as an incoherent record and fails closed.
 */
export function licenceTransitionIntentOfPendingRecord(
  record: LicencePendingTransactionRecord,
): 'baseline_free' | 'confirmed_upgrade' | null {
  try {
    const envelope = JSON.parse(record.transaction.exactJson) as {
      Payload?: { TransitionIntent?: unknown };
    };
    const intent = envelope.Payload?.TransitionIntent;
    return intent === 'confirmed_upgrade' || intent === 'baseline_free' ? intent : null;
  } catch {
    return null;
  }
}

/**
 * Closed coherence guard (Phase 2 code-review recommendation #3): a pending
 * record whose exact payload intent is `confirmed_upgrade` MUST carry the
 * additive `upgradeBinding` member. An upgrade record opened without its
 * binding must never be resubmitted as a baseline — the record codec would
 * otherwise read it as a baseline and the authority could construct a Direct
 * Free operation on top of a sealed upgrade. A baseline record (or an
 * unreadable envelope) must never carry a binding.
 */
export function isPendingRecordPurposeCoherent(record: LicencePendingTransactionRecord): boolean {
  const intent = licenceTransitionIntentOfPendingRecord(record);
  if (intent === 'confirmed_upgrade') {
    return record.upgradeBinding !== undefined;
  }
  if (intent === 'baseline_free') {
    return record.upgradeBinding === undefined;
  }
  // Unreadable/corrupt envelope: never submitable under any purpose.
  return false;
}

/**
 * Resolve the display name of a sealed upgrade target plan from validated
 * fresh projection data ONLY (Phase 2 code-review recommendation #4). A target
 * that has just become the current plan is read from the current display
 * (projection.planId === target); otherwise the target must still be a
 * server-offered higher option of the current truth. Any other case returns
 * null — never a stale or invented name.
 */
export function resolveUpgradeTargetDisplayName(
  projection: LicenceSafeProjection | null,
  targetPlanId: string,
): string | null {
  if (projection === null) {
    return null;
  }
  if (projection.planId === targetPlanId) {
    return projection.displayName;
  }
  const offered = projection.higherOptions.find((option) => option.planId === targetPlanId);
  return offered === undefined ? null : offered.displayName;
}
