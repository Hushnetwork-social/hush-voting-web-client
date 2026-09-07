/**
 * FEAT-016 Task 6.3 + FEAT-017 Task 2.3 — entitlement session contract
 * (shared, page-safe).
 *
 * The closed vocabulary exchanged between the page composition bridge and the
 * SharedWorker/native authority for the entitlement bootstrap and (FEAT-017)
 * the confirmed-upgrade operation. Page code may import this module; it
 * carries NO secret or exact-bytes material — only safe snapshots, progress,
 * and typed control intents.
 *
 * FEAT-017 upgrade-operation snapshots (below) are the safe presentation
 * vocabulary for one sealed confirmed-upgrade operation: statuses `pending`,
 * `delayed`, `stale`, `local-success` and `competing-activation`, each with
 * safe identity/display facts resolved by the authority from validated fresh
 * data. Exact bytes, signatures, key material, journal state, vault handles,
 * endpoints, and free-form server text are structurally absent.
 *
 * Normative source: FEAT-016 FeatureDescription "Web" (one SharedWorker-owned
 * loop; safe progress/projection only), "Authority and Target Composition",
 * "Security, Privacy, Performance, and Observability"; FEAT-017 FeatureDescription
 * D017-01…06 + recovery contract; planning-analysis-report §6.
 */

import type { EntitlementPhase } from './coordinator';
import type { LicenceSafeProjection } from './projection';

/** Safe snapshot a page may render (never secrets/bytes/journal state). */
export interface LicenceBootstrapSnapshot {
  readonly phase: EntitlementPhase;
  /** Runtime-memory-only safe projection; null until compatible active truth. */
  readonly projection: LicenceSafeProjection | null;
  readonly lastOutcomeCode: string | null;
  /** Opaque pending transaction id when one exists (public on-chain ref). */
  readonly pendingTransactionId: string | null;
}

/** Closed page→authority control intents (retry/recovery/revalidation). */
export type LicenceBootstrapControlKind = 'retry' | 'recover' | 'revalidate';

/** Revalidation trigger vocabulary (closed; bounds the payload). */
export type LicenceRevalidationTrigger =
  | 'foreground'
  | 'reconnect'
  | 'expiry'
  | 'account-entry'
  | 'authoritative-rejection'
  | 'explicit-recovery';

/** Closed connectivity inputs forwarded from the page connectivity authority. */
export type LicenceConnectivityInput = 'online' | 'offline' | 'paused' | 'reconnecting';

/** Eligibility inputs for the authority-owned reconciliation loop. */
export interface LicenceBootstrapEligibility {
  readonly foregrounded?: boolean;
  readonly connectivity?: LicenceConnectivityInput;
}

/** Worker→page progress event payload (additive protocol event). */
export interface LicenceProgressPayload extends LicenceBootstrapSnapshot {
  /** Epoch at emission time (page-side filtering; not an authority secret). */
  readonly emittedAtMs: number;
}

/** Safe outcome payload of a bootstrap step (returned by every licence op). */
export type LicenceBootstrapStepResult =
  | { readonly ok: true; readonly snapshot: LicenceBootstrapSnapshot }
  | { readonly ok: false; readonly reason: 'not-authenticated' | 'invalid-input' | 'authority-unavailable' };

// ---------------------------------------------------------------------------
// FEAT-017 confirmed-upgrade operation snapshot vocabulary (page-safe).
// ---------------------------------------------------------------------------

/**
 * Closed status vocabulary of one confirmed-upgrade operation as the page may
 * observe it. Transitions between statuses are driven by the coordinator
 * (Phase 3) against indexed truth; this module only pins the data model.
 */
export type LicenceUpgradeOperationStatus =
  | 'pending' // sealed; awaiting indexed match while the old licence stays current
  | 'delayed' // 30 s advancing-chain or paused-chain reached; exact Retry available
  | 'stale' // current licence/catalogue changed or typed stale rejection; fresh review required
  | 'local-success' // indexed originating UUID matches the sealed operation
  | 'competing-activation'; // authoritative different reference activated; obsolete pending retired

export const LICENCE_UPGRADE_OPERATION_STATUSES: readonly LicenceUpgradeOperationStatus[] = [
  'pending',
  'delayed',
  'stale',
  'local-success',
  'competing-activation',
] as const;

export function isLicenceUpgradeOperationStatus(
  value: unknown,
): value is LicenceUpgradeOperationStatus {
  return (
    typeof value === 'string' &&
    (LICENCE_UPGRADE_OPERATION_STATUSES as readonly string[]).includes(value)
  );
}

/**
 * Closed reason vocabulary for the `stale` snapshot (drives the S0 copy and
 * the requirement to review updated options and select again).
 */
export type LicenceUpgradeStaleReason =
  | 'current-changed'
  | 'catalogue-changed'
  | 'stale-rejection';

export function isLicenceUpgradeStaleReason(value: unknown): value is LicenceUpgradeStaleReason {
  return value === 'current-changed' || value === 'catalogue-changed' || value === 'stale-rejection';
}

/**
 * Safe identity facts of one sealed confirmed-upgrade operation. Display name
 * resolution is NOT stored here: the authority resolves display facts from
 * validated fresh data at snapshot time, so this identity never carries stale
 * or invented copy. No exact bytes, signature, journal state, or custody
 * binding is representable.
 */
export interface LicenceUpgradeOperationIdentity {
  /** Public on-chain reference of the sealed upgrade transaction. */
  readonly pendingTransactionId: string;
  /** Old current plan bound at seal time (FEAT-012 stable id). */
  readonly expectedCurrentPlanId: string;
  /** Requested target plan bound at seal time. */
  readonly targetPlanId: string;
  /** Immutable catalogue release used to present the transition. */
  readonly observedCatalogueVersion: string;
  /** UTC seal instant. */
  readonly sealedAtUtc: string;
}

interface LicenceUpgradeSafeOperationCommon {
  readonly kind: 'licence-upgrade-safe-operation';
  /** Sealed operation identity; null when nothing is sealed (pre-activation). */
  readonly operation: LicenceUpgradeOperationIdentity | null;
  /** Authoritative current plan id from the latest indexed truth (null when none). */
  readonly currentPlanId: string | null;
  /** Authoritative current plan display from validated fresh data. */
  readonly currentPlanDisplayName: string | null;
  /** Target plan display from validated fresh data (nullable pre-resolution). */
  readonly targetPlanDisplayName: string | null;
}

/**
 * Page-safe upgrade operation snapshot. `pending`/`delayed`/`local-success`/
 * `competing-activation` are the operation-lifecycle outcomes; `stale`
 * additionally carries the closed reason that requires a fresh review.
 */
export type LicenceUpgradeSafeOperation =
  | (LicenceUpgradeSafeOperationCommon & { readonly status: 'pending' })
  | (LicenceUpgradeSafeOperationCommon & { readonly status: 'delayed' })
  | (LicenceUpgradeSafeOperationCommon & {
      readonly status: 'stale';
      readonly reason: LicenceUpgradeStaleReason;
    })
  | (LicenceUpgradeSafeOperationCommon & { readonly status: 'local-success' })
  | (LicenceUpgradeSafeOperationCommon & { readonly status: 'competing-activation' });

/**
 * Closed pure builder for upgrade-operation snapshots. Consumers (Phase 3
 * coordinator/authority) construct snapshots only through this function, so a
 * snapshot can never carry exact bytes, signatures, journal state, bindings,
 * or free-form text by construction. Returns a typed rejection for impossible
 * status/field combinations.
 */
export function buildLicenceUpgradeSafeOperation(input: {
  readonly status: LicenceUpgradeOperationStatus;
  readonly operation?: LicenceUpgradeOperationIdentity | null;
  readonly currentPlanId?: string | null;
  readonly currentPlanDisplayName?: string | null;
  readonly targetPlanDisplayName?: string | null;
  readonly reason?: LicenceUpgradeStaleReason;
}):
  | { readonly ok: true; readonly snapshot: LicenceUpgradeSafeOperation }
  | { readonly ok: false; readonly reason: 'invalid-input' } {
  if (!isLicenceUpgradeOperationStatus(input.status)) {
    return { ok: false, reason: 'invalid-input' };
  }
  // `reason` is legal only on the stale arm.
  if (input.status !== 'stale' && input.reason !== undefined) {
    return { ok: false, reason: 'invalid-input' };
  }
  // pending/delayed describe a live sealed operation awaiting indexed truth.
  if (
    (input.status === 'pending' || input.status === 'delayed') &&
    (input.operation === undefined || input.operation === null)
  ) {
    return { ok: false, reason: 'invalid-input' };
  }
  const base: LicenceUpgradeSafeOperationCommon = {
    kind: 'licence-upgrade-safe-operation',
    operation: input.operation ?? null,
    currentPlanId: input.currentPlanId ?? null,
    currentPlanDisplayName: input.currentPlanDisplayName ?? null,
    targetPlanDisplayName: input.targetPlanDisplayName ?? null,
  };
  if (input.status === 'stale') {
    if (!isLicenceUpgradeStaleReason(input.reason)) {
      return { ok: false, reason: 'invalid-input' };
    }
    return { ok: true, snapshot: { ...base, status: 'stale', reason: input.reason } };
  }
  return { ok: true, snapshot: { ...base, status: input.status } };
}

/** Closed op outcome codes the authority may surface for licence steps. */
export type LicenceBootstrapOpOutcome = 'OK' | 'INVALID_INPUT' | 'AUTHORITY_REJECTED';

export const LICENCE_REVALIDATION_TRIGGERS: readonly LicenceRevalidationTrigger[] = [
  'foreground',
  'reconnect',
  'expiry',
  'account-entry',
  'authoritative-rejection',
  'explicit-recovery',
] as const;

export function isLicenceRevalidationTrigger(value: unknown): value is LicenceRevalidationTrigger {
  return typeof value === 'string' && (LICENCE_REVALIDATION_TRIGGERS as readonly string[]).includes(value);
}

export function isLicenceConnectivityInput(value: unknown): value is LicenceConnectivityInput {
  return value === 'online' || value === 'offline' || value === 'paused' || value === 'reconnecting';
}

export function isLicenceBootstrapControlKind(value: unknown): value is LicenceBootstrapControlKind {
  return value === 'retry' || value === 'recover' || value === 'revalidate';
}
