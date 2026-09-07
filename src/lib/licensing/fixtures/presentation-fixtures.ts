/**
 * FEAT-017 Phase 4 — deterministic presentation fixtures built through the
 * CLOSED public builders only (safe projection builder + upgrade-operation
 * snapshot builder). Tests therefore exercise real structural invariants:
 * a fixture that would violate the safe boundary cannot be constructed.
 *
 * No secrets, signatures, exact bytes, bindings, or journal state are
 * representable in this file by construction.
 */

import type { LicenceActiveEntitlementTransportView, LicenceHigherOptionView } from '../contracts';
import { buildLicenceSafeProjection, type LicenceSafeProjection } from '../projection';
import {
  buildLicenceUpgradeSafeOperation,
  type LicenceUpgradeOperationStatus,
  type LicenceUpgradeSafeOperation,
  type LicenceUpgradeStaleReason,
} from '../session-contract';

/** Frozen FEAT-015/canonical test values shared with the FEAT-017 suites. */
export const CATALOGUE_V1 = 'hushvoting-licence-catalogue/v1.0.0';
export const ACTOR_BINDING = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
export const NETWORK_BINDING = 'hush-network-local-devnet-5195086';
export const DIRECT_FREE_REFERENCE = '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e';
export const UPGRADE_TRANSACTION_REFERENCE = '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55';
export const DIRECT_FREE_PLAN = 'hushvoting.direct.free';
export const VERITAS_500_PLAN = 'hushvoting.veritas.500';
export const VERITAS_2000_PLAN = 'hushvoting.veritas.2000';
export const VERITAS_10000_PLAN = 'hushvoting.veritas.10000';
export const ENTERPRISE_PLAN = 'hushvoting.enterprise';

/** Direct Free active transport view (perpetual, capped, unlimited elections). */
export function directFreeTransportView(
  overrides: Partial<LicenceActiveEntitlementTransportView> = {},
): LicenceActiveEntitlementTransportView {
  return {
    LicenceReference: DIRECT_FREE_REFERENCE,
    PlanId: DIRECT_FREE_PLAN,
    PlanFamily: 'direct',
    DisplayName: 'HushVoting! Direct Free',
    SafeDescription: 'A perpetual licence for admin-controlled elections.',
    EligibleVoterCap: 100,
    UnlimitedElections: true,
    TermKind: 'perpetual',
    TermYears: 0,
    EffectiveFromUtc: '2026-09-06T20:35:00.000Z',
    ExpiresAtUtc: undefined,
    AssignedCatalogueVersion: CATALOGUE_V1,
    AllowedGovernanceOptionIds: ['no-customer-trustees'],
    HigherOptions: [],
    ...overrides,
  };
}

/** One higher Veritas option transport record (annual, one-year term). */
export function higherOptionView(
  overrides: Partial<LicenceHigherOptionView> = {},
): LicenceHigherOptionView {
  return {
    PlanId: VERITAS_2000_PLAN,
    DisplayName: 'HushVoting! Veritas 2k',
    SafeDescription: 'Up to 2,000 voters',
    EligibleVoterCap: 2000,
    UnlimitedElections: true,
    TermKind: 'annual',
    TermYears: 1,
    ...overrides,
  };
}

/** Direct Free with the standard three higher Veritas options + Enterprise. */
export function directFreeWithOptionsTransportView(): LicenceActiveEntitlementTransportView {
  return directFreeTransportView({
    HigherOptions: [
      higherOptionView({ PlanId: VERITAS_500_PLAN, DisplayName: 'HushVoting! Veritas 500', EligibleVoterCap: 500 }),
      higherOptionView(),
      higherOptionView({ PlanId: VERITAS_10000_PLAN, DisplayName: 'HushVoting! Veritas 10k', EligibleVoterCap: 10000 }),
    ],
    Enterprise: {
      PlanId: ENTERPRISE_PLAN,
      DisplayName: 'HushVoting! Enterprise',
      SafeDescription: 'Customer-specific limits and approved custom n-of-k governance.',
    },
  });
}

/** Build a validated safe projection (fails the test on builder rejection). */
export function safeProjectionOf(
  view: LicenceActiveEntitlementTransportView,
): LicenceSafeProjection {
  const result = buildLicenceSafeProjection(
    ACTOR_BINDING as never,
    NETWORK_BINDING as never,
    view,
  );
  if (!result.ok) {
    throw new Error(`fixture projection rejected: ${result.reason}`);
  }
  return result.projection;
}

/** Direct Free current with all three higher options (typical L1 fixture). */
export function directFreeWithOptionsProjection(): LicenceSafeProjection {
  return safeProjectionOf(directFreeWithOptionsTransportView());
}

/** No-higher Direct Free projection (L2 fixture). */
export function directFreeNoHigherProjection(): LicenceSafeProjection {
  return safeProjectionOf(directFreeTransportView());
}

/** Enterprise-active projection (recognized current; no self-service target). */
export function enterpriseActiveProjection(): LicenceSafeProjection {
  return safeProjectionOf(
    directFreeTransportView({
      LicenceReference: 'a1b2c3d4-1111-4222-8333-444455556666',
      PlanId: ENTERPRISE_PLAN,
      PlanFamily: 'enterprise',
      DisplayName: 'HushVoting! Enterprise',
      SafeDescription: 'Customer-specific limits and approved custom n-of-k governance.',
    }),
  );
}

/** Veritas 2k annual active projection (post-indexed upgrade fixture). */
export function veritas2000ActiveProjection(): LicenceSafeProjection {
  return safeProjectionOf(
    directFreeTransportView({
      LicenceReference: UPGRADE_TRANSACTION_REFERENCE,
      PlanId: VERITAS_2000_PLAN,
      PlanFamily: 'veritas',
      DisplayName: 'HushVoting! Veritas 2k',
      SafeDescription: 'Up to 2,000 voters',
      EligibleVoterCap: 2000,
      TermKind: 'annual',
      TermYears: 1,
      EffectiveFromUtc: '2026-09-07T12:24:00.000Z',
      ExpiresAtUtc: '2027-09-07T12:24:00.000Z',
      AllowedGovernanceOptionIds: ['no-customer-trustees', 'trustees-3of5', 'trustees-7of10'],
      HigherOptions: [
        higherOptionView({ PlanId: VERITAS_10000_PLAN, DisplayName: 'HushVoting! Veritas 10k', EligibleVoterCap: 10000 }),
      ],
    }),
  );
}

/**
 * Build one page-safe upgrade-operation snapshot through the closed builder.
 * `pending`/`delayed` require a sealed operation identity; `local-success`,
 * `competing-activation`, and `stale` are terminals (operation optional).
 */
export function upgradeOperationOf(
  status: LicenceUpgradeOperationStatus,
  overrides: {
    readonly targetPlanId?: string;
    readonly targetPlanDisplayName?: string;
    readonly currentPlanId?: string | null;
    readonly currentPlanDisplayName?: string | null;
    readonly reason?: LicenceUpgradeStaleReason;
    readonly sealed?: boolean;
  } = {},
): LicenceUpgradeSafeOperation {
  const targetPlanId = overrides.targetPlanId ?? VERITAS_2000_PLAN;
  const targetPlanDisplayName = overrides.targetPlanDisplayName ?? 'HushVoting! Veritas 2k';
  const sealed =
    overrides.sealed ??
    (status === 'pending' || status === 'delayed' || status === 'local-success');
  const result = buildLicenceUpgradeSafeOperation({
    status,
    ...(sealed
      ? {
          operation: {
            pendingTransactionId: UPGRADE_TRANSACTION_REFERENCE,
            expectedCurrentPlanId: DIRECT_FREE_PLAN,
            targetPlanId,
            observedCatalogueVersion: CATALOGUE_V1,
            sealedAtUtc: '2026-09-07T12:00:00.000Z',
          },
        }
      : {}),
    currentPlanId: overrides.currentPlanId === undefined ? DIRECT_FREE_PLAN : overrides.currentPlanId,
    currentPlanDisplayName:
      overrides.currentPlanDisplayName === undefined
        ? 'HushVoting! Direct Free'
        : overrides.currentPlanDisplayName,
    targetPlanDisplayName,
    ...(status === 'stale' ? { reason: overrides.reason ?? 'current-changed' } : {}),
  });
  if (!result.ok) {
    throw new Error(`fixture upgrade snapshot rejected: ${result.reason}`);
  }
  return result.snapshot;
}

/** Deterministic user-local timezone for presentation tests. */
export const FIXTURE_TIME_ZONE = 'Europe/Lisbon';
