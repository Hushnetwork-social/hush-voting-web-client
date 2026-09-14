/**
 * FEAT-017 Phase 5 — deterministic component fixtures. Facts are ALWAYS built
 * through the closed Phase-2/3/4 public builders + presentation projections so
 * component tests exercise the same invariants as the lib suites (an unsafe
 * fixture cannot be constructed). No secrets/bytes/journal state here.
 */

import {
  CATALOGUE_V1,
  DIRECT_FREE_PLAN,
  DIRECT_FREE_REFERENCE,
  ENTERPRISE_PLAN,
  UPGRADE_TRANSACTION_REFERENCE,
  VERITAS_10000_PLAN,
  VERITAS_2000_PLAN,
  VERITAS_500_PLAN,
  directFreeNoHigherProjection,
  directFreeWithOptionsProjection,
  enterpriseActiveProjection,
  FIXTURE_TIME_ZONE,
  upgradeOperationOf,
  veritas2000ActiveProjection,
} from '../../../lib/licensing/fixtures/presentation-fixtures';
import type { LicenceSafeHigherOption } from '../../../lib/licensing/projection';
import type { LicenceDraftSelection } from '../../../lib/licensing/upgrade-presentation';
import {
  draftFromHigherOption,
  projectAccountLicenceSummary,
  projectConfirmationViewFacts,
  projectDelayedViewFacts,
  projectLicenceEntryViewFacts,
  projectLicenceWorkspaceViewFacts,
  projectOptionsViewFacts,
  projectPendingIndicator,
  projectProgressViewFacts,
  projectResultViewFacts,
  projectStaleViewFacts,
  type LicenceUpgradePresentationInput,
} from '../../../lib/licensing/upgrade-presentation';

export { FIXTURE_TIME_ZONE };

export function presentationInput(
  overrides: Partial<LicenceUpgradePresentationInput> = {},
): LicenceUpgradePresentationInput {
  return {
    phase: 'entitlementReady',
    projection: directFreeWithOptionsProjection(),
    upgradeOperation: null,
    upgradeNotificationEligible: false,
    connectivity: 'online',
    ...overrides,
  };
}

export function higherOptionOf(
  projection: ReturnType<typeof directFreeWithOptionsProjection>,
  planId: string,
): LicenceSafeHigherOption {
  const option = projection.higherOptions.find((candidate) => candidate.planId === planId);
  if (option === undefined) {
    throw new Error(`fixture higher option missing: ${planId}`);
  }
  return option;
}

export function draftFor(input: LicenceUpgradePresentationInput, planId: string): LicenceDraftSelection {
  const projection = input.projection;
  if (projection === null) {
    throw new Error('fixture requires a projection for draft');
  }
  return draftFromHigherOption(higherOptionOf(projection, planId));
}

export {
  directFreeNoHigherProjection,
  directFreeWithOptionsProjection,
  enterpriseActiveProjection,
  upgradeOperationOf,
  veritas2000ActiveProjection,
  CATALOGUE_V1,
  VERITAS_500_PLAN,
  VERITAS_2000_PLAN,
  VERITAS_10000_PLAN,
  ENTERPRISE_PLAN,
  DIRECT_FREE_PLAN,
  DIRECT_FREE_REFERENCE,
  UPGRADE_TRANSACTION_REFERENCE,
};

export function accountFacts(input: LicenceUpgradePresentationInput) {
  return projectAccountLicenceSummary(input, FIXTURE_TIME_ZONE);
}

export function optionsFacts(input: LicenceUpgradePresentationInput) {
  return projectOptionsViewFacts(input, FIXTURE_TIME_ZONE, null);
}

export function confirmationFacts(input: LicenceUpgradePresentationInput, planId: string) {
  const draft = draftFor(input, planId);
  return projectConfirmationViewFacts(input, draft, FIXTURE_TIME_ZONE);
}

export function progressFacts(input: LicenceUpgradePresentationInput) {
  return projectProgressViewFacts(input);
}

export function delayedFacts(input: LicenceUpgradePresentationInput) {
  return projectDelayedViewFacts(input);
}

export function resultFacts(input: LicenceUpgradePresentationInput) {
  return projectResultViewFacts(input, FIXTURE_TIME_ZONE);
}

export function staleFacts(input: LicenceUpgradePresentationInput) {
  return projectStaleViewFacts(input, FIXTURE_TIME_ZONE);
}

export function workspaceFacts(
  input: LicenceUpgradePresentationInput,
  view: 'options' | 'confirmation' | 'progress' | 'delayed' | 'result' | 'stale',
  planId?: string,
) {
  return projectLicenceWorkspaceViewFacts(
    input,
    view,
    planId !== undefined ? draftFor(input, planId) : null,
    FIXTURE_TIME_ZONE,
  );
}

export function pendingIndicatorFacts(
  input: LicenceUpgradePresentationInput,
  currentSurface: Parameters<typeof projectPendingIndicator>[1],
) {
  return projectPendingIndicator(input, currentSurface);
}

export function gateFacts(input: LicenceUpgradePresentationInput) {
  return projectLicenceEntryViewFacts(input);
}
