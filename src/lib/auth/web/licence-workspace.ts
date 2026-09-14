/**
 * FEAT-017 Task 6.1 — page-side licence workspace composition (Web root).
 *
 * Framework-neutral helpers that turn the SAFE authority mirror (the
 * EntitlementBridge licence facts: coordinator phase, indexed projection,
 * page-safe confirmed-upgrade operation, one-shot notification eligibility)
 * plus the machine projection (entitlement stage, connectivity, epoch,
 * protected access) into the closed `LicenceUpgradePresentationInput` the
 * pure presentation layer consumes.
 *
 * View/draft/back semantics are intentionally NOT re-implemented here: the
 * pure presentation model (upgrade-presentation.ts, D017-04/01) already owns
 * restored-surface, back-verdict, focus, and announcement rules. The root
 * composition only decides open/closed and which surface the user asked to
 * see; everything else stays authority-derived.
 *
 * The controller NEVER signs, journals, stores, polls, or authorizes. No
 * licence identifier is persisted or placed in history/URL; Back/reload
 * restore from authority state only.
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…06 + recovery
 * contract; planning-analysis-report §6; Task 6.1 behavior spec.
 */

import type { AuthRenderProjection } from '../react/adapter';
import type { LicenceUpgradePresentationInput } from '../../licensing/upgrade-presentation';
import type { LicenceSafeProjection } from '../../licensing/projection';
import type { LicenceUpgradeSafeOperation } from '../../licensing/session-contract';

/**
 * Closed page-safe licence facts mirror (structural subset of the worker
 * progress snapshot the page is allowed to render).
 */
export interface LicenceWorkspaceFactsMirror {
  readonly phase: string;
  readonly projection: unknown;
  readonly upgradeOperation: unknown;
  readonly upgradeNotificationEligible: boolean;
}

/**
 * Derive the closed presentation input from the safe mirror + machine
 * projection. Connectivity comes from the machine connectivity authority;
 * the presentation `phase` is the machine entitlement substage the machine
 * already validated (never raw worker phase strings beyond the closed
 * mapping). Returns null while no protected projection exists.
 */
export function presentationInputFromMirror(input: {
  readonly mirror: LicenceWorkspaceFactsMirror | null;
  readonly projection: AuthRenderProjection | null;
}): LicenceUpgradePresentationInput | null {
  const { mirror, projection } = input;
  if (mirror === null || projection === null || projection.entitlementStage === null) {
    return null;
  }
  const safeProjection =
    mirror.projection !== null && typeof mirror.projection === 'object'
      ? (mirror.projection as LicenceSafeProjection)
      : null;
  const operation =
    mirror.upgradeOperation !== null && typeof mirror.upgradeOperation === 'object'
      ? (mirror.upgradeOperation as LicenceUpgradeSafeOperation)
      : null;
  return {
    phase: projection.entitlementStage as LicenceUpgradePresentationInput['phase'],
    projection: safeProjection,
    upgradeOperation: operation,
    upgradeNotificationEligible: mirror.upgradeNotificationEligible === true,
    connectivity: projection.connectivity,
  };
}

/**
 * Closed reasons a user may open the full-width licence workspace. The root
 * renders the SAME Licence page for all of them; the presented surface is
 * then derived from authority state (pending → progress, result → result,
 * stale → stale, fresh truth → options).
 */
export type LicenceWorkspaceOpenReason =
  | 'upgrade' // Account A0 action when higher options exist
  | 'view-licence' // Account A0 action when no higher plan / Enterprise current
  | 'view-progress' // N0/Account A0P while a live operation is pending
  | 'notification' // N1 one-time activation notification (View licence)
  | 'pending-indicator'; // N0 reopen

export const LICENCE_WORKSPACE_OPEN_REASONS: readonly LicenceWorkspaceOpenReason[] = [
  'upgrade',
  'view-licence',
  'view-progress',
  'notification',
  'pending-indicator',
] as const;

export function isLicenceWorkspaceOpenReason(value: unknown): value is LicenceWorkspaceOpenReason {
  return (
    typeof value === 'string' &&
    (LICENCE_WORKSPACE_OPEN_REASONS as readonly string[]).includes(value)
  );
}
