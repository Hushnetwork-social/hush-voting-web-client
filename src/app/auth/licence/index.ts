/**
 * FEAT-017 licence UI module — public surface (Phase 5).
 *
 * Exposes the closed presentational surfaces driven by the Phase-4 licence
 * presentation facts. Phase 6 composes these into the authenticated root
 * shell and real Web/native authorities; every component stays a thin
 * renderer (no state, no authority, no raw material).
 */

export {
  AccountLicenceSummary,
  accountActionLabel,
  accountSummaryReference,
  type LicenceAccountActionKind,
} from './account-licence-summary';
export { CurrentLicenceDetail } from './current-licence-detail';
export { EnterpriseInformation, HigherLicenceOption } from './licence-options';
export { LicenceOptionsView, NoHigherOptions } from './options-view';
export {
  LicenceConfirmationSurface,
  LicenceDelayedSurface,
  LicenceProgressSurface,
  LicenceResultSurface,
  LicenceStaleSurface,
} from './workspace-surfaces';
export { LicenceWorkspace } from './licence-workspace';
export {
  LicenceActivationNotification,
  PendingUpgradeIndicator,
} from './notifications';
export { LicenceReferenceFull, ShortLicenceReference } from './licence-reference';
export type { LicenceReferenceCopyHandler } from './licence-reference';
export type { LicenceWorkspaceActionHandlers } from './workspace-handlers';
