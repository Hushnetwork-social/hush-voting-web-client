/**
 * FEAT-017 Task 5.1/5.3 — licence workspace action handlers contract shared by
 * every surface component. Phase 6 wires these to the root typed intents; the
 * UI only ever emits one of these deterministic actions.
 *
 * Plan selection (`onReviewPlan`) is NOT part of this bag: it is passed as a
 * dedicated prop to option surfaces so the two concerns (choosing an option vs
 * committing/leaving an operation) stay separate.
 */

export interface LicenceWorkspaceActionHandlers {
  /** Reopen the live progress surface from the options lock summary. */
  readonly onViewProgress: () => void;
  /** C0 in-app secondary: return to L1 with the draft retained. */
  readonly onBackToPlans: () => void;
  /** C0 primary: activate the exact sealed target. */
  readonly onActivate: () => void;
  /** P0/D0 leave: keep the authority operation; return to workspace. */
  readonly onContinueWorking: () => void;
  /** D0 exact retry. */
  readonly onRetry: () => void;
  /** R0 return to the operational workspace. */
  readonly onReturnToWorkspace: () => void;
  /** R0 open the refreshed licence detail. */
  readonly onViewCurrentLicence: () => void;
}
