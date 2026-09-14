/**
 * FEAT-017 Task 6.1 — authenticated licence root content region (controlled).
 *
 * AuthRoot holds the licence workspace open flag (shared with the Account
 * menu action) and passes it here. This component composes N0/N1 and the
 * full-width LicenceWorkspace page, or falls back to the default operational
 * workspace children under the old indexed limits (D017-01).
 *
 * All rendering is projected from the closed `LicenceUpgradePresentationInput`;
 * actions forward to real root intents (never a page-owned signer/loop).
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…06; Task 6.1.
 */

import type { LicenceUpgradePresentationInput, LicenceCurrentSurface } from '../../lib/licensing/upgrade-presentation';
import { LicenceWorkspaceHost } from './licence/licence-workspace-host';
import { TopBarLicenceSurfaces, createWebClipboardAdapter } from './licence/top-bar-surfaces';

export interface LicenceRootActions {
  readonly onActivate: (targetPlanId: string) => void;
  readonly onRetryExact: () => void;
  readonly onAcknowledgeOutcome: () => void;
  readonly onRefreshForEntry: () => void;
}

/**
 * Resolve the current surface for N0/N1 placement. N0 hides while the user is
 * on the operation's own progress surface; N1 hides when result/progress
 * already surface success.
 */
export function currentSurfaceForOpen(
  open: boolean,
  input: LicenceUpgradePresentationInput | null,
): LicenceCurrentSurface {
  if (!open || input === null) {
    return 'workspace';
  }
  const operation = input.upgradeOperation;
  if (operation !== null && (operation.status === 'pending' || operation.status === 'delayed')) {
    return 'licence-progress';
  }
  if (operation !== null && operation.status === 'local-success') {
    return 'licence-result';
  }
  return 'licence-options';
}

export function AuthenticatedLicenceRoot({
  input,
  actions,
  open,
  onClose,
  children,
}: {
  readonly input: LicenceUpgradePresentationInput | null;
  readonly actions: LicenceRootActions;
  /** Whether the full-width licence workspace is the current destination. */
  readonly open: boolean;
  readonly onClose: () => void;
  /** Default operational workspace content (kept under old indexed limits). */
  readonly children: React.ReactNode;
}) {
  const surface = currentSurfaceForOpen(open, input);

  return (
    <>
      {input !== null ? (
        <div className="licence-topbar-region" data-testid="licence-topbar-region">
          <TopBarLicenceSurfaces
            input={input}
            currentSurface={surface}
            onViewProgress={() => actions.onRefreshForEntry()}
            onViewLicence={() => actions.onAcknowledgeOutcome()}
            onDismiss={() => actions.onAcknowledgeOutcome()}
          />
        </div>
      ) : null}

      {open && input !== null ? (
        <LicenceWorkspaceHost
          input={input}
          visible
          actions={{
            onActivate: actions.onActivate,
            onRetryExact: actions.onRetryExact,
            onAcknowledgeOutcome: actions.onAcknowledgeOutcome,
            onRefreshForEntry: actions.onRefreshForEntry,
            onClose,
          }}
          onCopyReference={createWebClipboardAdapter()}
        />
      ) : (
        children
      )}
    </>
  );
}
