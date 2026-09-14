/**
 * FEAT-017 Task 6.1 — authenticated top-bar licence surfaces (N0/N1) and
 * clipboard adapter hook for the root Web composition.
 *
 * N0 (persistent pending control) and N1 (one-time activation notification)
 * are mounted by the authenticated root shell next to the Account menu. They
 * project from the same closed `LicenceUpgradePresentationInput` the
 * workspace uses and forward their real actions (view progress / view
 * licence / dismiss → acknowledge) to the root licence actions.
 *
 * The clipboard hook is the Web write adapter (integration-owned): it calls
 * `navigator.clipboard.writeText` and returns a boolean so the reference
 * component can announce the exact success/failure copy. Failure keeps the
 * full reference selectable (component contract). Native targets swap this
 * adapter in the target composition (no Browser fallback there).
 *
 * Normative source: FEAT-017 FeatureDescription D017-02/03; design contract
 * N0/N1; Task 6.1 behavior spec.
 */

import type { LicenceUpgradePresentationInput } from '../../../lib/licensing/upgrade-presentation';
import {
  projectActivationNotification,
  projectPendingIndicator,
  type LicenceActivationNotificationFacts,
  type LicenceCurrentSurface,
  type LicencePendingIndicatorFacts,
} from '../../../lib/licensing/upgrade-presentation';
import { PendingUpgradeIndicator, LicenceActivationNotification } from './notifications';

/** N0 + N1 projection pair for the current surface (one pure call each). */
export function projectTopBarLicenceSurfaces(
  input: LicenceUpgradePresentationInput | null,
  currentSurface: LicenceCurrentSurface,
): { pending: LicencePendingIndicatorFacts; notification: LicenceActivationNotificationFacts } {
  if (input === null) {
    return {
      pending: { visible: false, visibleLabel: null, accessibleLabel: null, targetPlanName: null },
      notification: {
        visible: false,
        message: null,
        planName: null,
        viewLicenceAction: true,
        dismissAction: true,
        noFocusMovement: true,
        noRedirect: true,
        announceOnce: true,
      },
    };
  }
  return {
    pending: projectPendingIndicator(input, currentSurface),
    notification: projectActivationNotification(input, currentSurface),
  };
}

/** Web clipboard write adapter (integration-owned; never a secret sink). */
export function createWebClipboardAdapter(): (fullText: string) => Promise<boolean> {
  return async (fullText: string): Promise<boolean> => {
    try {
      await navigator.clipboard.writeText(fullText);
      return true;
    } catch {
      return false;
    }
  };
}

export function TopBarLicenceSurfaces({
  input,
  currentSurface,
  onViewProgress,
  onViewLicence,
  onDismiss,
}: {
  readonly input: LicenceUpgradePresentationInput | null;
  readonly currentSurface: LicenceCurrentSurface;
  readonly onViewProgress: () => void;
  readonly onViewLicence: () => void;
  readonly onDismiss: () => void;
}) {
  const { pending, notification } = projectTopBarLicenceSurfaces(input, currentSurface);
  return (
    <div className="licence-topbar-surfaces" data-testid="licence-topbar-surfaces">
      {pending.visible ? <PendingUpgradeIndicator facts={pending} onViewProgress={onViewProgress} /> : null}
      {notification.visible ? (
        <LicenceActivationNotification facts={notification} onViewLicence={onViewLicence} onDismiss={onDismiss} />
      ) : null}
    </div>
  );
}
