/**
 * FEAT-017 Task 5.3 — N0 persistent global pending control and N1 one-time
 * activation notification (authenticated top bar region).
 *
 * N0 is reachable while the Account flyout is closed and while the user works
 * anywhere under the old indexed limits; hidden while already on the
 * operation's own progress surface. It never submits, retries, or creates a
 * selection — it only reopens the same authority-owned operation.
 *
 * N1 is the one-shot polite activation message shown while the user is
 * elsewhere. It never moves focus, never redirects, and never repeats; it is
 * absent when the result/progress surface already shows success and never
 * claims a competing-device activation as local success.
 */

import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import type {
  LicenceActivationNotificationFacts,
  LicencePendingIndicatorFacts,
} from '../../../lib/licensing/upgrade-presentation';

export function PendingUpgradeIndicator({
  facts,
  onViewProgress,
}: {
  readonly facts: LicencePendingIndicatorFacts;
  readonly onViewProgress: () => void;
}) {
  if (!facts.visible || facts.visibleLabel === null || facts.accessibleLabel === null) {
    return null;
  }
  return (
    <button
      type="button"
      className="licence-pending-indicator"
      aria-label={facts.accessibleLabel}
      onClick={onViewProgress}
      data-testid="pending-upgrade-indicator"
    >
      <span aria-hidden="true" className="licence-pending-glyph">
        •
      </span>
      <span className="licence-pending-label">{facts.visibleLabel}</span>
    </button>
  );
}

export function LicenceActivationNotification({
  facts,
  onViewLicence,
  onDismiss,
}: {
  readonly facts: LicenceActivationNotificationFacts;
  readonly onViewLicence: () => void;
  readonly onDismiss: () => void;
}) {
  if (!facts.visible || facts.message === null) {
    return null;
  }
  return (
    <div
      className="licence-activation-notification"
      aria-label={facts.message}
      data-testid="licence-activation-notification"
    >
      <p className="licence-notification-message" role="status" aria-live="polite" data-testid="licence-notification-message">
        {facts.message}
      </p>
      <div className="licence-notification-actions">
        <button type="button" className="licence-notification-link" onClick={onViewLicence}>
          {licenceUpgradeCopy('actionViewLicence')}
        </button>
        <button type="button" className="licence-notification-dismiss" onClick={onDismiss}>
          {licenceUpgradeCopy('actionDismiss')}
        </button>
      </div>
    </div>
  );
}
