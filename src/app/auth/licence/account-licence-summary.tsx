/**
 * FEAT-017 Task 5.1 — Account flyout licence summary (A0 / A0P).
 *
 * Consumes the closed `LicenceAccountSummaryFacts` projection (Phase 4). The
 * flyout's existing identity copy, focus containment/restoration, outside/
 * Escape dismissal, and Lock behavior are NOT re-implemented here — this block
 * only contributes the licence facts region rendered inside the popup.
 *
 * `available=false` renders nothing: Account must never keep stale licence
 * values behind a loading/unavailable layer (D017 recovery contract). A live
 * pending upgrade is shown as a separate sibling surface (A0P) — the pending
 * target is never presented as the current plan.
 */

import type { LicenceAccountSummaryFacts } from '../../../lib/licensing/upgrade-presentation';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import type { LicenceReferenceFacts } from '../../../lib/licensing/licence-reference';
import { ShortLicenceReference } from './licence-reference';

export type LicenceAccountActionKind = 'upgrade' | 'view-licence' | 'view-progress';

export function accountActionLabel(action: LicenceAccountActionKind): string {
  switch (action) {
    case 'upgrade':
      return licenceUpgradeCopy('actionUpgrade');
    case 'view-licence':
      return licenceUpgradeCopy('actionViewLicence');
    case 'view-progress':
      return licenceUpgradeCopy('actionViewProgress');
  }
}

export function accountSummaryReference(
  summary: LicenceAccountSummaryFacts,
): LicenceReferenceFacts | null {
  if (summary.shortReference === null) {
    return null;
  }
  return {
    mode: 'shortened',
    displayText: summary.shortReference,
    fullText: summary.shortReference,
    selectable: true,
  };
}

export function AccountLicenceSummary({
  facts,
  onAction,
}: {
  readonly facts: LicenceAccountSummaryFacts;
  readonly onAction: (action: LicenceAccountActionKind) => void;
}) {
  if (!facts.available) {
    return null;
  }
  const reference = accountSummaryReference(facts);
  const action = facts.action === 'unavailable' ? null : facts.action;
  const label = action === null ? null : accountActionLabel(action);

  return (
    <section className="licence-account-summary" aria-label={licenceUpgradeCopy('titleLicence')}>
      <div className="licence-account-plan-row">
        <span className="licence-account-plan">{facts.planDisplayName}</span>
        {facts.active ? (
          <span className="licence-status-chip licence-status-active">{licenceUpgradeCopy('statusActive')}</span>
        ) : null}
      </div>

      {facts.pendingTargetName !== null ? (
        <div className="licence-account-pending">
          <span className="licence-status-chip licence-status-pending">
            {licenceUpgradeCopy('statusUpgradePending')}
          </span>
          <span className="licence-account-pending-target" data-testid="account-pending-target">
            {facts.pendingTargetName}
          </span>
          <span className="licence-account-pending-status" data-testid="account-pending-status">
            {facts.pendingStatusText}
          </span>
          {facts.currentLimitsRemain ? (
            <span className="licence-account-limits-note">
              {licenceUpgradeCopy('currentLimitsRemainInEffect')}
            </span>
          ) : null}
        </div>
      ) : (
        <dl className="licence-account-facts">
          {facts.conciseCapText !== null ? (
            <div className="licence-account-fact-row">
              <dt>{licenceUpgradeCopy('metricEligibleVoters')}</dt>
              <dd>{facts.conciseCapText}</dd>
            </div>
          ) : null}
          {facts.conciseValidityText !== null ? (
            <div className="licence-account-fact-row">
              <dt>{licenceUpgradeCopy('metricValidity')}</dt>
              <dd>{facts.conciseValidityText}</dd>
            </div>
          ) : null}
          {reference !== null ? (
            <div className="licence-account-fact-row">
              <dt>{licenceUpgradeCopy('sectionLicenceReference')}</dt>
              <dd>
                <ShortLicenceReference facts={reference} />
              </dd>
            </div>
          ) : null}
        </dl>
      )}

      {label !== null && action !== null ? (
        <button
          type="button"
          className="licence-account-action"
          onClick={() => onAction(action)}
          data-testid="account-licence-action"
        >
          {label}
        </button>
      ) : null}
    </section>
  );
}
