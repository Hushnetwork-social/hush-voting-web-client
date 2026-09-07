/**
 * FEAT-017 Task 5.1 — L1/L2 options surface (full-width Licence page body).
 *
 * Renders the current licence detail first, then the server-ordered higher
 * option list (or the exact no-higher message), then the informational
 * Enterprise entry. Section bands are complementary surfaces — no nested
 * heavy cards and no white-outline separators.
 */

import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import type { LicenceOptionsViewFacts } from '../../../lib/licensing/upgrade-presentation';
import { CurrentLicenceDetail } from './current-licence-detail';
import type { LicenceReferenceCopyHandler } from './licence-reference';
import { EnterpriseInformation, HigherLicenceOption } from './licence-options';
import type { LicenceWorkspaceActionHandlers } from './workspace-handlers';

export function NoHigherOptions() {
  return (
    <div className="licence-no-higher" data-testid="no-higher-options">
      <p className="licence-no-higher-message">{licenceUpgradeCopy('noHigherMessage')}</p>
    </div>
  );
}

export function LicenceOptionsView({
  facts,
  handlers,
  onReviewPlan,
  onCopyReference,
}: {
  readonly facts: LicenceOptionsViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
  readonly onReviewPlan: (planId: string) => void;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}) {
  return (
    <div className="licence-options-view" data-testid="licence-options">
      <section className="licence-section" aria-labelledby="licence-current-band">
        <h2 className="licence-section-band" id="licence-current-band">
          {licenceUpgradeCopy('sectionCurrentLicence')}
        </h2>
        {facts.current !== null ? <CurrentLicenceDetail facts={facts.current} onCopyReference={onCopyReference} /> : null}
      </section>

      <section className="licence-section" aria-labelledby="licence-higher-band">
        <h2 className="licence-section-band" id="licence-higher-band">
          {licenceUpgradeCopy('sectionAvailableHigherPlans')}
        </h2>

        {facts.selectionLocked ? (
          <div className="licence-selection-lock" data-testid="selection-locked">
            <span className="licence-status-chip licence-status-pending">{licenceUpgradeCopy('statusUpgradePending')}</span>
            {facts.lockedTargetName !== null ? (
              <span className="licence-lock-target">{facts.lockedTargetName}</span>
            ) : null}
            <button type="button" className="licence-secondary-action" onClick={handlers.onViewProgress}>
              {licenceUpgradeCopy('actionViewProgress')}
            </button>
          </div>
        ) : facts.noHigher ? (
          <NoHigherOptions />
        ) : facts.options.length > 0 ? (
          <div className="licence-option-grid">
            {facts.options.map((option) => (
              <HigherLicenceOption key={option.planId} option={option} onReview={onReviewPlan} />
            ))}
          </div>
        ) : (
          <NoHigherOptions />
        )}
      </section>

      {facts.enterprise !== null ? (
        <section className="licence-section" aria-labelledby="licence-enterprise-band">
          <h2 className="licence-section-band" id="licence-enterprise-band">
            {licenceUpgradeCopy('sectionEnterprise')}
          </h2>
          <EnterpriseInformation facts={facts.enterprise} />
        </section>
      ) : null}
    </div>
  );
}
