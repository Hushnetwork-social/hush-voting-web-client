/**
 * FEAT-017 Task 5.3 — licence workspace surfaces (C0, P0, D0, R0, S0).
 *
 * Each surface is a thin renderer over its closed Phase-4 view facts. It
 * never infers authority: confirmation only renders facts produced for a
 * valid fresh draft; progress/delayed only render for a live safe operation;
 * result only for exact local success; stale for the typed stale terminal.
 *
 * Announcement policy is honoured by the workspace shell (see
 * `licence-workspace.tsx`): meaningful entries announce once politely, while
 * repeated three-second query re-renders of the same surface stay silent.
 */

import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import type {
  LicenceConfirmationViewFacts,
  LicenceDelayedViewFacts,
  LicenceProgressViewFacts,
  LicenceResultViewFacts,
  LicenceStaleViewFacts,
} from '../../../lib/licensing/upgrade-presentation';
import { CurrentLicenceDetail } from './current-licence-detail';
import { LicenceReferenceFull, type LicenceReferenceCopyHandler } from './licence-reference';
import { LicenceOptionsView } from './options-view';
import type { LicenceWorkspaceActionHandlers } from './workspace-handlers';

/** One shared consequence/definition row for C0 current/target sides. */
function FactRows({ rows }: { readonly rows: ReadonlyArray<{ readonly label: string; readonly value: string }> }) {
  const present = rows.filter((row): row is { label: string; value: string } => row.value.length > 0);
  if (present.length === 0) {
    return null;
  }
  return (
    <dl className="licence-fact-list">
      {present.map((row) => (
        <div className="licence-fact-row" key={row.label}>
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function LicenceConfirmationSurface({
  facts,
  handlers,
  onCopyReference,
}: {
  readonly facts: LicenceConfirmationViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}) {
  const currentRows = [
    { label: licenceUpgradeCopy('metricEligibleVoters'), value: facts.currentSide.capText ?? '' },
    { label: licenceUpgradeCopy('metricGovernance'), value: facts.currentSide.governanceText ?? '' },
    { label: licenceUpgradeCopy('metricValidity'), value: facts.currentSide.validityText ?? '' },
    { label: licenceUpgradeCopy('metricTerm'), value: facts.currentSide.termText ?? '' },
  ];
  const targetRows = [
    { label: licenceUpgradeCopy('metricEligibleVoters'), value: facts.targetSide.capText ?? '' },
    { label: licenceUpgradeCopy('metricElections'), value: facts.targetSide.electionsText ?? '' },
    { label: licenceUpgradeCopy('metricTerm'), value: facts.targetSide.termText ?? '' },
  ];

  return (
    <div className="licence-confirmation" data-testid="licence-confirmation">
      <div className="licence-compare-grid">
        <section className="licence-compare-side" aria-labelledby="licence-current-side-title">
          <h2 className="licence-compare-side-title" id="licence-current-side-title">
            {licenceUpgradeCopy('labelCurrent')}
          </h2>
          <h3 className="licence-compare-plan">{facts.currentSide.displayName}</h3>
          <FactRows rows={currentRows} />
        </section>
        <section className="licence-compare-side licence-compare-side-target" aria-labelledby="licence-target-side-title">
          <h2 className="licence-compare-side-title" id="licence-target-side-title">
            {licenceUpgradeCopy('labelTarget')}
          </h2>
          <h3 className="licence-compare-plan">{facts.targetSide.displayName}</h3>
          {facts.targetSide.description.length > 0 ? (
            <p className="licence-compare-desc">{facts.targetSide.description}</p>
          ) : null}
          <FactRows rows={targetRows} />
        </section>
      </div>

      {facts.reference !== null ? (
        <div className="licence-confirm-metadata">
          <span className="licence-meta-label">{licenceUpgradeCopy('sectionLicenceReference')}</span>
          <LicenceReferenceFull facts={facts.reference} onCopy={onCopyReference} />
        </div>
      ) : null}

      <div className="licence-confirm-metadata">
        <span className="licence-meta-label">{licenceUpgradeCopy('sectionCatalogueVersion')}</span>
        <span className="licence-catalogue-version" data-testid="catalogue-version">
          {facts.catalogueVersion}
        </span>
      </div>

      <section className="licence-consequences" aria-labelledby="licence-consequences-title">
        <h2 className="licence-consequences-title" id="licence-consequences-title">
          {licenceUpgradeCopy('sectionWhatHappens')}
        </h2>
        <ul className="licence-consequences-list">
          {facts.consequences.map((consequence) => (
            <li key={consequence}>{consequence}</li>
          ))}
        </ul>
      </section>

      <div className="licence-action-row">
        <button type="button" className="licence-secondary-action" onClick={handlers.onBackToPlans}>
          {licenceUpgradeCopy('actionBackToPlans')}
        </button>
        <button type="button" className="licence-primary-action" onClick={handlers.onActivate}>
          {licenceUpgradeCopy('actionActivateLicence')}
        </button>
      </div>
    </div>
  );
}

export function LicenceProgressSurface({
  facts,
  handlers,
}: {
  readonly facts: LicenceProgressViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
}) {
  return (
    <div className="licence-progress" aria-busy={facts.ariaBusy ? 'true' : 'false'} data-testid="licence-progress">
      <p className="licence-progress-waiting">{facts.waitingMessage ?? facts.statusText}</p>
      <p className="licence-progress-status" role="status" aria-live="polite" data-testid="licence-progress-status">
        {facts.statusText}
      </p>

      <section className="licence-progress-current" aria-label={facts.currentName ?? undefined}>
        {facts.currentRemainsMessage !== null ? (
          <p className="licence-progress-current-message">{facts.currentRemainsMessage}</p>
        ) : null}
        <p className="licence-progress-limits">{facts.existingLimitsMessage}</p>
      </section>

      {facts.targetName !== null ? (
        <section className="licence-progress-target" aria-label={`${licenceUpgradeCopy('labelPendingTarget')}: ${facts.targetName}`}>
          <span className="licence-meta-label">{licenceUpgradeCopy('labelPendingTarget')}</span>
          <span className="licence-progress-target-name" data-testid="progress-target-name">
            {facts.targetName}
          </span>
        </section>
      ) : null}

      <p className="licence-progress-reassurance">{facts.reassurance}</p>

      <div className="licence-action-row">
        <button type="button" className="licence-secondary-action" onClick={handlers.onContinueWorking}>
          {licenceUpgradeCopy('actionContinueWorking')}
        </button>
      </div>
    </div>
  );
}

export function LicenceDelayedSurface({
  facts,
  handlers,
}: {
  readonly facts: LicenceDelayedViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
}) {
  return (
    <div className="licence-delayed" data-testid="licence-delayed">
      {facts.targetMessage !== null ? <p className="licence-delayed-message">{facts.targetMessage}</p> : null}
      {facts.currentMessage !== null ? <p className="licence-delayed-current">{facts.currentMessage}</p> : null}
      <p className="licence-delayed-explainer">{facts.retryExplainer}</p>
      <div className="licence-action-row">
        <button type="button" className="licence-primary-action" onClick={handlers.onRetry}>
          {licenceUpgradeCopy('actionRetry')}
        </button>
        <button type="button" className="licence-secondary-action" onClick={handlers.onContinueWorking}>
          {licenceUpgradeCopy('actionContinueWorking')}
        </button>
      </div>
    </div>
  );
}

export function LicenceResultSurface({
  facts,
  handlers,
  onCopyReference,
}: {
  readonly facts: LicenceResultViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}) {
  return (
    <div className="licence-result" data-testid="licence-result">
      {facts.activeMessage !== null ? (
        <p className="licence-result-message">
          <span className="licence-status-chip licence-status-active">{licenceUpgradeCopy('statusActive')}</span>{' '}
          {facts.activeMessage}
        </p>
      ) : null}
      {facts.current !== null ? <CurrentLicenceDetail facts={facts.current} onCopyReference={onCopyReference} /> : null}
      <div className="licence-action-row">
        <button type="button" className="licence-secondary-action" onClick={handlers.onReturnToWorkspace}>
          {licenceUpgradeCopy('actionReturnToWorkspace')}
        </button>
        <button type="button" className="licence-secondary-action" onClick={handlers.onViewCurrentLicence}>
          {licenceUpgradeCopy('actionViewCurrentLicence')}
        </button>
      </div>
    </div>
  );
}

export function LicenceStaleSurface({
  facts,
  handlers,
  onReviewPlan,
  onCopyReference,
}: {
  readonly facts: LicenceStaleViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
  readonly onReviewPlan: (planId: string) => void;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}) {
  return (
    <div className="licence-stale" data-testid="licence-stale">
      <div className="licence-change-notice" role="alert">
        <h2 className="licence-change-notice-title" tabIndex={-1} data-licence-focus-target="notice-heading" data-testid="stale-notice">
          {facts.notice}
        </h2>
      </div>
      {facts.fresh !== null ? (
        <LicenceOptionsView facts={facts.fresh} handlers={handlers} onReviewPlan={onReviewPlan} onCopyReference={onCopyReference} />
      ) : null}
    </div>
  );
}
