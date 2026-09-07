/**
 * FEAT-017 Task 5.1 — one server-ordered higher Veritas option and the
 * informational (never actionable) Enterprise surface (L1/L2/S0).
 *
 * Only strictly higher, validated options are ever rendered here by the
 * upstream projection; this component adds no rank/catalogue knowledge. Each
 * option exposes one deterministic "Review plan" action (selection only —
 * Review never creates, signs, or submits a transaction). `selected` marks a
 * presentation-only draft match (never color-only; a check glyph + copy).
 *
 * Enterprise is informational by construction: no link, form, provider
 * request, or activation descendant may exist inside this surface.
 */

import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import type {
  LicenceEnterpriseFacts,
  LicenceHigherOptionFacts,
} from '../../../lib/licensing/upgrade-presentation';

export function HigherLicenceOption({
  option,
  onReview,
}: {
  readonly option: LicenceHigherOptionFacts;
  readonly onReview: (planId: string) => void;
}) {
  const facts = [
    { label: licenceUpgradeCopy('metricEligibleVoters'), value: option.capText },
    { label: licenceUpgradeCopy('metricElections'), value: option.electionsText },
    { label: licenceUpgradeCopy('metricTerm'), value: option.termText },
  ].filter((row): row is { label: string; value: string } => row.value !== null);

  return (
    <article
      className={`licence-option${option.selected ? ' licence-option-selected' : ''}`}
      aria-current={option.selected ? 'true' : undefined}
    >
      <header className="licence-option-header">
        <h3 className="licence-option-name">{option.displayName}</h3>
        {option.selected ? (
          <span className="licence-option-selected-chip" data-testid="option-selected">
            <svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14">
              <path d="m3 8 3 3 7-7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {licenceUpgradeCopy('labelSelected')}
          </span>
        ) : null}
      </header>
      {option.description.length > 0 ? <p className="licence-option-desc">{option.description}</p> : null}
      {facts.length > 0 ? (
        <dl className="licence-option-facts">
          {facts.map((row) => (
            <div className="licence-option-fact-row" key={row.label}>
              <dt>{row.label}</dt>
              <dd>{row.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      <button
        type="button"
        className="licence-review-button"
        onClick={() => onReview(option.planId)}
        data-plan-id={option.planId}
        data-testid={`review-${option.planId}`}
      >
        {licenceUpgradeCopy('actionReviewPlan')}
      </button>
    </article>
  );
}

export function EnterpriseInformation({ facts }: { readonly facts: LicenceEnterpriseFacts }) {
  return (
    <aside className="licence-enterprise" aria-label={facts.displayName}>
      <h3 className="licence-enterprise-name">{facts.displayName}</h3>
      {facts.description.length > 0 ? <p className="licence-enterprise-desc">{facts.description}</p> : null}
      <span className="licence-enterprise-tag" data-testid="enterprise-tag">
        {facts.tag}
      </span>
    </aside>
  );
}
