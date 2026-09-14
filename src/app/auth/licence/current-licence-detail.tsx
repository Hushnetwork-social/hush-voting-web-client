/**
 * FEAT-017 Task 5.1 — current licence detail + metric value wells (L1/L2,
 * R0, and fresh S0 blocks). Consumes the closed `LicenceCurrentDetailFacts`
 * projection; renders name/status, description, definition-list metric rows
 * in complementary wells, effective-from line, upper-exclusive validity note,
 * and the full selectable/copyable reference.
 *
 * No value is invented: rows absent from facts are omitted; a perpetual
 * licence has no expiry; governance text comes only from mapped safe ids.
 */

import type { LicenceCurrentDetailFacts } from '../../../lib/licensing/upgrade-presentation';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import { LicenceReferenceFull, type LicenceReferenceCopyHandler } from './licence-reference';

export function CurrentLicenceDetail({
  facts,
  onCopyReference,
}: {
  readonly facts: LicenceCurrentDetailFacts;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}) {
  return (
    <section className="licence-current-detail" aria-label={facts.displayName}>
      <header className="licence-current-header">
        <h3 className="licence-current-name">{facts.displayName}</h3>
        {facts.active ? (
          <span className="licence-status-chip licence-status-active">{licenceUpgradeCopy('statusActive')}</span>
        ) : null}
      </header>
      {facts.description.length > 0 ? <p className="licence-current-desc">{facts.description}</p> : null}

      {facts.metricRows.length > 0 ? (
        <dl className="licence-metric-grid">
          {facts.metricRows.map((row) => (
            <div className="licence-metric-well" key={`${row.label}:${row.value}`}>
              <dt className="licence-metric-label">{row.label}</dt>
              <dd className="licence-metric-value">{row.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}

      {facts.effectiveFromText !== null ? (
        <p className="licence-current-effective">
          <span className="licence-meta-label">{licenceUpgradeCopy('effectiveFromLabel')}</span>{' '}
          <span data-testid="current-effective-local">{facts.effectiveFromText}</span>
        </p>
      ) : null}

      {facts.validity?.boundaryNote !== null && facts.validity?.boundaryNote !== undefined ? (
        <p className="licence-current-boundary-note" data-testid="validity-boundary-note">
          {facts.validity.boundaryNote}
        </p>
      ) : null}

      {facts.reference !== null ? (
        <div className="licence-current-reference">
          <span className="licence-meta-label">{licenceUpgradeCopy('sectionLicenceReference')}</span>
          <LicenceReferenceFull facts={facts.reference} onCopy={onCopyReference} />
        </div>
      ) : null}
    </section>
  );
}
