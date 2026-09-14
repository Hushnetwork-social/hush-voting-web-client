/**
 * FEAT-017 Task 5.1 — licence reference display surfaces (shortened account
 * row, full selectable/copyable value with polite feedback).
 *
 * The licence reference is the PUBLIC originating transaction UUID (never a
 * secret and never authorization). Account shows a recognizably shortened
 * value; details/confirmation show the full selectable value. Clipboard write
 * is injected (`copyReference`) so the Web/native adapter stays integration-
 * owned (Phase 6) while this component owns the accessible feedback model:
 * success/failure is announced once through a polite status region and the
 * full value always remains visible and selectable.
 *
 * Copy: this component never invents a reference and never logs/traces
 * anything. It renders only validated `LicenceReferenceFacts`.
 */

import { useState } from 'react';
import type { LicenceReferenceFacts } from '../../../lib/licensing/licence-reference';
import { licenceCopyFeedback } from '../../../lib/licensing/licence-reference';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';

export type LicenceReferenceCopyHandler = (fullText: string) => Promise<boolean>;

/** Full selectable reference with a Copy action and polite one-shot feedback. */
export function LicenceReferenceFull({
  facts,
  onCopy,
}: {
  readonly facts: LicenceReferenceFacts;
  readonly onCopy?: LicenceReferenceCopyHandler;
}) {
  const [feedback, setFeedback] = useState<ReturnType<typeof licenceCopyFeedback> | null>(null);
  const [feedbackKey, setFeedbackKey] = useState(0);

  async function copyValue(): Promise<void> {
    if (facts.mode !== 'full' || onCopy === undefined) {
      return;
    }
    const ok = await onCopy(facts.fullText);
    const outcome = licenceCopyFeedback(ok ? 'success' : 'failure');
    setFeedbackKey((current) => current + 1);
    setFeedback(outcome);
  }

  const statusText = feedback?.statusText ?? '';

  return (
    <div className="licence-reference-row">
      <span className="licence-reference-full" data-testid="licence-reference-full">
        {facts.fullText}
      </span>
      {onCopy !== undefined && (
        <button type="button" className="licence-copy-button" onClick={() => void copyValue()}>
          {licenceUpgradeCopy('actionCopy')}
        </button>
      )}
      <span
        className="licence-copy-feedback"
        role="status"
        aria-live="polite"
        data-testid="licence-copy-feedback"
        data-feedback-key={feedbackKey}
      >
        {statusText}
      </span>
    </div>
  );
}

/** Shortened display-only reference (Account A0 row; never a secret). */
export function ShortLicenceReference({
  facts,
}: {
  readonly facts: LicenceReferenceFacts;
}) {
  if (facts.mode !== 'shortened') {
    return null;
  }
  return (
    <span className="licence-short-reference" data-testid="licence-short-reference">
      {licenceUpgradeCopy('accountRefLabel')} {facts.displayText}
    </span>
  );
}
