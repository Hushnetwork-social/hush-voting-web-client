/**
 * FEAT-017 Task 5.1/5.3/5.5 — full-width Licence workspace shell.
 *
 * Renders exactly ONE surface for the closed `LicenceWorkspaceViewFacts`
 * snapshot. The shell owns the step heading, deterministic focus placement
 * (per `licenceFocusTargetFor`) and the polite live-region announcement
 * policy (`licenceAnnouncementPolicy`): meaningful transitions announce once;
 * repeated three-second polls on the same surface stay silent.
 *
 * gate/recovery are NOT rendered here — the existing FEAT-016 root gate owns
 * those screens (L0/E0 reuse). No remembered licence data can render for
 * those views by construction.
 */

import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { licenceUpgradeCopy } from '../../../lib/licensing/upgrade-copy';
import {
  licenceAnnouncementPolicy,
  type LicenceWorkspaceView,
  type LicenceWorkspaceViewFacts,
} from '../../../lib/licensing/upgrade-presentation';
import { LicenceOptionsView } from './options-view';
import {
  LicenceConfirmationSurface,
  LicenceDelayedSurface,
  LicenceProgressSurface,
  LicenceResultSurface,
  LicenceStaleSurface,
} from './workspace-surfaces';
import type { LicenceReferenceCopyHandler } from './licence-reference';
import type { LicenceWorkspaceActionHandlers } from './workspace-handlers';

/** Deterministic announcement text for a meaningful view entry. */
function announcementTextFor(facts: LicenceWorkspaceViewFacts): string {
  switch (facts.view) {
    case 'progress':
      return facts.statusText;
    case 'delayed':
      return facts.heading;
    case 'result':
      return facts.activeMessage ?? '';
    case 'stale':
      return facts.notice;
    default:
      return '';
  }
}

function SurfaceBody({
  facts,
  handlers,
  onReviewPlan,
  onCopyReference,
}: {
  readonly facts: LicenceWorkspaceViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
  readonly onReviewPlan: (planId: string) => void;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}): ReactNode {
  switch (facts.view) {
    case 'options':
      return <LicenceOptionsView facts={facts} handlers={handlers} onReviewPlan={onReviewPlan} onCopyReference={onCopyReference} />;
    case 'confirmation':
      return <LicenceConfirmationSurface facts={facts} handlers={handlers} onCopyReference={onCopyReference} />;
    case 'progress':
      return <LicenceProgressSurface facts={facts} handlers={handlers} />;
    case 'delayed':
      return <LicenceDelayedSurface facts={facts} handlers={handlers} />;
    case 'result':
      return <LicenceResultSurface facts={facts} handlers={handlers} onCopyReference={onCopyReference} />;
    case 'stale':
      return (
        <LicenceStaleSurface facts={facts} handlers={handlers} onReviewPlan={onReviewPlan} onCopyReference={onCopyReference} />
      );
    case 'gate':
    case 'recovery':
      // Root FEAT-016 gate owns these screens (L0/E0); never remembered data.
      return null;
    default: {
      const exhaustive: never = facts;
      return exhaustive;
    }
  }
}

function subtitleFor(facts: LicenceWorkspaceViewFacts): string | null {
  if (facts.view === 'options' || facts.view === 'confirmation') {
    return facts.subtitle;
  }
  return null;
}

export function LicenceWorkspace({
  facts,
  handlers,
  onReviewPlan,
  onCopyReference,
}: {
  readonly facts: LicenceWorkspaceViewFacts;
  readonly handlers: LicenceWorkspaceActionHandlers;
  readonly onReviewPlan?: (planId: string) => void;
  readonly onCopyReference?: LicenceReferenceCopyHandler;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const previousViewRef = useRef<LicenceWorkspaceView | 'none'>('none');
  const [announcement, setAnnouncement] = useState('');
  const view = facts.view;

  // Deterministic focus + one-shot announcement only on real view change
  // (a three-second poll re-render keeps the same view and stays silent).
  useEffect(() => {
    const previous = previousViewRef.current;
    previousViewRef.current = view;
    if (previous === view) {
      return;
    }
    const policy = licenceAnnouncementPolicy(previous, view);
    if (policy.announce) {
      setAnnouncement(announcementTextFor(facts));
    } else {
      setAnnouncement('');
    }
    const target = policy.focus;
    if (target !== 'none') {
      const el = containerRef.current?.querySelector<HTMLElement>(`[data-licence-focus-target="${target}"]`);
      el?.focus({ preventScroll: true });
    }
    // facts/announcement intentionally not dependencies: they may change on
    // every poll while the view remains identical.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view]);

  const title =
    view === 'gate' || view === 'recovery'
      ? ''
      : view === 'stale'
        ? licenceUpgradeCopy('titleLicence')
        : facts.heading;
  const subtitle = subtitleFor(facts);
  const body =
    view === 'gate' || view === 'recovery' ? null : (
      <SurfaceBody facts={facts} handlers={handlers} onReviewPlan={onReviewPlan ?? (() => undefined)} onCopyReference={onCopyReference} />
    );

  return (
    <div className="licence-workspace" ref={containerRef} data-view={view} data-testid={`licence-view-${view}`}>
      {view !== 'gate' && view !== 'recovery' ? (
        <header className="licence-workspace-header">
          <h1
            className="licence-workspace-title"
            {...(view === 'stale' ? {} : { 'data-licence-focus-target': 'heading' })}
            tabIndex={-1}
          >
            {title}
          </h1>
          {subtitle !== null ? <p className="licence-workspace-subtitle">{subtitle}</p> : null}
        </header>
      ) : null}

      {body}

      <span className="sr-only" role="status" aria-live="polite" data-testid="licence-live-region">
        {announcement}
      </span>
    </div>
  );
}
