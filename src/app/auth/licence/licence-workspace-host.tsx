/**
 * FEAT-017 Task 6.1 — root licence workspace host (Web composition).
 *
 * The full-width licence workspace page mounted by the authenticated root
 * shell. It receives the CLOSED authority-derived `LicenceUpgradePresentationInput`
 * (composed by AuthRoot from the EntitlementBridge mirror + machine
 * projection) and real action callbacks; it owns ONLY the D017-04-local
 * presentation state the authority cannot own: the unsubmitted draft
 * selection and the open/visible flag of the page.
 *
 * Rules enforced here (all authority-side facts remain validated by the pure
 * presentation layer):
 *  - no licence values are placed in URL/history; Back/reload/remount restore
 *    from authority state only;
 *  - leaving before Activate discards the draft (D017-04); leaving after a
 *    sealed operation keeps the authority operation and N0 reopens it;
 *  - a stale draft (fresh truth changed) can never reach confirmation;
 *  - activation/retry/acknowledge/refresh are forwarded to real root actions
 *    (never a page-owned signer/loop/journal).
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…06; design contract
 * A0/L1/L2/C0/P0/D0/R0/S0/N0/N1; Task 6.1 behavior spec.
 */
import { useMemo, useState } from 'react';
import type { LicenceUpgradePresentationInput, LicenceWorkspaceView } from '../../../lib/licensing/upgrade-presentation';
import {
  draftFromHigherOption,
  draftMatchesFreshOptions,
  projectLicenceWorkspaceViewFacts,
  projectRestoredLicenceSurface,
} from '../../../lib/licensing/upgrade-presentation';
import type { LicenceDraftSelection } from '../../../lib/licensing/upgrade-presentation';
import { LicenceWorkspace } from './licence-workspace';
import type { LicenceReferenceCopyHandler } from './licence-reference';
import type { LicenceWorkspaceActionHandlers } from './workspace-handlers';

export interface LicenceWorkspaceHostProps {
  /** Closed authority-derived presentation input; null → host renders nothing. */
  readonly input: LicenceUpgradePresentationInput | null;
  /** True while the licence page is the mounted root destination. */
  readonly visible: boolean;
  /** Real actions routed to the root composition (never page-owned authority). */
  readonly actions: {
    readonly onActivate: (targetPlanId: string) => void;
    readonly onRetryExact: () => void;
    readonly onAcknowledgeOutcome: () => void;
    readonly onRefreshForEntry: () => void;
    /** Leave the licence page back to the operational workspace. */
    readonly onClose: () => void;
  };
  /** Optional clipboard write (Web/native adapter injected by AuthRoot). */
  readonly onCopyReference?: LicenceReferenceCopyHandler;
  readonly timeZone?: string;
}

function nonNull<T>(value: T | null): T {
  if (value === null) {
    throw new Error('expected non-null licence presentation facts');
  }
  return value;
}

/**
 * Deterministic view the workspace page should show while visible. Restored
 * from AUTHORITY STATE ONLY (never a remembered step): live pending/delayed →
 * progress, retained local-success → result, typed stale → stale, fresh truth
 * → options. A matching fresh draft is honored ONLY on the options surface
 * (user may be reviewing the confirmation step they selected).
 */
export function visibleViewFor(input: LicenceUpgradePresentationInput | null): LicenceWorkspaceView | null {
  if (input === null) {
    return null;
  }
  return projectRestoredLicenceSurface(input);
}

/** True when the pure model can still show the selected draft (fresh options). */
export function draftStillFresh(
  input: LicenceUpgradePresentationInput | null,
  draft: LicenceDraftSelection | null,
): boolean {
  if (input === null || draft === null) {
    return false;
  }
  return draftMatchesFreshOptions(input.projection, draft);
}

export function LicenceWorkspaceHost({
  input,
  visible,
  actions,
  onCopyReference,
  timeZone = 'UTC',
}: LicenceWorkspaceHostProps) {
  const [draft, setDraft] = useState<LicenceDraftSelection | null>(null);
  const [reviewingConfirmation, setReviewingConfirmation] = useState(false);

  // Restored authority view. Draft can only surface while the user is on the
  // confirmation step and the pure model still accepts it.
  const restoredView = visibleViewFor(input);
  const draftFresh = draftStillFresh(input, draft);
  const draftOk = draftFresh && draft !== null;
  const view = visible
    ? restoredView === null
      ? null
      : reviewingConfirmation && draftOk && restoredView === 'options'
        ? 'confirmation'
        : restoredView
    : null;

  // A stale draft (fresh truth changed) can never reach confirmation: the
  // pure model clears it when it no longer matches fresh options. When the
  // authority moves away from options the confirmation flag is inert.
  const effectiveDraft = view === 'confirmation' && draftOk ? draft : null;
  const handlers = useMemo<LicenceWorkspaceActionHandlers>(
    () => ({
      onViewProgress: () => {
        setDraft(null);
        setReviewingConfirmation(false);
        actions.onRefreshForEntry();
      },
      onBackToPlans: () => {
        setReviewingConfirmation(false);
      },
      onActivate: () => {
        if (draft !== null) {
          actions.onActivate(draft.planId);
          setReviewingConfirmation(false);
        }
      },
      onContinueWorking: () => {
        actions.onClose();
      },
      onRetry: () => {
        actions.onRetryExact();
      },
      onReturnToWorkspace: () => {
        actions.onAcknowledgeOutcome();
        actions.onClose();
      },
      onViewCurrentLicence: () => {
        actions.onAcknowledgeOutcome();
        setReviewingConfirmation(false);
      },
    }),
    [draft, actions],
  );

  const onReviewPlan = (planId: string): void => {
    if (input === null || input.projection === null) {
      return;
    }
    const option = input.projection.higherOptions.find((candidate) => candidate.planId === planId);
    if (option === undefined) {
      return; // never a client-invented plan
    }
    setDraft(draftFromHigherOption(option));
    setReviewingConfirmation(true);
  };

  if (!visible || input === null || view === null) {
    return null;
  }

  const facts = projectLicenceWorkspaceViewFacts(input, view, effectiveDraft, timeZone);
  if (facts === null) {
    return null;
  }

  return (
    <div className="licence-workspace-host" data-testid="licence-workspace-host" data-view={view}>
      <LicenceWorkspace facts={nonNull(facts)} handlers={handlers} onReviewPlan={onReviewPlan} onCopyReference={onCopyReference} />
    </div>
  );
}
