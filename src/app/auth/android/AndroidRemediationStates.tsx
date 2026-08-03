/**
 * FEAT-006 Android remediation states (Phase 5, Task 5.1/5.3).
 *
 * Renders a safe Android remediation view from the closed projection
 * (`src/lib/android-vault/safe-states.ts`). Accessibility: role=alert,
 * aria-live, labelled buttons, correct focus order. No hardware class, exact
 * model, alias, path, identity, raw exception, or support-code echo is ever
 * rendered. Unknown values fail closed to generic safe guidance. This is an
 * additive component; FEAT-002 remains the sole navigation/UI authority.
 */

import type { SafeStateView } from '../../../lib/android-vault/safe-states';
import { safeStateViewFromUnknown } from '../../../lib/android-vault/safe-states';

/** Action labels (approved vocabulary only; no continue-anyway). */
const ACTION_LABELS: Readonly<Record<SafeStateView['actions'][number]['kind'], string>> = {
  retry: 'Try again',
  openSecuritySettings: 'Open security settings',
  updateApp: 'Update HushVoting',
  removeLocalUser: 'Remove local user',
  portableRecovery: 'Recovery options',
  resumeRemoval: 'Finish removal',
  cancel: 'Close',
};

export interface AndroidRemediationStatesProps {
  readonly code: unknown;
  readonly onAction?: (action: SafeStateView['actions'][number]['kind']) => void;
}

export function AndroidRemediationStates({ code, onAction }: AndroidRemediationStatesProps) {
  const view = safeStateViewFromUnknown(code);

  if (view.informational && view.actions.length === 0) {
    return (
      <section
        role="alert"
        aria-live="polite"
        className="rounded-xl bg-surface-raised p-6 shadow-sm focus:outline-none"
        data-testid="android-remediation-informational"
      >
        <h2 className="mb-2 text-lg font-semibold text-on-surface">{view.heading}</h2>
        <p className="mb-4 text-sm text-on-surface-muted">{view.body}</p>
        {view.actions.length > 0 ? (
          <div className="flex flex-wrap gap-3">{renderActions(view, onAction)}</div>
        ) : null}
      </section>
    );
  }

  return (
    <section
      role="alert"
      aria-live="polite"
      className="rounded-xl bg-surface-raised p-6 shadow-sm"
      data-testid="android-remediation"
    >
      <h2 className="mb-2 text-lg font-semibold text-on-surface">{view.heading}</h2>
      <p className="mb-4 text-sm text-on-surface-muted">{view.body}</p>
      <div className="flex flex-wrap gap-3">{renderActions(view, onAction)}</div>
    </section>
  );
}

function renderActions(
  view: SafeStateView,
  onAction?: (action: SafeStateView['actions'][number]['kind']) => void,
) {
  return view.actions.map((action) => (
    <button
      key={action.kind}
      type="button"
      onClick={() => onAction?.(action.kind)}
      className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-on-accent transition-colors hover:bg-accent-strong focus:outline-none focus:ring-2 focus:ring-accent"
    >
      {ACTION_LABELS[action.kind]}
    </button>
  ));
}
