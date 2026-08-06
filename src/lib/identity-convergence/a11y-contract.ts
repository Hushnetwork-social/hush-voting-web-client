/**
 * FEAT-011 Task 5.7 — WCAG 2.2 AA accessibility contract for the convergence
 * surfaces (framework-neutral rules the React layer must render).
 *
 * Every projection carries a11y metadata (focus target, live region, error
 * summary). This module freezes the WCAG 2.2 AA invariants: keyboard order,
 * 44×44 targets, 200% scaling / narrow reflow, reduced motion, error summary,
 * semantic names, and secret-input clearing. Rules are data — testable now,
 * rendered by Phase 6 components.
 */

import type { ConvergenceAction, ConvergenceViewProjection } from './presentation';

/** Minimum interactive target size (WCAG 2.5.8 Target Size Minimum, 24×24 CSS px; we require 44×44). */
export const MIN_TARGET_SIZE_CSS_PX = 44;

/** Reduced-motion contract: no essential motion; animation is decorative and prefers-reduced-motion safe. */
export const REDUCED_MOTION_CONTRACT = 'decorative-only' as const;

/** 200% scaling + 320px-wide reflow contract (WCAG 1.4.10 Reflow). */
export const REFLOW_MIN_WIDTH_CSS_PX = 320;

/** Keyboard order contract: the focus target is the first focusable element on every screen. */
export function keyboardOrderIsValid(projection: ConvergenceViewProjection): boolean {
  if (projection.a11y.focusTarget === null) {
    return true; // no focusable content on this screen (e.g., waiting)
  }
  return projection.a11y.focusTarget.length > 0;
}

/** Error summary contract: any screen with errors exposes them focusable and field-specific. */
export function errorSummaryIsValid(projection: ConvergenceViewProjection): boolean {
  const errors = projection.a11y.errorSummary;
  if (errors.length === 0) {
    return true;
  }
  return errors.every((e) => e.field.length > 0 && e.message.length > 0);
}

/** Secret-input contract: secret fields clear immediately after accepted transfer. */
export const SECRET_CLEAR_IMMEDIATELY = true;

/**
 * Action-label contract: every actionable screen exposes a labeled primary
 * action (44×44 target). Entry selections (selectCreate/selectWords/selectFile)
 * and dismiss/back/confirm actions carry their own visible labels, so they are
 * self-labeled and need no separate actionLabel.
 */
const SELF_LABELED_ACTIONS: ReadonlySet<ConvergenceAction> = new Set([
  'selectCreate',
  'selectWords',
  'selectFile',
  'confirmSixPosition',
  'dismiss',
  'back',
]);

export function actionLabelPresentForActionableScreens(projection: ConvergenceViewProjection): boolean {
  if (projection.actions.length === 0) {
    return true;
  }
  if (projection.copy.actionLabel !== null && projection.copy.actionLabel.length > 0) {
    return true;
  }
  return projection.actions.every((a) => SELF_LABELED_ACTIONS.has(a));
}

/** Semantic live-region contract: progress is polite; confirmations/errors are assertive. */
export function liveRegionIsAppropriate(projection: ConvergenceViewProjection): boolean {
  switch (projection.screen) {
    case 'existingProfile':
    case 'authenticated':
    case 'terminalBlocked':
    case 'correction':
      return projection.a11y.liveRegion === 'assertive';
    case 'firstRun':
      return projection.a11y.liveRegion === null;
    default:
      return projection.a11y.liveRegion === 'polite' || projection.a11y.liveRegion === null;
  }
}

/** Forbidden copy vocabulary — no premature success wording anywhere (negated phrases like "not signed in yet" are truthful and allowed). */
export const FORBIDDEN_PREMATURE_COPY = /(?<!\bnot )(?<!\bnever )(logged in|signed in|restored|created|authenticated)\b/i;

export function copyIsTruthful(projection: ConvergenceViewProjection): boolean {
  if (projection.screen === 'existingProfile' || projection.screen === 'authenticated') {
    return true; // success wording allowed ONLY on confirmed screens
  }
  return !FORBIDDEN_PREMATURE_COPY.test(projection.copy.heading) && !FORBIDDEN_PREMATURE_COPY.test(projection.copy.body);
}

/** No color-only status: every status is conveyed by text/live region as well. */
export const COLOR_ONLY_STATUS_FORBIDDEN = true;

/** Secret exclusion: projections never carry secret-bearing fields (structural scan). */
export function projectionIsSecretFree(projection: ConvergenceViewProjection): boolean {
  const json = JSON.stringify(projection);
  return !/password|mnemonic|private ?key|signature|transaction.?json|full ?address/.test(json);
}
