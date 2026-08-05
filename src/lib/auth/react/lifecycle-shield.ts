/**
 * FEAT-010 UI lifecycle — pagehide/pageshow shielding and focus management
 * (Task 5.7).
 *
 * - `pagehide` synchronously shields sensitive content (bfcache can never
 *   reveal stale protected content first);
 * - `pageshow` revalidates through the authority before protected restoration
 *   (AC-010-087);
 * - focus moves to the heading on transition and to the error summary on
 *   failure (WCAG 2.2 AA);
 * - sensitive destinations never resume after Lock; reload/process death
 *   returns through fresh authentication (AC-010-085/086).
 *
 * Framework-neutral helpers consumed by the page components.
 */

/** Shield verdict produced by page lifecycle events. */
export type ShieldVerdict =
  | { readonly kind: 'shielded' }
  | { readonly kind: 'restoredFromBfcache'; readonly mustRevalidate: true };

/** Visibility intent for focus management. */
export type FocusIntent = 'heading' | 'errorSummary';

/**
 * React-friendly hook contract (pure helpers; the hook wiring lives in the
 * page adapter): decide what to do on pagehide/pageshow.
 */
export function onPageHide(sensitiveContentVisible: boolean): ShieldVerdict | null {
  if (!sensitiveContentVisible) {
    return null;
  }
  // Synchronous shield: bfcache snapshot must never contain revealed content.
  return { kind: 'shielded' };
}

export function onPageShow(fromBfcache: boolean): ShieldVerdict | null {
  if (!fromBfcache) {
    return null;
  }
  // Revalidate through the authority before any protected restoration.
  return { kind: 'restoredFromBfcache', mustRevalidate: true };
}

/**
 * Focus target resolution: headings on transition, error summaries on
 * failure. Returns the selector the page adapter applies after render.
 */
export function focusTarget(intent: FocusIntent): string {
  return intent === 'heading' ? 'h1[data-focus-heading]' : '[role="alert"][data-focus-error]';
}

/** Minimum touch target (44×44 CSS px, WCAG 2.2). */
export const MIN_TOUCH_TARGET_CSS_PX = 44 as const;

/** Reduced-motion and high-contrast safe defaults (no animation when reduced). */
export function prefersReducedMotion(matchMediaResult: boolean): boolean {
  return matchMediaResult;
}

/** Verify a target size meets the 44×44 CSS px requirement. */
export function meetsTouchTarget(widthPx: number, heightPx: number): boolean {
  return widthPx >= MIN_TOUCH_TARGET_CSS_PX && heightPx >= MIN_TOUCH_TARGET_CSS_PX;
}
