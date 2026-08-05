/**
 * FEAT-010 Task 5.8 — lifecycle-shield, focus, and touch-target tests.
 *
 * Proves pagehide shielding, pageshow revalidation, focus intent resolution,
 * 44×44 CSS px touch targets, and reduced-motion handling (normative:
 * FeatureDescription "Navigation and Back", "Accessibility and Responsive
 * UX"; AC-010-083–090).
 */
import { describe, expect, it } from 'vitest';
import {
  focusTarget,
  meetsTouchTarget,
  MIN_TOUCH_TARGET_CSS_PX,
  onPageHide,
  onPageShow,
  prefersReducedMotion,
} from './lifecycle-shield';

describe('onPageHide', () => {
  it('synchronously shields when sensitive content is visible', () => {
    expect(onPageHide(true)).toEqual({ kind: 'shielded' });
  });

  it('does nothing when no sensitive content is visible', () => {
    expect(onPageHide(false)).toBeNull();
  });
});

describe('onPageShow', () => {
  it('revalidates through the authority on bfcache restoration', () => {
    expect(onPageShow(true)).toEqual({ kind: 'restoredFromBfcache', mustRevalidate: true });
  });

  it('does nothing on ordinary navigation', () => {
    expect(onPageShow(false)).toBeNull();
  });
});

describe('focusTarget', () => {
  it('resolves heading focus on transitions and error-summary focus on failures', () => {
    expect(focusTarget('heading')).toBe('h1[data-focus-heading]');
    expect(focusTarget('errorSummary')).toBe('[role="alert"][data-focus-error]');
  });
});

describe('touch targets and motion', () => {
  it('enforces the 44×44 CSS px minimum', () => {
    expect(MIN_TOUCH_TARGET_CSS_PX).toBe(44);
    expect(meetsTouchTarget(44, 44)).toBe(true);
    expect(meetsTouchTarget(43, 44)).toBe(false);
    expect(meetsTouchTarget(44, 43)).toBe(false);
  });

  it('respects reduced-motion preference', () => {
    expect(prefersReducedMotion(true)).toBe(true);
    expect(prefersReducedMotion(false)).toBe(false);
  });
});
