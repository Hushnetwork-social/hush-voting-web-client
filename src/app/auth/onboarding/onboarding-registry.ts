/**
 * FEAT-010 integration — onboarding child-view registry (Task 6.7 seam).
 *
 * The three completed child flows (FEAT-007/008/009) publish their safe
 * secret-free view states through this typed registry while their authorities
 * run; `AuthGate` resolves the closed `OnboardingChild` for the active
 * `onboardingKind`. Unknown/missing child views resolve to `null` and the
 * OnboardingHost renders its typed fail-closed error — placeholder onboarding copy remains
 * impossible (AC-010-012).
 *
 * App-layer module (components reference); secret-free.
 */
import type { OnboardingChild } from './OnboardingHost';

const publications = new Map<string, OnboardingChild>();

/** Publish the current child view for a kind (child authority adapters). */
export function publishChildView(kind: string, child: OnboardingChild): void {
  publications.set(kind, child);
}

/** Clear a publication (child cleanup/back). */
export function clearChildView(kind: string): void {
  publications.delete(kind);
}

/** Resolve the closed child slot for the active onboarding kind. */
export function resolveOnboardingChild(kind: string | null | undefined): OnboardingChild | null {
  if (kind === null || kind === undefined) {
    return null;
  }
  return publications.get(kind) ?? null;
}

/** Reset all publications (test isolation / authority teardown). */
export function resetChildViews(): void {
  publications.clear();
}
