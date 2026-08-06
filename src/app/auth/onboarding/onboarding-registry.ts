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
const listeners = new Set<() => void>();

/** Publish the current child view for a kind (child authority adapters). */
export function publishChildView(kind: string, child: OnboardingChild): void {
  publications.set(kind, child);
  notify();
}

/** Clear a publication (child cleanup/back). */
export function clearChildView(kind: string): void {
  publications.delete(kind);
  notify();
}

/** Resolve the closed child slot for the active onboarding kind. */
export function resolveOnboardingChild(kind: string | null | undefined): OnboardingChild | null {
  if (kind === null || kind === undefined) {
    return null;
  }
  return publications.get(kind) ?? null;
}

/** Subscribe to child-view publications (renderer re-render trigger). */
export function subscribeChildViews(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function notify(): void {
  for (const listener of listeners) {
    listener();
  }
}

/** Reset all publications (test isolation / authority teardown). */
export function resetChildViews(): void {
  publications.clear();
  notify();
}
