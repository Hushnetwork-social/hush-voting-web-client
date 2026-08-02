/**
 * FEAT-002 page lifecycle shielding — pagehide shield + pageshow revalidation.
 *
 * Before `pagehide`, synchronously replace protected content with a
 * non-sensitive shield so browser history caches do not snapshot the
 * protected UI. On `pageshow` (including persisted restoration), render only
 * the gate until the shared authority revalidates access; the configured
 * background policy decides whether another password is required.
 *
 * Normative source: FeatureDescription "Page suspension and restoration".
 */

/** Document visibility + page-lifecycle abstraction (injected). */
export interface PageLifecycleEnvironment {
  readonly documentHidden: boolean;
  addPagehideListener(callback: () => void): void;
  addPageshowListener(callback: (persisted: boolean) => void): void;
}

export type ShieldState = 'visible' | 'shielded';

/** Synchronous protected-content shield controller. */
export class LifecycleShield {
  private state: ShieldState = 'visible';

  constructor(private readonly env: PageLifecycleEnvironment) {
    this.env.addPagehideListener(() => {
      // Synchronous: browser history caches may snapshot immediately after.
      this.state = 'shielded';
    });
    this.env.addPageshowListener((persisted) => {
      if (persisted) {
        // Render only the gate until the authority revalidates.
        this.state = 'shielded';
      } else {
        // Normal navigation back — shield stays until revalidation anyway.
        this.state = 'shielded';
      }
    });
  }

  /** Whether protected content may currently render. */
  canRenderProtected(): boolean {
    return this.state === 'visible';
  }

  /** Called by the authority after access revalidation succeeds. */
  revalidated(): void {
    this.state = 'visible';
  }

  /** Force the shield (Lock, removal, invalidation). */
  shield(): void {
    this.state = 'shielded';
  }

  /** Current shield state (for tests and render projections). */
  snapshot(): ShieldState {
    return this.state;
  }
}

/**
 * Deterministic policy: after a persisted pageshow, the gate must stay until
 * the shared authority confirms a live capability. `revalidated` is only ever
 * true when the authority reports a current opaque capability AND (for the
 * persisted case) the background policy permits continuing without a password.
 */
export function shouldShowProtectedContent(
  shield: ShieldState,
  authorityLive: boolean,
  backgroundPolicyAllows: boolean,
): boolean {
  if (shield === 'shielded') {
    return false;
  }
  return authorityLive && backgroundPolicyAllows;
}
