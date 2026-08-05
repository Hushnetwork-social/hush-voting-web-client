/**
 * FEAT-010 presentation logic — root/onboarding/verification/navigation
 * projections (Task 4.1).
 *
 * Maps authoritative state into ONE closed secret-free render model for
 * startup, first-run, child flows, staged resume, root verification,
 * missing-profile confirmation, quarantine, and blocked states. React decides
 * copy/actions/focus only; it never decides business transitions or holds
 * secrets. Placeholder onboarding copy is not an allowed fallback: unknown/missing child
 * projections produce a typed blocking screen (AC-010-012).
 *
 * Post-Lock resume permits only home or settings landing (AC-010-085); forms,
 * confirmations, revealed content, and pending operations never resume.
 *
 * Framework-neutral, secret-free.
 */
import type { ChildFlowKind } from '../child-flow';
import type { StagedKind } from '../../vault-core/contracts/startup-inspection';

/** Quarantine reasons (closed). */
export type QuarantineReason = 'corrupt' | 'unsupported' | 'contradictory' | 'incompleteRemoval';

/** Closed root screens (one deterministic projection per state). */
export type RootScreen =
  | { readonly kind: 'startup' }
  | { readonly kind: 'firstRun' }
  | { readonly kind: 'childFlow'; readonly childKind: ChildFlowKind }
  | { readonly kind: 'stagedResume'; readonly stagedKind: StagedKind; readonly title: string }
  | { readonly kind: 'verification'; readonly retryAllowed: boolean }
  | { readonly kind: 'missingProfile' }
  | { readonly kind: 'quarantine'; readonly reason: QuarantineReason }
  | { readonly kind: 'blocked'; readonly supportCode: string }
  | { readonly kind: 'locked' }
  | { readonly kind: 'home' }
  | { readonly kind: 'settingsLanding' };

/** Exhaustive input view of authority state (secret-free). */
export interface RootStateView {
  readonly phase: 'initializing' | 'noLocalUser' | 'onboarding' | 'verifying' | 'missingProfile' | 'quarantine' | 'blocked' | 'locked' | 'authenticated';
  readonly childKind?: ChildFlowKind;
  readonly stagedKind?: StagedKind;
  readonly retryAllowed?: boolean;
  readonly supportCode?: string;
  readonly quarantineReason?: QuarantineReason;
}

/** Exact staged-resume copy (AC-010-025). */
export const STAGED_RESUME_TITLES: Readonly<Record<StagedKind, string>> = {
  createUser: 'Resume creating your identity',
  recoveryWords: 'Finish restoring your identity',
  credentialFile: 'Finish restoring your identity',
} as const;

/** Deterministic state → root screen mapping. */
export function projectRootScreen(state: RootStateView): RootScreen {
  switch (state.phase) {
    case 'initializing':
      return { kind: 'startup' };
    case 'noLocalUser':
      return { kind: 'firstRun' };
    case 'onboarding':
      if (state.childKind === undefined) {
        // Unknown/missing child projection → typed blocking error; NEVER
        // placeholder onboarding copy as a completion substitute (AC-010-012).
        return { kind: 'blocked', supportCode: state.supportCode ?? 'ROOT-NO-CHILD' };
      }
      return { kind: 'childFlow', childKind: state.childKind };
    case 'verifying':
      return { kind: 'verification', retryAllowed: state.retryAllowed ?? false };
    case 'missingProfile':
      return { kind: 'missingProfile' };
    case 'quarantine':
      return { kind: 'quarantine', reason: state.quarantineReason ?? 'contradictory' };
    case 'blocked':
      return { kind: 'blocked', supportCode: state.supportCode ?? 'ROOT-BLOCKED' };
    case 'locked':
      return { kind: 'locked' };
    case 'authenticated':
      return { kind: 'home' };
    default: {
      // Exhaustiveness guard: a new phase must be handled explicitly.
      const never: never = state.phase;
      return never;
    }
  }
}

/** Staged-resume projection (title per staged kind). */
export function projectStagedResume(stagedKind: StagedKind): { readonly kind: 'stagedResume'; readonly stagedKind: StagedKind; readonly title: string } {
  return { kind: 'stagedResume', stagedKind, title: STAGED_RESUME_TITLES[stagedKind] };
}

/** Safe post-Lock resume destinations (AC-010-085). */
export type SafeResumeDestination = 'home' | 'settingsLanding';

/**
 * Resolve an in-memory pre-Lock destination after fresh authentication.
 * ONLY home or settings landing may resume; password/protection forms,
 * fresh-authorization prompts, export, confirmations, revealed content, and
 * pending secret operations restart safely.
 */
export function safeResumeDestination(destination: string | null | undefined): SafeResumeDestination | null {
  if (destination === 'home' || destination === 'settingsLanding') {
    return destination;
  }
  return null;
}

/** Typed Back intent for child flows (cleanup acknowledged before first-run). */
export type ChildBackVerdict = { readonly kind: 'cleanupPending' } | { readonly kind: 'cleanupComplete' };

export function projectChildBack(cleanupAcknowledged: boolean): ChildBackVerdict {
  return cleanupAcknowledged ? { kind: 'cleanupComplete' } : { kind: 'cleanupPending' };
}
