/**
 * FEAT-010 UI — typed OnboardingHost (Task 5.1).
 *
 * Mounts the real completed FEAT-007 Create User, FEAT-008 Recovery Words, or
 * FEAT-009 Credential File flow at `/` through a closed discriminated
 * `child` slot. The host forwards typed callbacks only; it owns no business
 * policy and receives no secrets. Unknown or missing child projections render
 * a typed fail-closed error — placeholder onboarding copy is never an allowed fallback
 * (AC-010-012). Back requests child cleanup before the three-choice root
 * (AC-010-084).
 *
 * Integration seam: Phase 6 feeds the child views from the auth machine's
 * projection; this component stays a thin renderer.
 */

import type { CreateUserFlowProps } from '../create/create-flow';
import { CreateUserFlow } from '../create/create-flow';
import type { RecoveryFlowProps } from '../recovery-words/recovery-flow';
import { RecoveryFlow } from '../recovery-words/recovery-flow';
import type { CredentialFileFlowProps } from '../credential-file/credential-file-flow';
import { CredentialFileFlow } from '../credential-file/credential-file-flow';

/** Closed discriminated child slot (one real completed flow per kind). */
export type OnboardingChild =
  | { readonly kind: 'createUser'; readonly props: CreateUserFlowProps }
  | { readonly kind: 'recoveryWords'; readonly props: RecoveryFlowProps }
  | { readonly kind: 'credentialFile'; readonly props: CredentialFileFlowProps };

export interface OnboardingHostProps {
  /** Selected child flow (Phase 6 supplies from the machine projection). */
  readonly child: OnboardingChild | null;
  /** Typed Back intent (authority runs child cleanup before first-run). */
  readonly onBack: () => void;
}

/** Fail-closed error surface (never placeholder onboarding copy). */
export function OnboardingError({ onBack }: { readonly onBack: () => void }) {
  return (
    <div role="alert" className="blocking-error" data-testid="onboarding-error">
      <h1>This journey cannot be opened right now.</h1>
      <p>Something is missing in this build. Go back and try again.</p>
      <button type="button" className="link-button" onClick={onBack}>
        Back
      </button>
    </div>
  );
}

/** Thin renderer: selected child → real completed flow component. */
export function OnboardingHost({ child, onBack }: OnboardingHostProps) {
  if (child === null) {
    return <OnboardingError onBack={onBack} />;
  }
  switch (child.kind) {
    case 'createUser':
      return <CreateUserFlow {...child.props} />;
    case 'recoveryWords':
      return <RecoveryFlow {...child.props} />;
    case 'credentialFile':
      return <CredentialFileFlow {...child.props} />;
    default: {
      const never: never = child;
      return never;
    }
  }
}
