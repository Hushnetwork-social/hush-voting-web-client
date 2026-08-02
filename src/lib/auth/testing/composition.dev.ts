/**
 * FEAT-002 DEVELOPMENT-ONLY composition.
 *
 * Lives under `testing/` so production bundlers can tree-shake it: AuthRoot
 * imports this module ONLY inside a `process.env.NODE_ENV !== 'production'`
 * branch, which Next.js inlines to `false` in production builds. Synthetic
 * actors are therefore impossible to select AND absent from production
 * output (verified by the Phase 7 production bundle scan).
 *
 * TEST-ONLY BOUNDARY: never import this module from production composition.
 */

import type { AuthActors, CapabilityRegistration } from '../ports';
import { buildEmptyActors } from '../composition';
import {
  createAutoResolvingBrowserCoordination,
  createAutoResolvingIdentityVerification,
  createAutoResolvingLocalUserAuthority,
  createAutoResolvingNavigation,
  createAutoResolvingOnboarding,
  createAutoResolvingRemoval,
  createAutoResolvingSecretAuthority,
} from './actors.auto';

/** Result of validating and assembling a composition. */
export interface CompositionResult {
  readonly actors: AuthActors;
  readonly registrations: readonly CapabilityRegistration[];
  readonly ok: boolean;
  readonly diagnostics: readonly { code: string; capability: string }[];
}

/**
 * Development/test composition: synthetic actors wired to the machine.
 * ONLY selectable when `allowDevelopmentActors` is explicitly true. In a
 * production build this flag must resolve to false; callers gate it on
 * `process.env.NODE_ENV !== 'production'`.
 */
export function createDevelopmentComposition(allowDevelopmentActors: boolean): CompositionResult {
  if (!allowDevelopmentActors) {
    return {
      actors: buildEmptyActors(),
      registrations: [],
      ok: false,
      diagnostics: [{ code: 'DEV_ACTORS_DISALLOWED', capability: '*' }],
    };
  }

  const registrations: CapabilityRegistration[] = [
    { capability: 'localUserAuthority', availability: 'mandatory', synthetic: true },
    { capability: 'secretAuthority', availability: 'mandatory', synthetic: true },
    { capability: 'identityVerification', availability: 'mandatory', synthetic: true },
    { capability: 'browserCoordination', availability: 'mandatory', synthetic: true },
  ];

  const builder = buildEmptyActors();
  builder.localUserAuthority = createAutoResolvingLocalUserAuthority([
    { code: 'INIT_NO_LOCAL_USER' },
    { code: 'INIT_LOCKED_USER', safeIdentity: { alias: 'Demo User', abbreviatedSigningAddress: 'NVh…demo' } },
  ]);
  builder.secretAuthority = createAutoResolvingSecretAuthority([
    { code: 'UNLOCK_SUCCESS' },
    { code: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' },
  ]);
  builder.identityVerification = createAutoResolvingIdentityVerification([
    { code: 'VERIFY_SUCCESS' },
    { code: 'VERIFY_NETWORK_UNAVAILABLE' },
  ]);
  builder.onboarding = {
    createUser: createAutoResolvingOnboarding([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'dev-user-ref' }]),
    restoreCredentialFile: createAutoResolvingOnboarding([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'dev-user-ref' }]),
    restoreRecoveryWords: createAutoResolvingOnboarding([{ code: 'ONBOARDING_COMPLETED', localUserRef: 'dev-user-ref' }]),
  };
  builder.removal = createAutoResolvingRemoval([{ code: 'REMOVAL_COMPLETE' }]);
  builder.browserCoordination = createAutoResolvingBrowserCoordination([{ code: 'COORDINATION_SAFE' }]);
  builder.navigation = createAutoResolvingNavigation();
  const actors = builder as AuthActors;

  return { actors, registrations, ok: true, diagnostics: [] };
}
