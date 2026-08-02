/**
 * FEAT-002 production application composition — explicit registration,
 * fail-closed, and dev/test-actor gated.
 *
 * Builds ONE `AuthActors` set from explicit capability registrations.
 * Missing downstream production actors (FEAT-003–010) yield `null` ports; the
 * machine then fails closed (blockedError / SESSION.AUTHORITY_LOST). Test,
 * demonstration, development bypass, and in-memory fake actors are impossible
 * to select in production builds: `createProductionComposition` never contains
 * synthetic actors, and `createDevelopmentComposition` requires an explicit
 * non-production flag.
 *
 * Normative source: FeatureDescription "Authority and Dependencies",
 * "Production actor registration is explicit and fail-closed", acceptance
 * criteria 22 and 6, security invariants.
 */

import type { AuthActors, AuthActorsBuilder, CapabilityRegistration, NavigationPort } from './ports';
import { validateProductionRegistry } from './registry';
import { InMemoryNavigationStack } from './navigation/navigation';
import {
  createBrowserCoordinationTestActor,
  createIdentityVerificationTestActor,
  createLocalUserAuthorityTestActor,
  createNavigationTestActor,
  createSecretAuthorityTestActor,
} from './testing/actors';

/** Production-safe in-memory navigation port (no persistence, no secrets). */
function productionNavigationPort(): NavigationPort {
  const stack = new InMemoryNavigationStack();
  return {
    push(destination) {
      return stack.push(destination);
    },
    resolve(token) {
      return stack.resolve(token);
    },
    clear() {
      stack.reset();
    },
  };
}

/** Result of validating and assembling a composition. */
export interface CompositionResult {
  readonly actors: AuthActors;
  readonly registrations: readonly CapabilityRegistration[];
  readonly ok: boolean;
  readonly diagnostics: readonly { code: string; capability: string }[];
}

/**
 * Build the production composition from explicit registrations.
 * `actorProvider(capability)` returns the real port or null (not registered).
 * Synthetic registrations are rejected outright.
 */
export function createProductionComposition(
  registrations: readonly CapabilityRegistration[],
  actorProvider: (capability: CapabilityRegistration['capability']) => unknown,
): CompositionResult {
  const validation = validateProductionRegistry(registrations);
  if (!validation.ok) {
    return {
      actors: emptyActors(),
      registrations,
      ok: false,
      diagnostics: validation.diagnostics.map((d) => ({ code: d.code, capability: d.capability })),
    };
  }

  const builder = buildActors();
  for (const registration of registrations) {
    if (registration.synthetic) {
      continue; // unreachable: validation already rejected synthetic in production
    }
    const port = actorProvider(registration.capability);
    assignPort(builder, registration.capability, port);
  }
  const actors = builder as AuthActors;

  return { actors, registrations, ok: true, diagnostics: [] };
}

/** A fully null actor set (all flows fail closed until registered). */
export function emptyActors(): AuthActors {
  return buildActors();
}

/** Mutable builder; the result is frozen into the public AuthActors shape. */
function buildActors(): AuthActorsBuilder {
  return {
    localUserAuthority: null,
    secretAuthority: null,
    identityVerification: null,
    onboarding: {
      createUser: null,
      restoreCredentialFile: null,
      restoreRecoveryWords: null,
    },
    removal: null,
    browserCoordination: null,
    navigation: productionNavigationPort(),
    telemetry: null,
  };
}

function assignPort(actors: AuthActorsBuilder, capability: CapabilityRegistration['capability'], port: unknown): void {
  switch (capability) {
    case 'localUserAuthority':
      actors.localUserAuthority = port as AuthActors['localUserAuthority'];
      break;
    case 'secretAuthority':
      actors.secretAuthority = port as AuthActors['secretAuthority'];
      break;
    case 'identityVerification':
      actors.identityVerification = port as AuthActors['identityVerification'];
      break;
    case 'onboardingCreateUser':
      actors.onboarding.createUser = port as AuthActors['onboarding']['createUser'];
      break;
    case 'onboardingRestoreCredentialFile':
      actors.onboarding.restoreCredentialFile = port as AuthActors['onboarding']['restoreCredentialFile'];
      break;
    case 'onboardingRestoreRecoveryWords':
      actors.onboarding.restoreRecoveryWords = port as AuthActors['onboarding']['restoreRecoveryWords'];
      break;
    case 'removal':
      actors.removal = port as AuthActors['removal'];
      break;
    case 'browserCoordination':
      actors.browserCoordination = port as AuthActors['browserCoordination'];
      break;
    case 'temporaryMode':
      // temporaryMode is a capability flag, not an actor port.
      break;
  }
}

/**
 * Development/test composition: synthetic actors wired to the machine.
 * ONLY selectable when `allowDevelopmentActors` is explicitly true. In a
 * production build this flag must resolve to false; callers gate it on
 * `process.env.NODE_ENV !== 'production'` or an equivalent explicit switch.
 */
export function createDevelopmentComposition(allowDevelopmentActors: boolean): CompositionResult {
  if (!allowDevelopmentActors) {
    return { actors: emptyActors(), registrations: [], ok: false, diagnostics: [{ code: 'DEV_ACTORS_DISALLOWED', capability: '*' }] };
  }

  const registrations: CapabilityRegistration[] = [
    { capability: 'localUserAuthority', availability: 'mandatory', synthetic: true },
    { capability: 'secretAuthority', availability: 'mandatory', synthetic: true },
    { capability: 'identityVerification', availability: 'mandatory', synthetic: true },
    { capability: 'browserCoordination', availability: 'mandatory', synthetic: true },
  ];

  const builder = buildActors();
  builder.localUserAuthority = createLocalUserAuthorityTestActorForComposition();
  builder.secretAuthority = createSecretAuthorityTestActorForComposition();
  builder.identityVerification = createIdentityVerificationTestActorForComposition();
  builder.browserCoordination = createBrowserCoordinationTestActorForComposition();
  builder.navigation = createNavigationTestActor();
  const actors = builder as AuthActors;

  return { actors, registrations, ok: true, diagnostics: [] };
}

// Dev-only synthetic actors (imported from the test kit; never used by
// createProductionComposition). Kept explicit so production bundlers can
// tree-shake them when the development composition is not imported.
function createLocalUserAuthorityTestActorForComposition() {
  return createLocalUserAuthorityTestActor([
    { code: 'INIT_NO_LOCAL_USER' },
    { code: 'INIT_LOCKED_USER', safeIdentity: { alias: 'Demo User', abbreviatedSigningAddress: 'NVh…demo' } },
  ]);
}

function createSecretAuthorityTestActorForComposition() {
  return createSecretAuthorityTestActor([
    { code: 'UNLOCK_SUCCESS' },
    { code: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' },
  ]);
}

function createIdentityVerificationTestActorForComposition() {
  return createIdentityVerificationTestActor([
    { code: 'VERIFY_SUCCESS' },
    { code: 'VERIFY_NETWORK_UNAVAILABLE' },
  ]);
}

function createBrowserCoordinationTestActorForComposition() {
  return createBrowserCoordinationTestActor([{ code: 'COORDINATION_SAFE' }]);
}
