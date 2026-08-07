/**
 * FEAT-010 web composition (Task 7.3) — one real browser actor graph.
 *
 * Assembles the FEAT-002 web ports over the sealed browser-vault client:
 * local-user authority, secret authority, identity verification, browser
 * coordination, removal, and the three onboarding child ports. The client
 * connects to the first-party SharedWorker (`/workers/vault-shared-worker.js`)
 * with an exact build handshake; a failed handshake never falls back.
 *
 * One client + one actor set per application instance (the SharedWorker
 * authority itself is shared across tabs by construction).
 *
 * Normative source: FEAT-010 FeatureDescription "Real Composition";
 * AC-010-001/003/004/006.
 */

import { BrowserVaultClient, type ClientAppIdentity } from '../../browser-vault/production/client';
import { createWebLocalUserAuthority, createWebSecretAuthority, createWebIdentityVerification, createWebBrowserCoordination, createWebRemoval } from './web-actors';
import { createWebOnboardingPorts, createBridgeBffLookup, type ChildBridgeContext } from './child-bridge';
import type { AuthActors, CapabilityRegistration } from '../ports';
import { buildEmptyActors } from '../composition';
import type { DeploymentManifest } from '../../runtime/deployment';
import type { CapabilityId } from '../types';

/** Application build identity used by the exact handshake. */
export const WEB_APP_IDENTITY: ClientAppIdentity = {
  appVersion: '0.1.0',
};

/** The one browser-vault client for this application instance. */
export interface WebComposition {
  readonly client: BrowserVaultClient;
  readonly actors: AuthActors;
  readonly registrations: readonly CapabilityRegistration[];
}

let singleton: WebComposition | null = null;

/** Build (or reuse) the real web actor graph for a resolved manifest. */
export function getWebComposition(manifest: DeploymentManifest): WebComposition {
  if (singleton !== null) {
    return singleton;
  }
  const client = new BrowserVaultClient({
    appIdentity: WEB_APP_IDENTITY,
    runtimeConfigId: 'development-localhost',
  });
  const ctx: ChildBridgeContext = {
    client,
    manifest,
    lookupIdentity: createBridgeBffLookup(),
    randomId: (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
  };

  const onboardingPorts = createWebOnboardingPorts(ctx);
  const builder = buildEmptyActors();
  builder.localUserAuthority = createWebLocalUserAuthority(client);
  builder.secretAuthority = createWebSecretAuthority(client);
  builder.identityVerification = createWebIdentityVerification(client);
  builder.browserCoordination = createWebBrowserCoordination(client);
  builder.removal = createWebRemoval(client, async () => {
    const issued = await client.issueCapability('removeLocalUser');
    return issued.capabilityId;
  });
  builder.onboarding = {
    createUser: onboardingPorts.createUser,
    restoreCredentialFile: onboardingPorts.restoreCredentialFile,
    restoreRecoveryWords: onboardingPorts.restoreRecoveryWords,
  };

  const registrations: CapabilityRegistration[] = [
    { capability: 'localUserAuthority', availability: 'mandatory', synthetic: false },
    { capability: 'secretAuthority', availability: 'mandatory', synthetic: false },
    { capability: 'identityVerification', availability: 'mandatory', synthetic: false },
    { capability: 'browserCoordination', availability: 'mandatory', synthetic: false },
    { capability: 'removal', availability: 'mandatory', synthetic: false },
    { capability: 'onboardingCreateUser', availability: 'mandatory', synthetic: false },
    { capability: 'onboardingRestoreCredentialFile', availability: 'mandatory', synthetic: false },
    { capability: 'onboardingRestoreRecoveryWords', availability: 'mandatory', synthetic: false },
  ];

  const composition: WebComposition = { client, actors: builder as AuthActors, registrations };
  singleton = composition;
  return composition;
}

/** SecretSubmissionSink bridge: route a UI secret to the sealed authority.
 * The client owns reconnection (the machine cancels completed actors, which
 * bumps the worker epoch); this bridge never drops a secret. */
export function submitWebSecret(operationId: string, secret: string): void {
  if (singleton !== null) {
    singleton.client.submitSecret(operationId, 'devicePassword', secret);
  }
}

/** Authenticated Lock: wipe the worker-held session before closing the UI gate. */
export async function lockWebSession(): Promise<boolean> {
  if (singleton === null) return false;
  const outcome = await singleton.client.dispatch('lockAll');
  return outcome.outcome === 'OK';
}

/** Reset the singleton (test isolation). */
export function resetWebComposition(): void {
  singleton?.client.close();
  singleton = null;
}

/** Capability ids the web composition backs. */
export const WEB_CAPABILITIES: readonly CapabilityId[] = [
  'localUserAuthority',
  'secretAuthority',
  'identityVerification',
  'browserCoordination',
  'removal',
  'onboardingCreateUser',
  'onboardingRestoreCredentialFile',
  'onboardingRestoreRecoveryWords',
];
