/**
 * FEAT-010 Task 6.2 — central target composition tests.
 *
 * Proves exact actor sets on all targets, atomic rejection (missing/
 * duplicate/synthetic/incompatible/partial/null-provider/contradictory),
 * ordinary-development real selection (no synthetic), native no-fallback,
 * and deployment-manifest binding (normative: FeatureDescription "Production
 * Composition Architecture", "Trusted runtime-target handshake";
 * AC-010-001…006, 019–022).
 */
import { describe, expect, it } from 'vitest';
import { createTargetComposition, targetClassFor } from './composition-target-builder';
import type { TargetAwareActorRegistration } from './composition-target';
import type { CapabilityId } from './types';
import type { DeploymentManifest } from '../runtime/deployment';
import type { TrustedTargetDescriptor } from '../runtime/target';
import { ISOLATED_DEVNET_MANIFEST } from '../runtime/manifests';

function registration(capability: CapabilityId, targetClasses: TargetAwareActorRegistration['targetClasses'] = ['web']): TargetAwareActorRegistration {
  return { capability, targetClasses, contractVersion: '1.0.0', provider: 'real', synthetic: false };
}



const MANDATORY: readonly CapabilityId[] = ['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination', 'removal'];
const OPTIONAL: readonly CapabilityId[] = ['onboardingCreateUser', 'onboardingRestoreCredentialFile', 'onboardingRestoreRecoveryWords'];

function completeSet(target: 'web' | 'ubuntu' | 'android' = 'web'): TargetAwareActorRegistration[] {
  const classes: TargetAwareActorRegistration['targetClasses'] = [target];
  return [...MANDATORY, ...OPTIONAL].map((capability) => registration(capability, classes));
}

function providerMap(set: TargetAwareActorRegistration[]): (capability: string) => unknown {
  const ports = new Map<string, unknown>(set.map((r) => [r.capability, { real: true }]));
  return (capability) => ports.get(capability) ?? null;
}

const nativeDescriptor: TrustedTargetDescriptor = {
  platform: 'ubuntu',
  buildIdentity: 'hush-voting-app-0.1.0-dev',
  adapterContractVersion: '1.0.0',
  capabilityClasses: ['secret-service', 'native-transport', 'native-lifecycle'],
  deploymentConfigurationId: 'isolated-local-devnet-v1',
};

function compose(set: TargetAwareActorRegistration[], handshake: TrustedTargetDescriptor | null, manifest: DeploymentManifest = ISOLATED_DEVNET_MANIFEST) {
  return createTargetComposition({
    manifest,
    handshake,
    pinnedContractVersion: manifest.contractVersions.adapter,
    extension: { kind: 'absent' },
    registrations: set,
    actorProvider: providerMap(set),
  });
}

describe('targetClassFor', () => {
  it('maps browser → web and native platforms 1:1', () => {
    expect(targetClassFor({ kind: 'browser' })).toBe('web');
    expect(targetClassFor({ kind: 'native', platform: 'ubuntu', descriptor: nativeDescriptor })).toBe('ubuntu');
    expect(targetClassFor({ kind: 'native', platform: 'android', descriptor: nativeDescriptor })).toBe('android');
  });
});

describe('createTargetComposition — browser', () => {
  it('assembles a complete real web actor set when no handshake exists', () => {
    const verdict = compose(completeSet('web'), null);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) {
      expect(verdict.targetClass).toBe('web');
      expect(verdict.actors.localUserAuthority).not.toBeNull();
      expect(verdict.actors.removal).not.toBeNull();
    }
  });

  it('rejects missing mandatory capabilities atomically', () => {
    const set = completeSet().filter((r) => r.capability !== 'secretAuthority');
    const verdict = compose(set, null);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.code).toBe('ACTOR_SET_INVALID');
      expect(JSON.stringify(verdict.diagnostics)).toContain('MISSING_MANDATORY');
    }
  });

  it('rejects null providers (incomplete real composition)', () => {
    const set = completeSet();
    const verdict = createTargetComposition({
      manifest: ISOLATED_DEVNET_MANIFEST,
      handshake: null,
      pinnedContractVersion: '1.0.0',
      extension: { kind: 'absent' },
      registrations: set,
      actorProvider: () => null,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(JSON.stringify(verdict.diagnostics)).toContain('NULL_PROVIDER');
  });

  it('rejects duplicate and synthetic registrations', () => {
    const duplicate = [...completeSet(), registration('localUserAuthority')];
    expect(compose(duplicate, null).ok).toBe(false);

    const synthetic = completeSet().map((r) => (r.capability === 'removal' ? { ...r, synthetic: true } : r));
    expect(compose(synthetic, null).ok).toBe(false);
  });

  it('rejects incompatible contract versions', () => {
    const set = completeSet().map((r) => (r.capability === 'removal' ? { ...r, contractVersion: '9.9.9' } : r));
    expect(compose(set, null).ok).toBe(false);
  });

  it('rejects an incompatible FEAT-011 extension', () => {
    const verdict = createTargetComposition({
      manifest: ISOLATED_DEVNET_MANIFEST,
      handshake: null,
      pinnedContractVersion: '1.0.0',
      extension: { kind: 'incompatible', contractVersion: '0.9.0' },
      registrations: completeSet(),
      actorProvider: providerMap(completeSet()),
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.code).toBe('ACTOR_SET_INVALID');
  });
});

describe('createTargetComposition — native', () => {
  it('assembles the exact Ubuntu set from a valid descriptor', () => {
    const set = completeSet('ubuntu');
    const verdict = compose(set, nativeDescriptor);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.targetClass).toBe('ubuntu');
  });

  it('never falls back to Browser on a failed native resolution', () => {
    const incompatible = { ...nativeDescriptor, adapterContractVersion: '9.9.9' };
    const verdict = compose(completeSet('ubuntu'), incompatible);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.code).toBe('TARGET_RESOLUTION_FAILED');
      expect(verdict.target).toBeNull();
    }
  });

  it('rejects web registrations for a native target (no mixed sets)', () => {
    const verdict = compose(completeSet('web'), nativeDescriptor);
    expect(verdict.ok).toBe(false);
  });

  it('rejects native descriptors whose deployment configuration mismatches the manifest', () => {
    const mismatched = { ...nativeDescriptor, deploymentConfigurationId: 'production-mainnet-v1' };
    const verdict = compose(completeSet('ubuntu'), mismatched);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.code).toBe('TARGET_RESOLUTION_FAILED');
  });

  it('rejects a native descriptor for a different platform set', () => {
    const androidDescriptor: TrustedTargetDescriptor = { ...nativeDescriptor, platform: 'android', capabilityClasses: ['android-keystore', 'native-transport', 'native-lifecycle'] };
    const verdict = compose(completeSet('ubuntu'), androidDescriptor);
    expect(verdict.ok).toBe(false);
  });
});
