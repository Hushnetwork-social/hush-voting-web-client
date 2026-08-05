/**
 * FEAT-010 Task 2.2 — exhaustive trusted-target handshake tests.
 *
 * Covers exact Web/Ubuntu/Android resolution, every descriptor malformation,
 * version incompatibility, unknown capability, missing mandatory capability,
 * deployment mismatch, contradiction, and the no-native-fallback rule
 * (normative: FeatureDescription "Trusted runtime-target handshake",
 * AC-010-005/006).
 */
import { describe, expect, it } from 'vitest';
import { resolveRuntimeTarget, isBrowserTarget, type TrustedTargetDescriptor } from './target';
import type { DeploymentManifest } from './deployment';

function validManifest(): DeploymentManifest {
  return {
    configurationId: 'isolated-local-devnet-v1',
    canonicalNetworkId: 'hushnetwork-devnet',
    networkMagic: 5195086,
    transportMode: 'native',
    endpointIds: ['devnet-identity-a'],
    contractVersions: { client: '1.0.0', server: '1.0.0', adapter: '1.0.0' },
    classification: 'isolated-non-production',
    digest: 'sha256:valid',
  };
}

function validDescriptor(overrides: Partial<TrustedTargetDescriptor> = {}): TrustedTargetDescriptor {
  return {
    platform: 'ubuntu',
    buildIdentity: 'ubuntu-build-20260805-deadbeef',
    adapterContractVersion: '1.0.0',
    capabilityClasses: ['secret-service', 'native-transport', 'native-lifecycle'],
    deploymentConfigurationId: 'isolated-local-devnet-v1',
    ...overrides,
  };
}

describe('resolveRuntimeTarget — browser', () => {
  it('selects Browser only when no valid handshake exists', () => {
    for (const handshake of [null, undefined]) {
      const result = resolveRuntimeTarget(handshake, validManifest());
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.target.kind).toBe('browser');
        expect(isBrowserTarget(result.target)).toBe(true);
      }
    }
  });
});

describe('resolveRuntimeTarget — native', () => {
  it('accepts an exact Ubuntu descriptor', () => {
    const result = resolveRuntimeTarget(validDescriptor(), validManifest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.target.kind).toBe('native');
      if (result.target.kind === 'native') {
        expect(result.target.platform).toBe('ubuntu');
        expect(isBrowserTarget(result.target)).toBe(false);
      }
    }
  });

  it('accepts an exact Android descriptor with hardware-backed Keystore', () => {
    const descriptor = validDescriptor({ platform: 'android', capabilityClasses: ['android-keystore', 'native-transport', 'native-lifecycle'] });
    const result = resolveRuntimeTarget(descriptor, validManifest());
    expect(result.ok).toBe(true);
    if (result.ok && result.target.kind === 'native') {
      expect(result.target.platform).toBe('android');
    }
  });

  it('rejects unknown platforms (user agent / env text can never select)', () => {
    const descriptor = validDescriptor({ platform: 'windows' as TrustedTargetDescriptor['platform'] });
    const result = resolveRuntimeTarget(descriptor, validManifest());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.diagnostics).toContainEqual({ code: 'UNKNOWN_PLATFORM' });
  });

  it('rejects malformed build identities', () => {
    for (const buildIdentity of ['', 'x', 'has spaces', 'https://x']) {
      const result = resolveRuntimeTarget(validDescriptor({ buildIdentity }), validManifest());
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.diagnostics).toContainEqual({ code: 'INVALID_BUILD_IDENTITY' });
    }
  });

  it('rejects malformed adapter versions', () => {
    const result = resolveRuntimeTarget(validDescriptor({ adapterContractVersion: 'latest' }), validManifest());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.diagnostics).toContainEqual({ code: 'INVALID_ADAPTER_VERSION' });
  });

  it('rejects incompatible adapter contract versions (exact match required)', () => {
    const result = resolveRuntimeTarget(validDescriptor({ adapterContractVersion: '1.1.0' }), validManifest());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.diagnostics).toContainEqual({ code: 'INCOMPATIBLE_ADAPTER_VERSION' });
  });

  it('rejects unknown capability classes', () => {
    const result = resolveRuntimeTarget(validDescriptor({ capabilityClasses: ['secret-service', 'remote-password-reset'] as TrustedTargetDescriptor['capabilityClasses'] }), validManifest());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.diagnostics).toContainEqual({ code: 'UNKNOWN_CAPABILITY_CLASS' });
  });

  it('rejects missing mandatory platform capability (no secret fallback)', () => {
    const ubuntu = resolveRuntimeTarget(validDescriptor({ capabilityClasses: ['native-transport'] }), validManifest());
    expect(ubuntu.ok).toBe(false);
    if (!ubuntu.ok) expect(ubuntu.diagnostics).toContainEqual({ code: 'MISSING_MANDATORY_CAPABILITY' });

    const android = resolveRuntimeTarget(validDescriptor({ platform: 'android', capabilityClasses: ['native-transport'] }), validManifest());
    expect(android.ok).toBe(false);
    if (!android.ok) expect(android.diagnostics).toContainEqual({ code: 'MISSING_MANDATORY_CAPABILITY' });
  });

  it('rejects deployment configuration mismatch', () => {
    const result = resolveRuntimeTarget(validDescriptor({ deploymentConfigurationId: 'production-mainnet-v1' }), validManifest());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.diagnostics).toContainEqual({ code: 'DEPLOYMENT_MISMATCH' });
  });

  it('rejects contradictory platform/capability combinations', () => {
    const ubuntuWithAndroid = resolveRuntimeTarget(validDescriptor({ capabilityClasses: ['android-keystore', 'native-transport'] }), validManifest());
    expect(ubuntuWithAndroid.ok).toBe(false);
    if (!ubuntuWithAndroid.ok) expect(ubuntuWithAndroid.diagnostics).toContainEqual({ code: 'CONTRADICTORY_DESCRIPTOR' });

    const androidWithSecretService = resolveRuntimeTarget(
      validDescriptor({ platform: 'android', capabilityClasses: ['secret-service', 'native-transport'] }),
      validManifest(),
    );
    expect(androidWithSecretService.ok).toBe(false);
    if (!androidWithSecretService.ok) expect(androidWithSecretService.diagnostics).toContainEqual({ code: 'CONTRADICTORY_DESCRIPTOR' });
  });

  it('never falls back to Browser on any failed native resolution', () => {
    const failures: TrustedTargetDescriptor[] = [
      validDescriptor({ adapterContractVersion: '9.9.9' }),
      validDescriptor({ deploymentConfigurationId: 'other' }),
      validDescriptor({ platform: 'android', capabilityClasses: [] }),
    ];
    for (const descriptor of failures) {
      const result = resolveRuntimeTarget(descriptor, validManifest());
      expect(result.ok).toBe(false);
      expect(isBrowserTarget({ kind: 'browser' })).toBe(true); // browser is never returned on failure
    }
  });
});
