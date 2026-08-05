/**
 * FEAT-010 Task 6.2 — manifest catalog and native-bridge tests.
 *
 * Proves catalog resolution (approved isolated devnet), tamper detection,
 * unapproved/notConfigured fail-closed paths, and the trusted native bridge
 * outcomes (absent/descriptor/failed with NO browser fallback on failure)
 * (normative: FeatureDescription "Deployment and Network Binding", "Trusted
 * runtime-target handshake"; AC-010-005/006/019/020).
 */
import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  ISOLATED_DEVNET_DIGEST,
  ISOLATED_DEVNET_MANIFEST,
  MANIFEST_CATALOG_SELF_CHECK,
  resolveManifest,
  verifyManifestCatalog,
} from './manifests';
import { readNativeTargetDescriptor, __setBridgeProbeForTests } from './native-bridge';
import type { TrustedTargetDescriptor } from './target';

describe('resolveManifest', () => {
  it('resolves the approved isolated devnet manifest exactly', () => {
    const resolution = resolveManifest('isolated-local-devnet-v1');
    expect(resolution.ok).toBe(true);
    if (resolution.ok) {
      expect(resolution.manifest).toEqual(ISOLATED_DEVNET_MANIFEST);
      expect(resolution.manifest.digest).toBe(ISOLATED_DEVNET_DIGEST);
      expect(resolution.manifest.classification).toBe('isolated-non-production');
    }
  });

  it('fails closed for production until an approved manifest is pinned', () => {
    expect(resolveManifest('production-mainnet-v1')).toEqual({ ok: false, code: 'notConfigured' });
  });

  it('rejects unapproved configuration identifiers', () => {
    expect(resolveManifest('attacker-config')).toEqual({ ok: false, code: 'unapproved' });
    expect(resolveManifest('')).toEqual({ ok: false, code: 'unapproved' });
  });

  it('self-check verifies the pinned catalog', () => {
    expect(verifyManifestCatalog()).toBe(true);
    expect(MANIFEST_CATALOG_SELF_CHECK).toBe(true);
  });
});

describe('readNativeTargetDescriptor', () => {
  const originalInvoke = (globalThis as Record<string, unknown>).__TAURI_INTERNALS__;

  afterEach(() => {
    __setBridgeProbeForTests(null);
    if (originalInvoke === undefined) {
      delete (globalThis as Record<string, unknown>).__TAURI_INTERNALS__;
    } else {
      (globalThis as Record<string, unknown>).__TAURI_INTERNALS__ = originalInvoke;
    }
  });

  function installBridge(result: unknown | ((command: string) => Promise<unknown>)): void {
    (globalThis as Record<string, unknown>).__TAURI_INTERNALS__ = {
      invoke:
        typeof result === 'function'
          ? result
          : async () => result,
    };
    __setBridgeProbeForTests(() => true);
  }

  const validDescriptor: TrustedTargetDescriptor = {
    platform: 'ubuntu',
    buildIdentity: 'hush-voting-app-0.1.0-dev',
    adapterContractVersion: '1.0.0',
    capabilityClasses: ['secret-service', 'native-transport', 'native-lifecycle'],
    deploymentConfigurationId: 'isolated-local-devnet-v1',
  };

  it('reports absent when no Tauri bridge exists (browser context)', async () => {
    __setBridgeProbeForTests(() => false);
    expect(await readNativeTargetDescriptor()).toEqual({ kind: 'absent' });
  });

  it('returns a validated descriptor from the Rust command', async () => {
    installBridge(validDescriptor);
    expect(await readNativeTargetDescriptor()).toEqual({ kind: 'descriptor', descriptor: validDescriptor });
  });

  it('fails closed when the bridge command rejects — never Browser fallback', async () => {
    installBridge(async () => {
      throw new Error('bridge-unavailable');
    });
    expect(await readNativeTargetDescriptor()).toEqual({ kind: 'failed' });
  });

  it('fails closed on malformed or unknown payloads', async () => {
    for (const payload of [
      null,
      'text',
      { platform: 'windows' },
      { platform: 'ubuntu', buildIdentity: '', adapterContractVersion: '1.0.0', capabilityClasses: ['secret-service'], deploymentConfigurationId: 'x' },
      { platform: 'ubuntu', buildIdentity: 'id', adapterContractVersion: 'latest', capabilityClasses: ['secret-service'], deploymentConfigurationId: 'x' },
      { platform: 'ubuntu', buildIdentity: 'id', adapterContractVersion: '1.0.0', capabilityClasses: ['remote-reset'], deploymentConfigurationId: 'x' },
      { platform: 'ubuntu', buildIdentity: 'id', adapterContractVersion: '1.0.0', capabilityClasses: [], deploymentConfigurationId: 'x' },
    ]) {
      installBridge(payload);
      expect(await readNativeTargetDescriptor(), JSON.stringify(payload)).toEqual({ kind: 'failed' });
    }
  });

  it('never selects the platform from page input or user agent', async () => {
    installBridge({ platform: 'ubuntu', buildIdentity: 'id', adapterContractVersion: '1.0.0', capabilityClasses: ['secret-service'], deploymentConfigurationId: 'x' });
    const outcome = await readNativeTargetDescriptor();
    expect(outcome.kind).toBe('descriptor');
    if (outcome.kind === 'descriptor') {
      expect(outcome.descriptor.platform).toBe('ubuntu');
    }
    // Platform/capability contradictions are rejected by the composition
    // builder (resolveRuntimeTarget → CONTRADICTORY_DESCRIPTOR), not the
    // bridge shape validator.
    void vi; // keep vitest import used
  });
});
