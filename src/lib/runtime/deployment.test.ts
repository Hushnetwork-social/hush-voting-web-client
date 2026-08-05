/**
 * FEAT-010 Task 2.2 — exhaustive deployment-manifest contract tests.
 *
 * Covers every legal manifest combination and every malformed, unknown,
 * cross-network, arbitrary-input, duplicate, digest, and rotation rejection
 * (normative: FeatureDescription "Deployment and Network Binding",
 * AC-010-019…022).
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  canRotateEndpoint,
  canonicalManifestJson,
  isProductionManifest,
  parseDeploymentManifest,
  type DeploymentManifest,
} from './deployment';

/** Deterministic sha256 digest for manifest pinning (BFF uses node:crypto). */
const sha256 = (canonical: string): string => createHash('sha256').update(canonical).digest('hex');

function validManifest(overrides: Partial<DeploymentManifest> = {}): DeploymentManifest {
  const rest = { ...DEFAULT_MANIFEST, ...overrides };
  const withoutDigest: Omit<DeploymentManifest, 'digest'> = {
    configurationId: rest.configurationId,
    canonicalNetworkId: rest.canonicalNetworkId,
    networkMagic: rest.networkMagic,
    transportMode: rest.transportMode,
    endpointIds: rest.endpointIds,
    contractVersions: rest.contractVersions,
    classification: rest.classification,
  };
  return { ...withoutDigest, digest: sha256(canonicalManifestJson(withoutDigest)) };
}

const DEFAULT_MANIFEST: Omit<DeploymentManifest, 'digest'> = {
  configurationId: 'isolated-local-devnet-v1',
  canonicalNetworkId: 'hushnetwork-devnet',
  networkMagic: 5195086,
  transportMode: 'bff',
  endpointIds: ['devnet-identity-a', 'devnet-identity-b'],
  contractVersions: { client: '1.0.0', server: '1.0.0', adapter: '1.0.0' },
  classification: 'isolated-non-production',
};

describe('parseDeploymentManifest', () => {
  it('accepts a fully valid manifest with matching digest', () => {
    const manifest = validManifest();
    const result = parseDeploymentManifest(manifest, sha256);
    expect(result.ok).toBe(true);
    expect(result.manifest?.configurationId).toBe('isolated-local-devnet-v1');
    expect(result.manifest?.networkMagic).toBe(5195086);
  });

  it('rejects non-object payloads', () => {
    for (const payload of [null, undefined, 42, 'text', [], true]) {
      const result = parseDeploymentManifest(payload, sha256);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'NOT_AN_OBJECT' });
    }
  });

  it('rejects unknown fields (arbitrary user input cannot control behavior)', () => {
    const manifest = validManifest() as unknown as Record<string, unknown>;
    manifest.endpointOverride = 'https://evil.example';
    const result = parseDeploymentManifest(manifest, sha256);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'UNKNOWN_FIELD' });
  });

  it('rejects invalid configuration and network identifiers', () => {
    const manifest = validManifest({ configurationId: 'has space', canonicalNetworkId: 'https://x' });
    const result = parseDeploymentManifest(manifest, sha256);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_CONFIGURATION_ID' });
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_NETWORK_ID' });
  });

  it('rejects invalid, unsafe, or missing network magic', () => {
    for (const magic of [0, -1, 1.5, NaN, '5195086']) {
      const manifest = validManifest({ networkMagic: magic as number });
      const result = parseDeploymentManifest(manifest, sha256);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'INVALID_NETWORK_MAGIC' });
    }
  });

  it('rejects invalid transport modes', () => {
    for (const mode of ['grpc', 'websocket', '', 1]) {
      const manifest = validManifest({ transportMode: mode as DeploymentManifest['transportMode'] });
      const result = parseDeploymentManifest(manifest, sha256);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'INVALID_TRANSPORT_MODE' });
    }
  });

  it('rejects empty, duplicate, or URL-shaped endpoint IDs', () => {
    const empty = validManifest({ endpointIds: [] });
    expect(parseDeploymentManifest(empty, sha256).diagnostics).toContainEqual({ code: 'NO_ENDPOINTS' });

    const duplicate = validManifest({ endpointIds: ['devnet-identity-a', 'devnet-identity-a'] });
    expect(parseDeploymentManifest(duplicate, sha256).diagnostics).toContainEqual({ code: 'DUPLICATE_ENDPOINT' });

    const urlShaped = validManifest({ endpointIds: ['https://example.com/rpc'] });
    expect(parseDeploymentManifest(urlShaped, sha256).diagnostics).toContainEqual({ code: 'INVALID_ENDPOINT_ID' });
  });

  it('rejects non-pinned, non-semver contract versions', () => {
    const manifest = validManifest({ contractVersions: { client: 'latest', server: '1.0.0', adapter: '1.0.0' } });
    const result = parseDeploymentManifest(manifest, sha256);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_CONTRACT_VERSION' });
  });

  it('rejects invalid classification values', () => {
    const manifest = validManifest({ classification: 'staging' as DeploymentManifest['classification'] });
    const result = parseDeploymentManifest(manifest, sha256);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_CLASSIFICATION' });
  });

  it('rejects content tampering even when the digest field is copied along', () => {
    const manifest = validManifest();
    const tampered = { ...manifest, endpointIds: ['attacker-endpoint'] };
    const result = parseDeploymentManifest(tampered, sha256);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'DIGEST_MISMATCH' });
  });

  it('rejects when the digest field itself is missing or malformed', () => {
    const missing = validManifest() as unknown as Record<string, unknown>;
    delete missing.digest;
    expect(parseDeploymentManifest(missing, sha256).diagnostics).toContainEqual({ code: 'DIGEST_MISMATCH' });

    const wrong = { ...validManifest(), digest: 'not-the-digest' };
    expect(parseDeploymentManifest(wrong, sha256).diagnostics).toContainEqual({ code: 'DIGEST_MISMATCH' });
  });
});

describe('canRotateEndpoint', () => {
  it('allows rotation between manifests on the same canonical network with pinned versions', () => {
    const from = validManifest();
    const to = validManifest({ configurationId: 'isolated-local-devnet-v2', endpointIds: ['devnet-identity-c'] });
    expect(canRotateEndpoint(from, to)).toBe(true);
  });

  it('rejects rotation across different network identifiers', () => {
    const from = validManifest();
    const to = validManifest({ canonicalNetworkId: 'hushnetwork-mainnet' });
    expect(canRotateEndpoint(from, to)).toBe(false);
  });

  it('rejects rotation across different network magic values', () => {
    const from = validManifest();
    const to = validManifest({ networkMagic: 12345 });
    expect(canRotateEndpoint(from, to)).toBe(false);
  });

  it('rejects rotation when client/server contract pins drift', () => {
    const from = validManifest();
    const to = validManifest({ contractVersions: { client: '1.1.0', server: '1.0.0', adapter: '1.0.0' } });
    expect(canRotateEndpoint(from, to)).toBe(false);
  });
});

describe('isProductionManifest', () => {
  it('classifies production vs isolated manifests', () => {
    expect(isProductionManifest(validManifest())).toBe(false);
    expect(isProductionManifest(validManifest({ classification: 'production' }))).toBe(true);
  });
});
