/**
 * FEAT-010 Task 2.2 — exhaustive deployment-bound transport tests.
 *
 * Covers endpoint resolution (allowlist, same-network rotation, cross-network
 * rejection, unknown endpoints), the unconditional-unavailable gate, and the
 * closed-result vocabulary (normative: FeatureDescription "Live HushServerNode
 * Transport", AC-010-014…018).
 */
import { describe, expect, it } from 'vitest';
import {
  DEPLOYMENT_MAX_REQUEST_BYTES,
  DEPLOYMENT_RPC_TIMEOUT_MS,
  isUnconditionalUnavailableTransport,
  resolveEndpointId,
  type DeploymentBoundTransportPort,
} from './transport';
import type { DeploymentManifest } from './deployment';

function validManifest(overrides: Partial<DeploymentManifest> = {}): DeploymentManifest {
  return {
    configurationId: 'isolated-local-devnet-v1',
    canonicalNetworkId: 'hushnetwork-devnet',
    networkMagic: 5195086,
    transportMode: 'bff',
    endpointIds: ['devnet-identity-a', 'devnet-identity-b'],
    contractVersions: { client: '1.0.0', server: '1.0.0', adapter: '1.0.0' },
    classification: 'isolated-non-production',
    digest: 'sha256:valid',
    ...overrides,
  };
}

describe('resolveEndpointId', () => {
  it('resolves allowlisted endpoint IDs from the active manifest', () => {
    const manifest = validManifest();
    expect(resolveEndpointId(manifest, 'devnet-identity-a')).toEqual({ ok: true, endpointId: 'devnet-identity-a' });
    expect(resolveEndpointId(manifest, 'devnet-identity-b')).toEqual({ ok: true, endpointId: 'devnet-identity-b' });
  });

  it('rejects unknown endpoint IDs', () => {
    expect(resolveEndpointId(validManifest(), 'attacker-endpoint')).toEqual({ ok: false, code: 'UNKNOWN_ENDPOINT' });
  });

  it('allows rotation to a candidate manifest endpoint on the same canonical network', () => {
    const manifest = validManifest();
    const candidate = validManifest({ configurationId: 'isolated-local-devnet-v2', endpointIds: ['devnet-identity-c'] });
    expect(resolveEndpointId(manifest, 'devnet-identity-c', [candidate])).toEqual({ ok: true, endpointId: 'devnet-identity-c' });
  });

  it('rejects rotation to an endpoint on a different canonical network', () => {
    const manifest = validManifest();
    const candidate = validManifest({ canonicalNetworkId: 'hushnetwork-mainnet', endpointIds: ['mainnet-identity-a'] });
    expect(resolveEndpointId(manifest, 'mainnet-identity-a', [candidate])).toEqual({ ok: false, code: 'CROSS_NETWORK_ENDPOINT' });
  });

  it('rejects rotation to an endpoint on the same network but different magic', () => {
    const manifest = validManifest();
    const candidate = validManifest({ networkMagic: 999, endpointIds: ['devnet-identity-c'] });
    expect(resolveEndpointId(manifest, 'devnet-identity-c', [candidate])).toEqual({ ok: false, code: 'CROSS_NETWORK_ENDPOINT' });
  });

  it('rejects rotation when server contract pins drift', () => {
    const manifest = validManifest();
    const candidate = validManifest({
      contractVersions: { client: '1.0.0', server: '1.1.0', adapter: '1.0.0' },
      endpointIds: ['devnet-identity-c'],
    });
    expect(resolveEndpointId(manifest, 'devnet-identity-c', [candidate])).toEqual({ ok: false, code: 'CROSS_NETWORK_ENDPOINT' });
  });
});

describe('deployment-bound policy bounds', () => {
  it('keeps the sealed 10-second deadline and bounded request size', () => {
    expect(DEPLOYMENT_RPC_TIMEOUT_MS).toBe(10_000);
    expect(DEPLOYMENT_MAX_REQUEST_BYTES).toBe(65_536);
  });
});

describe('isUnconditionalUnavailableTransport', () => {
  const unavailable: DeploymentBoundTransportPort = {
    endpointId: 'devnet-identity-a',
    lookupIdentity: async () => ({ ok: false, failure: { kind: 'unavailable' } }),
    submitTransaction: async () => ({ ok: false, failure: { kind: 'unavailable' } }),
  };
  const working: DeploymentBoundTransportPort = {
    endpointId: 'devnet-identity-a',
    lookupIdentity: async () => ({ ok: false, failure: { kind: 'timeout' } }),
    submitTransaction: async () => ({ ok: false, failure: { kind: 'protocol' } }),
  };

  it('flags a transport whose every call is unconditionally unavailable', async () => {
    expect(await isUnconditionalUnavailableTransport(unavailable)).toBe(true);
  });

  it('does not flag transports that reach the wire (even on failures)', async () => {
    expect(await isUnconditionalUnavailableTransport(working)).toBe(false);
  });

  it('does not flag transports that succeed', async () => {
    const successful: DeploymentBoundTransportPort = {
      endpointId: 'devnet-identity-a',
      lookupIdentity: async () => ({ ok: true, reply: { successfull: false, message: '' } }),
      submitTransaction: async () => ({ ok: true, reply: { successfull: true, message: '', status: 'ACCEPTED' } }),
    };
    expect(await isUnconditionalUnavailableTransport(successful)).toBe(false);
  });
});
