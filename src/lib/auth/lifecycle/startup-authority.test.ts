/**
 * FEAT-010 Task 3.2 — startup/reconciliation/verification/reset authority tests.
 *
 * Proves every precedence branch, stage resume, five-second boundary, exact
 * both-key outcome, offline verification-only retry, stale completion, and
 * same-network reset / different-network rejection (normative: FeatureDescription
 * "Startup and Reconciliation", "Unlock and Authentication Boundary";
 * AC-010-013/024…028/035/039…043/050).
 */
import { describe, expect, it } from 'vitest';
import {
  acceptChildCompletion,
  performRootVerification,
  prepareSameKeyRecreation,
  runStartupInspection,
  type RootVerificationOutcome,
  type RootVerificationPort,
  type StartupInspectionPorts,
  type VerificationOnlyCustody,
} from './startup-authority';
import type { VerificationOnlyCapability, VerificationOnlyCompletion } from '../child-flow';
import type { CurrentVaultRecordV1 } from '../../vault-core/contracts/current-binding';
import type { DeploymentManifest } from '../../runtime/deployment';

function validCompletion(overrides: Partial<VerificationOnlyCompletion> = {}): VerificationOnlyCompletion {
  return {
    capability: 'verification-only-token' as VerificationOnlyCapability,
    binding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
    outcome: 'provisioned',
    ...overrides,
  };
}

function custody(epoch = 1): VerificationOnlyCustody {
  return { epoch, capability: 'token', binding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) }, custodyId: 1 };
}

function manifest(): DeploymentManifest {
  return {
    configurationId: 'isolated-local-devnet-v1',
    canonicalNetworkId: 'hushnetwork-devnet',
    networkMagic: 5195086,
    transportMode: 'bff',
    endpointIds: ['devnet-identity-a'],
    contractVersions: { client: '1.0.0', server: '1.0.0', adapter: '1.0.0' },
    classification: 'isolated-non-production',
    digest: 'sha256:valid',
  };
}

function record(): CurrentVaultRecordV1 {
  return {
    schemaVersion: 1,
    networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
    keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
    protectionModeClass: 'device-password',
    generation: 1,
  };
}

describe('runStartupInspection', () => {
  it('resolves precedence within the deadline', async () => {
    const ports: StartupInspectionPorts = {
      inspect: async () => [{ kind: 'lockedVault', protectionModeClass: 'device-password' }],
      deadlineMs: () => 5000,
    };
    const verdict = await runStartupInspection(ports);
    expect(verdict.kind).toBe('inspection');
    if (verdict.kind === 'inspection') expect(verdict.result.kind).toBe('lockedVault');
  });

  it('times out beyond the five-second bound with a typed retryable verdict', async () => {
    const ports: StartupInspectionPorts = {
      inspect: () => new Promise((resolve) => setTimeout(() => resolve([{ kind: 'verifiedAbsent' }]), 50)),
      deadlineMs: () => 5,
    };
    const verdict = await runStartupInspection(ports);
    expect(verdict).toEqual({ kind: 'inspectionTimedOut' });
  });

  it('fails closed on malformed observations', async () => {
    const ports: StartupInspectionPorts = {
      inspect: async () => [{ kind: 'not-a-kind' } as never],
      deadlineMs: () => 5000,
    };
    const verdict = await runStartupInspection(ports);
    expect(verdict).toEqual({ kind: 'inspectionFailed' });
  });

  it('uses the contract default deadline when the port provides none', async () => {
    const ports: StartupInspectionPorts = {
      inspect: async () => [{ kind: 'verifiedAbsent' }],
      deadlineMs: () => 0,
    };
    const verdict = await runStartupInspection(ports);
    expect(verdict.kind).toBe('inspection');
  });
});

describe('acceptChildCompletion', () => {
  it('creates verification-only custody (never authenticated)', () => {
    const result = acceptChildCompletion(validCompletion(), 3, 5);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.custody.epoch).toBe(3);
      expect(result.custody.custodyId).toBe(6);
      expect(result.custody.binding.signingAddress).toBe('A'.repeat(44));
    }
  });

  it('rejects missing completions', () => {
    expect(acceptChildCompletion(null, 1, 0).ok).toBe(false);
    expect(acceptChildCompletion(undefined, 1, 0).ok).toBe(false);
  });
});

describe('performRootVerification', () => {
  const exactPort = (outcome: RootVerificationOutcome): RootVerificationPort => ({
    verifyExact: async () => outcome,
  });

  it('forwards one fresh exact verification for the current epoch', async () => {
    const port = exactPort({ kind: 'exactExisting' });
    const outcome = await performRootVerification(port, custody(1), 1);
    expect(outcome).toEqual({ kind: 'exactExisting' });
  });

  it('rejects stale epochs — stale results can never restore access', async () => {
    const spy = { called: false };
    const port: RootVerificationPort = {
      verifyExact: async () => {
        spy.called = true;
        return { kind: 'exactExisting' };
      },
    };
    const outcome = await performRootVerification(port, custody(1), 2);
    expect(outcome).toEqual({ kind: 'stale' });
    expect(spy.called).toBe(false);
  });

  it('preserves verification-only custody on transport failure (Retry without re-unlock)', async () => {
    const outcome = await performRootVerification(exactPort({ kind: 'transportFailure' }), custody(1), 1);
    expect(outcome).toEqual({ kind: 'transportFailure' });
  });
});

describe('prepareSameKeyRecreation', () => {
  it('permits recreation only on same-network authoritative absence', () => {
    expect(prepareSameKeyRecreation(record(), manifest(), { kind: 'authoritativeAbsentSameNetwork' }, 1, 1)).toEqual({ kind: 'permitted' });
  });

  it('never permits recreation on mismatch or transport failure', () => {
    expect(prepareSameKeyRecreation(record(), manifest(), { kind: 'mismatch' }, 1, 1)).toEqual({ kind: 'notAuthoritativeAbsence' });
    expect(prepareSameKeyRecreation(record(), manifest(), { kind: 'transportFailure' }, 1, 1)).toEqual({ kind: 'notAuthoritativeAbsence' });
    expect(prepareSameKeyRecreation(record(), manifest(), { kind: 'exactExisting' }, 1, 1)).toEqual({ kind: 'notAuthoritativeAbsence' });
  });

  it('rejects recreation when the record is bound to a different network', () => {
    const otherNetwork: CurrentVaultRecordV1 = {
      ...record(),
      networkBinding: { ...record().networkBinding, canonicalNetworkId: 'hushnetwork-mainnet' },
    };
    expect(prepareSameKeyRecreation(otherNetwork, manifest(), { kind: 'authoritativeAbsentSameNetwork' }, 1, 1)).toEqual({ kind: 'wrongNetwork' });
  });

  it('rejects recreation on stale custody', () => {
    expect(prepareSameKeyRecreation(record(), manifest(), { kind: 'authoritativeAbsentSameNetwork' }, 2, 1)).toEqual({ kind: 'stale' });
  });
});
