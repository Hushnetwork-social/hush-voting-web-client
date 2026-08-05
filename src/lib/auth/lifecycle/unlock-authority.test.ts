/**
 * FEAT-010 Task 3.4 — unlock/cooldown/migration authority tests.
 *
 * Proves each mode, no-fallback rule, exact cooldown sequence, malformed
 * sidecar recovery, historical unlock, migration gates, rollback retention,
 * and obsolete-generation retirement rules (normative: FeatureDescription
 * "Returning Locked Screen", "Unlock and Authentication Boundary", "Legacy
 * Vault Migration"; AC-010-029…038, 079…082).
 */
import { describe, expect, it } from 'vitest';
import {
  classifyVaultForMigration,
  cooldownAfterFailures,
  evaluateUnlockRequest,
  isQualifiedProtectionMode,
  MAX_COOLDOWN_SECONDS,
  reconstructCooldownSidecar,
  shouldRetireObsoleteGeneration,
} from './unlock-authority';
import type { DeploymentManifest } from '../../runtime/deployment';

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

const SUPPORTED_HISTORICAL = new Set(['vault-v0.7', 'vault-v0.8', 'current-v1']);

describe('evaluateUnlockRequest', () => {
  it('permits unlock only through the recorded protection mode', () => {
    expect(evaluateUnlockRequest('device-password', 'device-password').ok).toBe(true);
    expect(evaluateUnlockRequest('webauthn-prf', 'webauthn-prf').ok).toBe(true);
    expect(evaluateUnlockRequest('ubuntu-secret-service', 'ubuntu-secret-service').ok).toBe(true);
    expect(evaluateUnlockRequest('android-keystore', 'android-keystore').ok).toBe(true);
  });

  it('rejects every alternate-mode attempt (no fallback)', () => {
    const cases: Array<[CurrentMode, CurrentMode]> = [
      ['device-password', 'webauthn-prf'],
      ['webauthn-prf', 'device-password'],
      ['device-password', 'ubuntu-secret-service'],
      ['android-keystore', 'device-password'],
      ['android-keystore', 'webauthn-prf'],
      ['ubuntu-secret-service', 'android-keystore'],
    ];
    for (const [recorded, requested] of cases) {
      const result = evaluateUnlockRequest(recorded, requested);
      expect(result).toEqual({ ok: false, code: 'MODE_MISMATCH' });
    }
  });
});
type CurrentMode = 'device-password' | 'webauthn-prf' | 'ubuntu-secret-service' | 'android-keystore';

describe('cooldownAfterFailures', () => {
  it('follows the exact 5/10/20/40/80/160/300 sequence after four failures', () => {
    expect(cooldownAfterFailures(0)).toBe(0);
    expect(cooldownAfterFailures(4)).toBe(0);
    expect(cooldownAfterFailures(5)).toBe(5);
    expect(cooldownAfterFailures(6)).toBe(10);
    expect(cooldownAfterFailures(7)).toBe(20);
    expect(cooldownAfterFailures(8)).toBe(40);
    expect(cooldownAfterFailures(9)).toBe(80);
    expect(cooldownAfterFailures(10)).toBe(160);
    expect(cooldownAfterFailures(11)).toBe(300);
    expect(cooldownAfterFailures(99)).toBe(300);
  });

  it('bounds malformed attempt counts', () => {
    expect(cooldownAfterFailures(-5)).toBe(0);
    expect(cooldownAfterFailures(NaN)).toBe(0);
    expect(cooldownAfterFailures(1.5)).toBe(0);
  });
});

describe('reconstructCooldownSidecar', () => {
  it('rebuilds a bounded safe state from malformed or extreme sidecars', () => {
    const now = 1_000_000;
    expect(reconstructCooldownSidecar(null, now)).toEqual({ failedAttempts: 0, deadlineMs: 0 });
    expect(reconstructCooldownSidecar({ failedAttempts: 'huge', deadlineMs: Infinity }, now)).toEqual({ failedAttempts: 0, deadlineMs: 0 });
    expect(reconstructCooldownSidecar({ failedAttempts: 10_000, deadlineMs: now + 10_000_000 }, now)).toEqual({
      failedAttempts: 1000,
      deadlineMs: now + MAX_COOLDOWN_SECONDS * 1000,
    });
    expect(reconstructCooldownSidecar({ failedAttempts: 7, deadlineMs: -5 }, now)).toEqual({ failedAttempts: 7, deadlineMs: 0 });
  });

  it('preserves valid values exactly', () => {
    const now = 1_000_000;
    expect(reconstructCooldownSidecar({ failedAttempts: 6, deadlineMs: now + 10_000 }, now)).toEqual({ failedAttempts: 6, deadlineMs: now + 10_000 });
  });
});

describe('classifyVaultForMigration', () => {
  it('routes supported historical vaults into the migration gate only', () => {
    expect(classifyVaultForMigration({ version: 'vault-v0.7' }, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'requiresMigration', historicalVersion: 'vault-v0.7' });
    expect(classifyVaultForMigration({ version: 'vault-v0.8' }, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'requiresMigration', historicalVersion: 'vault-v0.8' });
  });

  it('classifies a valid current record as already current when network-bound', () => {
    const current = {
      schemaVersion: 1,
      networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
      keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
      protectionModeClass: 'device-password',
      generation: 2,
    };
    expect(classifyVaultForMigration(current, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'alreadyCurrent' });
  });

  it('fails closed on wrong-network current records (never recreate on another network)', () => {
    const current = {
      schemaVersion: 1,
      networkBinding: { canonicalNetworkId: 'hushnetwork-mainnet', networkMagic: 5195086, configurationId: 'production-mainnet-v1' },
      keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
      protectionModeClass: 'device-password',
      generation: 2,
    };
    expect(classifyVaultForMigration(current, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'wrongNetwork' });
  });

  it('rejects unsupported/newer versions and corrupt payloads non-destructively', () => {
    expect(classifyVaultForMigration({ version: 'vault-v2.0' }, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'unsupported' });
    expect(classifyVaultForMigration(null, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'corrupt' });
    expect(classifyVaultForMigration({ noVersion: true }, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'corrupt' });
  });

  it('rejects mnemonic-shaped current payloads as corrupt', () => {
    const poisoned = {
      schemaVersion: 1,
      networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
      keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
      protectionModeClass: 'device-password',
      generation: 2,
      mnemonic: 'abandon abandon',
    };
    expect(classifyVaultForMigration(poisoned, SUPPORTED_HISTORICAL, manifest())).toEqual({ kind: 'corrupt' });
  });
});

describe('isQualifiedProtectionMode', () => {
  it('accepts only the closed qualified registry', () => {
    for (const mode of ['device-password', 'webauthn-prf', 'ubuntu-secret-service', 'android-keystore']) {
      expect(isQualifiedProtectionMode(mode as 'device-password')).toBe(true);
    }
    expect(isQualifiedProtectionMode('plaintext' as 'device-password')).toBe(false);
  });
});

describe('shouldRetireObsoleteGeneration', () => {
  it('retires the obsolete generation only after new-mode unlock AND online verification', () => {
    expect(shouldRetireObsoleteGeneration(true, true, 3, 3)).toEqual({ kind: 'retire' });
    expect(shouldRetireObsoleteGeneration(false, true, 3, 3)).toEqual({ kind: 'retain', reason: 'newModeNotProven' });
    expect(shouldRetireObsoleteGeneration(true, false, 3, 3)).toEqual({ kind: 'retain', reason: 'newModeNotProven' });
    expect(shouldRetireObsoleteGeneration(true, true, 3, 4)).toEqual({ kind: 'retain', reason: 'generationMismatch' });
  });
});
