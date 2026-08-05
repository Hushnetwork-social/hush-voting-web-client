/**
 * FEAT-010 Task 2.4 — exhaustive current-record binding, network-binding,
 * no-mnemonic, and startup-precedence tests.
 *
 * Covers exact precedence pairs, version parsing, network mismatch,
 * no-mnemonic shape rejection, stage contradiction, removal quarantine, and
 * verified-absence rules (normative: FeatureDescription "Startup and
 * Reconciliation", "Legacy Vault Migration", "Local-User Removal";
 * AC-010-021/024…028/034/074…082).
 */
import { describe, expect, it } from 'vitest';
import {
  checkNetworkBinding,
  validateCurrentRecord,
  type CurrentVaultRecordV1,
} from './current-binding';
import {
  resolveStartupPrecedence,
  STARTUP_INSPECTION_TIMEOUT_MS,
  type StartupInspectionResult,
} from './startup-inspection';
import type { DeploymentManifest } from '../../runtime/deployment';

function validRecord(overrides: Partial<CurrentVaultRecordV1> = {}): CurrentVaultRecordV1 {
  return {
    schemaVersion: 1,
    networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' },
    keyBinding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
    protectionModeClass: 'device-password',
    generation: 3,
    ...overrides,
  };
}

function validManifest(): DeploymentManifest {
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

describe('validateCurrentRecord', () => {
  it('accepts a fully valid current concrete-key-only record', () => {
    const result = validateCurrentRecord(validRecord());
    expect(result.ok).toBe(true);
  });

  it('accepts every qualified protection-mode class', () => {
    for (const protectionModeClass of ['device-password', 'webauthn-prf', 'ubuntu-secret-service', 'android-keystore'] as const) {
      expect(validateCurrentRecord(validRecord({ protectionModeClass })).ok).toBe(true);
    }
  });

  it('rejects unknown/newer schema versions', () => {
    const result = validateCurrentRecord(validRecord({ schemaVersion: 2 as 1 }));
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'UNSUPPORTED_SCHEMA_VERSION' });
  });

  it('rejects mnemonic-shaped fields injected into a current record', () => {
    for (const marker of ['mnemonic', 'seedPhrase', 'recoveryWords', 'seed', 'bip39', 'phrase']) {
      const poisoned = { ...validRecord(), [marker]: 'abandon abandon abandon' };
      const result = validateCurrentRecord(poisoned);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'MNEMONIC_SHAPE_PRESENT' });
    }
  });

  it('rejects mnemonic-shaped nested extensions', () => {
    const poisoned = { ...validRecord(), extensions: { recoveryWords: ['word1', 'word2'] } };
    const result = validateCurrentRecord(poisoned);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'MNEMONIC_SHAPE_PRESENT' });
  });

  it('rejects invalid network bindings', () => {
    const cases = [
      { networkBinding: null },
      { networkBinding: { canonicalNetworkId: '', networkMagic: 5195086, configurationId: 'x' } },
      { networkBinding: { canonicalNetworkId: 'x', networkMagic: 0, configurationId: 'x' } },
      { networkBinding: { canonicalNetworkId: 'x', networkMagic: 1.5, configurationId: 'x' } },
      { networkBinding: { canonicalNetworkId: 'x', networkMagic: 1, configurationId: '' } },
    ];
    for (const overrides of cases) {
      const result = validateCurrentRecord({ ...validRecord(), ...overrides });
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'INVALID_NETWORK_BINDING' });
    }
  });

  it('rejects invalid or secret-shaped key bindings', () => {
    for (const keyBinding of [
      { signingAddress: 'short', encryptionAddress: 'B'.repeat(44) },
      { signingAddress: 'A'.repeat(44), encryptionAddress: 'not-an-address!' },
      null,
      { signingAddress: 'A'.repeat(44) }, // missing encryption
    ]) {
      const result = validateCurrentRecord({ ...validRecord(), keyBinding: keyBinding as CurrentVaultRecordV1['keyBinding'] });
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'INVALID_KEY_BINDING' });
    }
  });

  it('rejects unknown protection modes (no unqualified fallback)', () => {
    const result = validateCurrentRecord(validRecord({ protectionModeClass: 'plaintext' as CurrentVaultRecordV1['protectionModeClass'] }));
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_PROTECTION_MODE' });
  });

  it('rejects invalid generations', () => {
    for (const generation of [-1, 1.5, NaN, '3']) {
      const result = validateCurrentRecord(validRecord({ generation: generation as number }));
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'INVALID_GENERATION' });
    }
  });

  it('rejects non-object payloads', () => {
    for (const payload of [null, undefined, 'text', 42, []]) {
      expect(validateCurrentRecord(payload).ok).toBe(false);
    }
  });
});

describe('checkNetworkBinding', () => {
  it('accepts an exactly bound record', () => {
    expect(checkNetworkBinding(validRecord(), validManifest())).toEqual({ kind: 'bound' });
  });

  it('fails closed on canonical-network mismatch', () => {
    const record = validRecord({ networkBinding: { canonicalNetworkId: 'hushnetwork-mainnet', networkMagic: 5195086, configurationId: 'isolated-local-devnet-v1' } });
    expect(checkNetworkBinding(record, validManifest())).toEqual({ kind: 'mismatch' });
  });

  it('fails closed on network-magic mismatch', () => {
    const record = validRecord({ networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 999, configurationId: 'isolated-local-devnet-v1' } });
    expect(checkNetworkBinding(record, validManifest())).toEqual({ kind: 'mismatch' });
  });

  it('fails closed on deployment-configuration mismatch', () => {
    const record = validRecord({ networkBinding: { canonicalNetworkId: 'hushnetwork-devnet', networkMagic: 5195086, configurationId: 'production-mainnet-v1' } });
    expect(checkNetworkBinding(record, validManifest())).toEqual({ kind: 'mismatch' });
  });
});

describe('resolveStartupPrecedence', () => {
  const removal: StartupInspectionResult = { kind: 'removalTombstone' };
  const quarantine: StartupInspectionResult = { kind: 'quarantine', reason: 'corrupt' };
  const stagedCreate: StartupInspectionResult = { kind: 'staged', stagedKind: 'createUser' };
  const stagedWords: StartupInspectionResult = { kind: 'staged', stagedKind: 'recoveryWords' };
  const stagedFile: StartupInspectionResult = { kind: 'staged', stagedKind: 'credentialFile' };
  const locked: StartupInspectionResult = { kind: 'lockedVault', protectionModeClass: 'device-password' };
  const absent: StartupInspectionResult = { kind: 'verifiedAbsent' };

  it('no observations → verified absence', () => {
    expect(resolveStartupPrecedence([])).toEqual(absent);
  });

  it('removal tombstone outranks every other state', () => {
    expect(resolveStartupPrecedence([locked, removal])).toEqual(removal);
    expect(resolveStartupPrecedence([stagedCreate, removal])).toEqual(removal);
    expect(resolveStartupPrecedence([quarantine, removal])).toEqual(removal);
  });

  it('quarantine outranks stages and locked states', () => {
    expect(resolveStartupPrecedence([locked, quarantine])).toEqual(quarantine);
    expect(resolveStartupPrecedence([stagedWords, quarantine])).toEqual(quarantine);
  });

  it('multiple distinct staged kinds are contradictory (never sub-precedence or last-write-wins)', () => {
    expect(resolveStartupPrecedence([stagedWords, stagedCreate])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
    expect(resolveStartupPrecedence([stagedFile, stagedWords])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('locked vault outranks verified absence; a stage plus a vault is contradictory', () => {
    expect(resolveStartupPrecedence([absent, locked])).toEqual(locked);
    expect(resolveStartupPrecedence([stagedCreate, locked])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('multiple distinct staged kinds are contradictory (never last-write-wins)', () => {
    expect(resolveStartupPrecedence([stagedCreate, stagedWords])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('multiple distinct locked vaults are contradictory', () => {
    const locked2: StartupInspectionResult = { kind: 'lockedVault', protectionModeClass: 'android-keystore' };
    expect(resolveStartupPrecedence([locked, locked2])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('a stage plus a locked vault is contradictory', () => {
    expect(resolveStartupPrecedence([stagedFile, locked])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('multiple identical stage records collapse to the single resume target', () => {
    expect(resolveStartupPrecedence([stagedCreate, stagedCreate])).toEqual(stagedCreate);
  });

  it('multiple removal tombstones are contradictory', () => {
    expect(resolveStartupPrecedence([removal, removal])).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('never chooses by timestamp or silent deletion', () => {
    // A contradictory set must quarantine regardless of order.
    const shuffled = [stagedFile, stagedCreate, locked];
    expect(resolveStartupPrecedence(shuffled)).toEqual({ kind: 'quarantine', reason: 'contradictory' });
  });

  it('exposes the bounded five-second inspection deadline', () => {
    expect(STARTUP_INSPECTION_TIMEOUT_MS).toBe(5_000);
  });
});
