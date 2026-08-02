/**
 * FEAT-003 vault-core auth-adapter tests — FEAT-002 safe projections.
 *
 * Covers Task 4.5/4.6: every core result maps once to a FEAT-002 outcome or is
 * explicitly blocked fail-closed; secret-bearing core objects are unrepresentable in
 * machine-facing projections.
 */
import { describe, expect, it } from 'vitest';
import {
  projectVaultResult,
  assertProjectionsExhaustive,
  type VaultToAuthProjection,
} from './projections';
import { VAULT_RESULT_CODES } from '../contracts/results';

describe('FEAT-002 safe projections', () => {
  it('is exhaustive: every v1 code is mapped or explicitly blocked, never both', () => {
    expect(() => assertProjectionsExhaustive()).not.toThrow();
  });

  it('maps core results deterministically to existing FEAT-002 outcomes', () => {
    expect(projectVaultResult('NoVault')).toEqual({ kind: 'mapped', outcome: 'INIT_NO_LOCAL_USER' });
    expect(projectVaultResult('UnsupportedVaultVersion')).toEqual({ kind: 'mapped', outcome: 'INIT_UNSUPPORTED_VAULT_VERSION' });
    expect(projectVaultResult('MalformedEnvelope')).toEqual({ kind: 'mapped', outcome: 'INIT_CORRUPT_VAULT' });
    expect(projectVaultResult('WrongPasswordOrDamagedData')).toEqual({ kind: 'mapped', outcome: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' });
    expect(projectVaultResult('Throttled')).toEqual({ kind: 'mapped', outcome: 'UNLOCK_THROTTLED' });
    expect(projectVaultResult('IdentityBindingMismatch')).toEqual({ kind: 'mapped', outcome: 'VERIFY_SIGNING_KEY_MISMATCH' });
    expect(projectVaultResult('StaleSession')).toEqual({ kind: 'mapped', outcome: 'SESSION_INVALIDATED' });
  });

  it('fails closed for results with no safe projection', () => {
    const p = projectVaultResult('MigrationFailedRollbackAvailable');
    expect(p.kind).toBe('blocked');
    if (p.kind === 'blocked') expect(p.reason).toBe('unknown-future-result');
  });

  it('every mapped outcome is a real FEAT-002 outcome code', () => {
    for (const code of VAULT_RESULT_CODES) {
      const p: VaultToAuthProjection = projectVaultResult(code);
      if (p.kind === 'mapped') {
        expect(p.outcome).toMatch(/^(INIT_|UNLOCK_|VERIFY_|REMOVAL_|SESSION_|MISSING_)/);
      }
    }
  });

  it('projections carry no secrets or opaque references (type-level safety)', () => {
    // The projection shape contains only kind/outcome/reason — no capability,
    // bundle, key, or ciphertext fields are representable.
    const p = projectVaultResult('Throttled');
    const keys = Object.keys(p).sort();
    expect(keys).toEqual(['kind', 'outcome']);
  });
});
