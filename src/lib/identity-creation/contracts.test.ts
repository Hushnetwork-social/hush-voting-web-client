/**
 * FEAT-007 Task 2.2 — unit and type tests for creation/lifecycle contracts.
 * Coverage targets: AC-007-016, 019–024, 027–036, 042–044, 052–062 (contract
 * layer portion); downstream FEAT-008 missing-profile serialization safety.
 */
import { describe, expect, it } from 'vitest';
import {
  abbreviateAddress,
  assertNoSecretSurface,
  type CreationLifecycle,
  type CreationReviewProjection,
  type CreationStage,
  type MissingProfileCreationContract,
  type ReconciliationTrigger,
} from './contracts';

describe('CreationReviewProjection safe boundary', () => {
  it('exposes only safe public fields (no secret key names)', () => {
    const projection: CreationReviewProjection = {
      normalizedAlias: 'Voter',
      visibility: 'private',
      abbreviatedSigningAddress: 'Ab12Cd34…Xy98Zz76',
      abbreviatedEncryptionAddress: 'Qw12Er34…Rt56Yu78',
      recoveryConfirmed: true,
      deviceProtectionReady: true,
      stage: 'review',
      progress: 0.9,
    };
    expect(assertNoSecretSurface(projection)).toEqual([]);
    const json = JSON.stringify(projection);
    expect(json).not.toMatch(/password|mnemonic|privateKey|transaction|signature/i);
  });

  it('fails the boundary guard when a secret key name is accidentally added', () => {
    const projection = {
      normalizedAlias: 'Voter',
      visibility: 'private' as const,
      abbreviatedSigningAddress: 'Ab12Cd34…Xy98Zz76',
      abbreviatedEncryptionAddress: 'Qw12Er34…Rt56Yu78',
      recoveryConfirmed: true,
      deviceProtectionReady: true,
      stage: 'review' as CreationStage,
      progress: 0.9,
      password: 'hunter2',
    };
    const violations = assertNoSecretSurface(projection as unknown as CreationReviewProjection);
    expect(violations).toContain('password');
  });
});

describe('abbreviateAddress', () => {
  it('uses <first 8>…<last 6> for long addresses', () => {
    const address = 'ABCDEFGH1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA0123456789';
    expect(abbreviateAddress(address)).toBe('ABCDEFGH…456789');
  });

  it('returns short addresses unchanged', () => {
    expect(abbreviateAddress('short')).toBe('short');
  });
});

describe('lifecycle vocabulary', () => {
  it('enumerates the closed lifecycle set (provisional is never confirmation)', () => {
    const lifecycles: readonly CreationLifecycle[] = ['provisional', 'savedWaiting', 'confirmed', 'failClosed'];
    expect(lifecycles).toHaveLength(4);
    expect(lifecycles).toContain('provisional');
    expect(lifecycles).toContain('savedWaiting');
    expect(lifecycles).toContain('confirmed');
    expect(lifecycles).toContain('failClosed');
  });

  it('rejects an unknown lifecycle at the type level (fail closed)', () => {
    // @ts-expect-error unknown lifecycle values are not assignable
    const bad: CreationLifecycle = 'blockchainConfirmedLocally';
    void bad;
  });
});

describe('reconciliation triggers', () => {
  it('covers every documented trigger once', () => {
    const triggers: readonly ReconciliationTrigger[] = [
      'startup',
      'provisionalResume',
      'unlock',
      'foreground',
      'connectivityRestored',
      'checkAgain',
      'pollTick',
    ];
    expect(new Set(triggers).size).toBe(triggers.length);
  });
});

describe('downstream missing-profile contract (FEAT-008)', () => {
  it('serializes without any secret or full sensitive field', () => {
    const contract: MissingProfileCreationContract = {
      version: 1,
      requiresAuthoritativeAbsence: true,
      requiresCredentialVerification: true,
      fields: ['normalizedAlias', 'visibility', 'abbreviatedSigningAddress', 'abbreviatedEncryptionAddress'],
      authorizationRef: 'opaque-ref' as MissingProfileCreationContract['authorizationRef'],
    };
    const json = JSON.stringify(contract);
    expect(json).not.toMatch(/mnemonic|password|privateKey|transaction|signature|fullAddress/i);
    expect(contract.requiresAuthoritativeAbsence).toBe(true);
    expect(contract.requiresCredentialVerification).toBe(true);
  });
});
