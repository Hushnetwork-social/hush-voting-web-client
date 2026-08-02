/**
 * FEAT-004 downstream operation registry tests — consumer closure.
 *
 * Proves: every current downstream consumer has exactly one version,
 * capability phase, input boundary, cancellation rule, and typed result; no
 * generic key/signing/decryption/plaintext-bundle surface exists; unknown or
 * future kinds fail closed.
 *
 * Normative source: FEAT-004 FeatureDescription "Downstream consumers";
 * Task 2.6 behavior specification.
 */
import { describe, expect, it } from 'vitest';
import {
  DOWNSTREAM_OPERATION_KINDS,
  DOWNSTREAM_OPERATION_REGISTRY,
  assertNoGenericSecretAccess,
  resolveDownstreamOperation,
} from './operations';

describe('downstream operation registry — exhaustive and closed', () => {
  it('registers every consumer seam with one version and typed result surface', () => {
    const expectedKinds = [
      'createProvision',
      'recoverWordsProvision',
      'recoverFileProvision',
      'unlock',
      'changePassword',
      'lock',
      'removeLocalUser',
      'verifyOnline',
      'revealMnemonic',
      'exportEncryptedFile',
    ];
    expect([...DOWNSTREAM_OPERATION_KINDS].sort()).toEqual([...expectedKinds].sort());
    for (const kind of DOWNSTREAM_OPERATION_KINDS) {
      const spec = DOWNSTREAM_OPERATION_REGISTRY[kind];
      expect(spec.version).toBe(1);
      expect(spec.kind).toBe(kind);
      expect(['provisioning', 'verificationOnly', 'authenticated', 'locked', 'removal']).toContain(spec.requiredCapabilityPhase);
      expect(spec.resultSurface).toMatch(/^(typed-outcome|opaque-operation-id|digest-only-report)$/);
    }
  });

  it('proves no generic secret surface exists', () => {
    expect(assertNoGenericSecretAccess()).toEqual([]);
  });

  it('rejects unknown or generic-secret operation kinds', () => {
    expect(resolveDownstreamOperation('sign')).toBeNull();
    expect(resolveDownstreamOperation('decrypt')).toBeNull();
    expect(resolveDownstreamOperation('returnPrivateKey')).toBeNull();
    expect(resolveDownstreamOperation('plaintextExport')).toBeNull();
    expect(resolveDownstreamOperation(42)).toBeNull();
  });

  it('binds fresh-password requirements to the right operations', () => {
    expect(DOWNSTREAM_OPERATION_REGISTRY.revealMnemonic.requiresFreshPasswordCapability).toBe(true);
    expect(DOWNSTREAM_OPERATION_REGISTRY.removeLocalUser.requiresFreshPasswordCapability).toBe(true);
    expect(DOWNSTREAM_OPERATION_REGISTRY.lock.requiresFreshPasswordCapability).toBe(false);
    expect(DOWNSTREAM_OPERATION_REGISTRY.unlock.requiresFreshPasswordCapability).toBe(false);
    expect(DOWNSTREAM_OPERATION_REGISTRY.exportEncryptedFile.resultSurface).toBe('digest-only-report');
  });
});
