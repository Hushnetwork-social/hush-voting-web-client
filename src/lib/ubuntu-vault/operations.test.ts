/**
 * FEAT-005 bridge operation-registry tests — native closure.
 *
 * Proves: every declared native operation has exactly one version, capability
 * phase, purpose, and bounded input ceiling (mirroring the Rust registry); no
 * generic key/signing/decryption/plaintext/filesystem surface exists; unknown
 * or future kinds fail closed.
 *
 * Normative source: FEAT-005 FeatureDescription "Closed operation registry";
 * Rust `src-tauri/src/ubuntu_vault/contracts/operations.rs`.
 */
import { describe, expect, it } from 'vitest';
import {
  NATIVE_OPERATION_KINDS,
  NATIVE_OPERATION_REGISTRY,
  assertNoGenericNativeAccess,
  resolveNativeOperation,
} from './operations';

describe('ubuntu-vault native operation registry — exhaustive and closed', () => {
  it('registers every declared seam with one version, phase, purpose, and bound', () => {
    expect([...NATIVE_OPERATION_KINDS].sort()).toEqual(
      [
        'inspectPreview',
        'provision',
        'replace',
        'unlock',
        'lock',
        'changeDevicePassword',
        'removeLocalUser',
        'revealMnemonic',
        'generateIdentity',
        'restoreIdentity',
        'verifyOnline',
        'createFullIdentitySign',
        'importDatV1',
        'exportDatV1',
      ].sort(),
    );
    for (const kind of NATIVE_OPERATION_KINDS) {
      const spec = NATIVE_OPERATION_REGISTRY[kind];
      expect(spec.version).toBe(1);
      expect(spec.kind).toBe(kind);
      expect(['provisioning', 'verificationOnly', 'authenticated', 'locked', 'removal']).toContain(
        spec.requiredCapabilityPhase,
      );
      expect(spec.maxInputBytes).toBeGreaterThanOrEqual(0);
      expect(spec.maxInputBytes).toBeLessThanOrEqual(16_384);
      expect(spec.purpose).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it('proves no generic secret surface exists', () => {
    expect(assertNoGenericNativeAccess()).toEqual([]);
  });

  it('rejects unknown, stale, or generic-secret operation kinds', () => {
    expect(resolveNativeOperation('sign')).toBeNull();
    expect(resolveNativeOperation('decrypt')).toBeNull();
    expect(resolveNativeOperation('getPrivateKey')).toBeNull();
    expect(resolveNativeOperation('returnBundle')).toBeNull();
    expect(resolveNativeOperation('')).toBeNull();
    expect(resolveNativeOperation(7)).toBeNull();
    expect(resolveNativeOperation(null)).toBeNull();
  });

  it('capability-scoped secret operations require authenticated phases', () => {
    expect(NATIVE_OPERATION_REGISTRY.revealMnemonic.requiredCapabilityPhase).toBe('authenticated');
    expect(NATIVE_OPERATION_REGISTRY.exportDatV1.requiredCapabilityPhase).toBe('authenticated');
    expect(NATIVE_OPERATION_REGISTRY.changeDevicePassword.requiredCapabilityPhase).toBe('authenticated');
    // Signing is verification-only (never arbitrary post-authenticated signing).
    expect(NATIVE_OPERATION_REGISTRY.createFullIdentitySign.requiredCapabilityPhase).toBe('verificationOnly');
  });

  it('direct-secret and bounded-input operations carry tight bounds', () => {
    expect(NATIVE_OPERATION_REGISTRY.unlock.maxInputBytes).toBeLessThanOrEqual(1_024);
    expect(NATIVE_OPERATION_REGISTRY.restoreIdentity.maxInputBytes).toBeLessThanOrEqual(4_096);
    expect(NATIVE_OPERATION_REGISTRY.createFullIdentitySign.maxInputBytes).toBe(16_384);
  });
});
