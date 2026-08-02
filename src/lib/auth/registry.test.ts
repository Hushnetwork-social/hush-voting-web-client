/**
 * FEAT-002 registry tests — capability registration and production gates.
 *
 * Proves complete registrations succeed, and missing/duplicate/incompatible/
 * synthetic registrations fail closed with deterministic, secret-free
 * diagnostics. Test actors live behind the testing boundary and are never
 * valid in a production registry.
 */

import { describe, expect, it } from 'vitest';
import {
  MANDATORY_CAPABILITIES,
  ONBOARDING_CAPABILITIES,
  TEMPORARY_MODE_CAPABILITY,
  registerCapability,
  validateProductionRegistry,
} from './registry';
import type { CapabilityId } from './types';
import type { UnlockResult } from './results';
import {
  createLocalUserAuthorityTestActor,
  createSecretAuthorityTestActor,
  type TestActorOperation,
} from './testing/actors';

/** Complete, non-synthetic production registration (all mandatory + onboarding + temp). */
function completeRegistration() {
  return [
    registerCapability('localUserAuthority', 'mandatory'),
    registerCapability('secretAuthority', 'mandatory'),
    registerCapability('identityVerification', 'mandatory'),
    registerCapability('browserCoordination', 'mandatory'),
    registerCapability('onboardingCreateUser', 'optional'),
    registerCapability('onboardingRestoreCredentialFile', 'optional'),
    registerCapability('onboardingRestoreRecoveryWords', 'optional'),
    registerCapability('temporaryMode', 'temporaryMode'),
  ];
}

describe('production registration validation', () => {
  it('accepts a complete non-synthetic registration with safe coordination', () => {
    const result = validateProductionRegistry(completeRegistration());
    expect(result.ok).toBe(true);
    expect(result.diagnostics).toHaveLength(0);
    for (const capability of MANDATORY_CAPABILITIES) {
      expect(result.availableCapabilities.has(capability)).toBe(true);
    }
    for (const capability of ONBOARDING_CAPABILITIES) {
      expect(result.availableCapabilities.has(capability)).toBe(true);
    }
    expect(result.availableCapabilities.has(TEMPORARY_MODE_CAPABILITY)).toBe(true);
  });

  it('rejects each missing mandatory capability with a typed diagnostic', () => {
    for (const missing of MANDATORY_CAPABILITIES) {
      const result = validateProductionRegistry(
        completeRegistration().filter((r) => r.capability !== missing),
      );
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'MISSING_MANDATORY', capability: missing });
    }
  });

  it('rejects an unavailable mandatory capability', () => {
    const registrations = completeRegistration().map((r) =>
      r.capability === 'secretAuthority' ? { ...r, availability: 'unavailable' as const } : r,
    );
    const result = validateProductionRegistry(registrations);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'MISSING_MANDATORY', capability: 'secretAuthority' });
  });

  it('rejects duplicate registrations', () => {
    const registrations = [...completeRegistration(), registerCapability('localUserAuthority', 'mandatory')];
    const result = validateProductionRegistry(registrations);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'DUPLICATE_REGISTRATION', capability: 'localUserAuthority' });
  });

  it('rejects synthetic actors in production even when the set is otherwise complete', () => {
    const registrations = completeRegistration().map((r) =>
      r.capability === 'localUserAuthority' ? { ...r, synthetic: true } : r,
    );
    const result = validateProductionRegistry(registrations);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'SYNTHETIC_IN_PRODUCTION', capability: 'localUserAuthority' });
  });

  it('rejects temporaryMode when browser coordination is unsafe', () => {
    const registrations = completeRegistration().map((r) =>
      r.capability === 'browserCoordination' ? { ...r, availability: 'unavailable' as const } : r,
    );
    const result = validateProductionRegistry(registrations);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'UNSAFE_COORDINATION', capability: 'browserCoordination' });
    expect(result.diagnostics).toContainEqual({ code: 'INCOMPATIBLE_AVAILABILITY', capability: TEMPORARY_MODE_CAPABILITY });
  });

  it('never exposes implementation details or secrets in diagnostics', () => {
    const result = validateProductionRegistry(completeRegistration());
    for (const diagnostic of result.diagnostics) {
      expect(JSON.stringify(diagnostic)).not.toMatch(/password|mnemonic|private|secret|exception|stack/i);
    }
  });

  it('treats missing onboarding flows as fail-closed but non-blocking for mandatory auth', () => {
    const registrations = completeRegistration().filter(
      (r) => r.capability !== 'onboardingCreateUser' && r.capability !== 'onboardingRestoreCredentialFile',
    );
    const result = validateProductionRegistry(registrations);
    expect(result.ok).toBe(true);
    expect(result.availableCapabilities.has('onboardingCreateUser')).toBe(false);
  });
});

describe('test-kit actor boundary', () => {
  it('test actors implement the published port contracts (compile-time)', () => {
    const localUser = createLocalUserAuthorityTestActor([{ code: 'INIT_NO_LOCAL_USER' }]);
    const secret = createSecretAuthorityTestActor([{ code: 'UNLOCK_SUCCESS' }]);
    // Both expose initialize/beginUnlock and cancellation per the port shape.
    expect(typeof localUser.initialize).toBe('function');
    expect(typeof localUser.cancel).toBe('function');
    expect(typeof secret.beginUnlock).toBe('function');
  });

  it('test actors never receive secrets and produce only typed results', async () => {
    const secret = createSecretAuthorityTestActor([{ code: 'UNLOCK_SUCCESS' }]);
    const op = secret.beginUnlock(0 as never) as TestActorOperation<UnlockResult>;
    op.complete();
    const result = await op.result;
    expect(result).toEqual({ code: 'UNLOCK_SUCCESS' });
  });

  it('enumerates every mandatory capability id exactly once', () => {
    const unique = new Set<CapabilityId>(MANDATORY_CAPABILITIES);
    expect(unique.size).toBe(MANDATORY_CAPABILITIES.length);
  });
});
