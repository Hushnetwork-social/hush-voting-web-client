/**
 * FEAT-008 Tasks 6.4/6.6 — native integration tests: Ubuntu/Android
 * capability gates, provider-state fail-closed mapping, versioned contract
 * reports.
 * Coverage targets: AC-008-048–050, 075 (integration portion).
 */
import { describe, expect, it } from 'vitest';
import { androidCapabilityGate, mapNativeProviderState, nativeRecoveryContractReport, ubuntuCapabilityGate } from './native.js';

describe('Ubuntu capability gate (Task 6.4)', () => {
  it('qualifies Secret Service passwordless only with a usable provider', () => {
    expect(ubuntuCapabilityGate('available-unlocked').qualifiedOsProtection).toBe(true);
    expect(ubuntuCapabilityGate('available-locked').qualifiedOsProtection).toBe(true); // transparent OS prompt
    expect(ubuntuCapabilityGate('absent').qualifiedOsProtection).toBe(false);
    expect(ubuntuCapabilityGate('temporary').qualifiedOsProtection).toBe(false);
  });

  it('fails closed on confirmed provider absence', () => {
    const result = mapNativeProviderState('ubuntu', 'provider-absent');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('UNQUALIFIED_PASSWORDLESS');
    }
  });
});

describe('Android capability gate (Task 6.6)', () => {
  it('requires secure lock AND hardware-backed key for passwordless persistence', () => {
    expect(androidCapabilityGate(true, true).qualifiedOsProtection).toBe(true);
    expect(androidCapabilityGate(true, false).qualifiedOsProtection).toBe(false);
    expect(androidCapabilityGate(false, true).qualifiedOsProtection).toBe(false);
    expect(androidCapabilityGate(false, false).qualifiedOsProtection).toBe(false);
  });

  it('never allows password-only persistent Android storage', () => {
    const result = mapNativeProviderState('android', 'non-hardware-key');
    expect(result.ok).toBe(false);
    const noLock = mapNativeProviderState('android', 'secure-lock-missing');
    expect(noLock.ok).toBe(false);
    if (!noLock.ok) {
      expect(noLock.code).toBe('UNQUALIFIED_PASSWORDLESS');
    }
  });
});

describe('versioned native contract report (Tasks 6.4/6.6)', () => {
  it('records the additive versions, fail-closed states, and no-WebView-fallback invariant', () => {
    const ubuntu = nativeRecoveryContractReport('ubuntu', ubuntuCapabilityGate('available-unlocked'));
    expect(ubuntu.contractVersion).toBe(1);
    expect(ubuntu.sealedSeam).toBe('ubuntu-vault/v1');
    expect(ubuntu.additiveVersions).toContain('passwordless-secret-service');
    expect(ubuntu.webViewFallbackProhibited).toBe(true);

    const android = nativeRecoveryContractReport('android', androidCapabilityGate(true, true));
    expect(android.sealedSeam).toBe('android-vault/v1');
    expect(android.additiveVersions).toContain('passwordless-hardware-keystore');
    expect(android.failClosedStates).toContain('non-hardware-key');
  });
});
