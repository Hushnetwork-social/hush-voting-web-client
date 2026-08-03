/**
 * FEAT-005 bridge contract tests — closed vocabulary and fail-closed lookup.
 *
 * Proves the TypeScript mirror matches the exact serde camelCase vocabulary
 * of the Rust `ubuntu_vault` contracts, unknown strings fail closed, and no
 * raw/secret vocabulary leaks into the projection surface.
 *
 * Normative source: FEAT-005 FeatureDescription "Error Handling"; Rust
 * `src-tauri/src/ubuntu_vault/contracts/*`.
 */
import { describe, expect, it } from 'vitest';
import {
  NATIVE_ERROR_CODES,
  PROVIDER_AVAILABILITY_STATES,
  UBUNTU_VAULT_VOCABULARY,
  isNativeErrorCode,
  isProviderAvailability,
} from './contracts';

describe('ubuntu-vault bridge contracts — closed vocabulary', () => {
  it('provider availability states are exhaustive and closed', () => {
    expect(PROVIDER_AVAILABILITY_STATES).toEqual([
      'availableUnlocked',
      'availableLocked',
      'promptCancelled',
      'temporarilyUnavailable',
      'unavailable',
      'unqualifiedProvider',
      'protectionInvalidated',
    ]);
  });

  it('every native error code resolves and no unknown string passes', () => {
    // All 31 declared codes are valid.
    for (const code of NATIVE_ERROR_CODES) {
      expect(isNativeErrorCode(code)).toBe(true);
    }
    // Unknown or generic-secret strings fail closed.
    expect(isNativeErrorCode('getPrivateKey')).toBe(false);
    expect(isNativeErrorCode('decryptVault')).toBe(false);
    expect(isNativeErrorCode('sign(bytes)')).toBe(false);
    expect(isNativeErrorCode('filesystem')).toBe(false);
    expect(isNativeErrorCode(42)).toBe(false);
    expect(isNativeErrorCode(null)).toBe(false);
  });

  it('provider states fail closed for unknown values', () => {
    expect(isProviderAvailability('availableUnlocked')).toBe(true);
    expect(isProviderAvailability('garbage')).toBe(false);
    expect(isProviderAvailability(undefined)).toBe(false);
  });

  it('fixed vocabulary is identity-free and stable', () => {
    expect(UBUNTU_VAULT_VOCABULARY.applicationId).toBe('com.hushvoting.client');
    expect(UBUNTU_VAULT_VOCABULARY.adapterId).toBe('ubuntu-secret-service-v1');
    expect(UBUNTU_VAULT_VOCABULARY.wrapperFormatVersion).toBe(1);
    // No alias/address/username/uid/mnemonic vocabulary in the fixed labels.
    const values = Object.values(UBUNTU_VAULT_VOCABULARY).join(' ');
    expect(values.toLowerCase()).not.toMatch(/(alias|address|username|uid|mnemonic)/);
  });

  it('no forbidden raw vocabulary exists in code lists', () => {
    const all = [...NATIVE_ERROR_CODES, ...PROVIDER_AVAILABILITY_STATES].join(' ').toLowerCase();
    expect(all).not.toMatch(/dbus|objectpath|\.local\/share|\/home\//);
  });
});
