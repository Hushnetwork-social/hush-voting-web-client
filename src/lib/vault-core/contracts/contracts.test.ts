/**
 * FEAT-003 vault-core contracts tests — version registries and logical schemas.
 *
 * Covers Task 2.1/2.2: closed version axes, record classes, identity-only preview,
 * extension mechanism, and the corpus schemas (valid/reject boundary fixtures).
 */
import { describe, expect, it } from 'vitest';
import {
  ADAPTER_BINDINGS,
  checkSupportedVersion,
  VAULT_VERSION_V1,
} from './versions';
import {
  RECORD_PURPOSES,
  RECORD_BOUNDS,
  VAULT_LIFECYCLE_STATUSES,
} from './records';
import {
  PREVIEW_ALIAS_MAX_LENGTH,
  PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH,
  PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH,
  validatePreviewV1,
} from './preview';
import {
  EXTENSION_BOUNDS,
  EXTENSION_NAMESPACE_PATTERN,
  validateExtensionContainer,
} from './extensions';
import { PARAMETER_SUITE_V1, PARAMETER_SUITE_REGISTRY } from './suite';
import { RECORD_PURPOSE_REGISTRY, LIFECYCLE_STATUS_REGISTRY, ADAPTER_BINDING_REGISTRY } from './registry';

describe('vault version registries', () => {
  it('supports exactly the v1 version combination', () => {
    expect(checkSupportedVersion(VAULT_VERSION_V1)).toEqual({ ok: true });
  });

  it('rejects every other critical version combination (fail closed)', () => {
    expect(checkSupportedVersion({ ...VAULT_VERSION_V1, envelopeFormatVersion: 2 } as never)).toEqual({
      ok: false,
      code: 'UNSUPPORTED_CRITICAL_VERSION',
    });
    expect(checkSupportedVersion({ ...VAULT_VERSION_V1, parameterSuiteVersion: 2 } as never)).toEqual({
      ok: false,
      code: 'UNSUPPORTED_CRITICAL_VERSION',
    });
    expect(checkSupportedVersion({ ...VAULT_VERSION_V1, recordSchemaVersion: 2 } as never)).toEqual({
      ok: false,
      code: 'UNSUPPORTED_CRITICAL_VERSION',
    });
    expect(checkSupportedVersion({ ...VAULT_VERSION_V1, platformWrapperVersion: 1 } as never)).toEqual({
      ok: false,
      code: 'UNSUPPORTED_CRITICAL_VERSION',
    });
  });

  it('keeps the adapter binding registry closed', () => {
    expect(ADAPTER_BINDINGS).toEqual(['logical', 'browser', 'ubuntu', 'android']);
    expect(ADAPTER_BINDING_REGISTRY).toEqual(ADAPTER_BINDINGS);
  });
});

describe('record classes and bounds', () => {
  it('exposes exactly the two secret record purposes and two lifecycle statuses', () => {
    expect(RECORD_PURPOSES).toEqual(['ordinary', 'mnemonic']);
    expect(RECORD_PURPOSE_REGISTRY).toEqual(['ordinary', 'mnemonic']);
    expect(VAULT_LIFECYCLE_STATUSES).toEqual(['PendingRegistration', 'Active']);
    expect(LIFECYCLE_STATUS_REGISTRY).toEqual(['PendingRegistration', 'Active']);
  });

  it('binds record byte limits to the closed suite limits', () => {
    expect(RECORD_BOUNDS.maxRecordBytes).toBe(PARAMETER_SUITE_V1.limits.maxRecordBytes);
    expect(RECORD_BOUNDS.nonceBase64UrlLength).toBe(16);
  });
});

describe('identity-only locked preview', () => {
  const validPreview = {
    alias: 'Alice',
    signingAddressPrefix: '01234567',
    signingAddressSuffix: '89abcd',
    lifecycleStatus: 'Active',
    envelopeFormatVersion: 1,
    parameterSuiteVersion: 1,
    recordSchemaVersion: 1,
  };

  it('accepts an allowlisted preview', () => {
    expect(validatePreviewV1(validPreview).ok).toBe(true);
  });

  it('rejects oversized alias, malformed address preview, and unknown lifecycle', () => {
    expect(validatePreviewV1({ ...validPreview, alias: 'x'.repeat(PREVIEW_ALIAS_MAX_LENGTH + 1) }).ok).toBe(false);
    expect(validatePreviewV1({ ...validPreview, signingAddressPrefix: 'short' }).ok).toBe(false);
    expect(validatePreviewV1({ ...validPreview, signingAddressSuffix: 'toooooo' }).ok).toBe(false);
    expect(validatePreviewV1({ ...validPreview, lifecycleStatus: 'Unknown' }).ok).toBe(false);
    expect(validatePreviewV1({ ...validPreview, envelopeFormatVersion: 2 }).ok).toBe(false);
  });

  it('enforces exact preview field lengths', () => {
    expect(PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH).toBe(8);
    expect(PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH).toBe(6);
  });
});

describe('extension mechanism', () => {
  it('accepts bounded namespaced non-critical and critical extensions', () => {
    const ok = validateExtensionContainer({
      extensions: { 'hush.vault.telemetry': { enabled: false } },
      criticalExtensions: [],
    });
    expect(ok.ok).toBe(true);
  });

  it('rejects invalid namespaces, non-unique criticals, and dangling criticals', () => {
    expect(EXTENSION_NAMESPACE_PATTERN.test('Hush.Vault')).toBe(false);
    expect(validateExtensionContainer({ extensions: { 'UPPER': 1 }, criticalExtensions: [] }).ok).toBe(false);
    expect(
      validateExtensionContainer({
        extensions: { a: 1 },
        criticalExtensions: ['a', 'a'],
      }).ok
    ).toBe(false);
    expect(
      validateExtensionContainer({
        extensions: {},
        criticalExtensions: ['missing.ns'],
      }).ok
    ).toBe(false);
  });

  it('caps extension counts at the closed bounds', () => {
    const many = Object.fromEntries(Array.from({ length: EXTENSION_BOUNDS.maxExtensions + 1 }, (_, i) => [`ns${i}`, 1]));
    expect(validateExtensionContainer({ extensions: many, criticalExtensions: [] }).ok).toBe(false);
  });
});

describe('closed parameter suite v1', () => {
  it('pins the exact v1 construction', () => {
    expect(PARAMETER_SUITE_V1.kdf).toMatchObject({
      algorithm: 'Argon2id',
      minMemoryKiB: 19456,
      iterations: 2,
      parallelism: 1,
      saltBytesMin: 16,
      outputBytes: 32,
      calibrationTargetMs: 750,
      hardTimeoutMs: 1500,
    });
    expect(PARAMETER_SUITE_V1.hkdf.labels).toEqual([
      'hush/vault/v1/credential-kek',
      'hush/vault/v1/mnemonic-kek',
    ]);
    expect(PARAMETER_SUITE_V1.cipher).toEqual({ algorithm: 'AES-256-GCM', keyBytes: 32, nonceBytes: 12 });
    expect(PARAMETER_SUITE_REGISTRY[1]).toBe(PARAMETER_SUITE_V1);
  });
});
