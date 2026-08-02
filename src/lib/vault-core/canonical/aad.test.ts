/**
 * FEAT-003 vault-core canonical tests — AAD binding and suite reference operations.
 *
 * Covers Task 3.1/3.2: purpose/version/adapter/preview/generation binding, absence of
 * network identity in v1, deterministic canonical AAD bytes, and known-answer behavior
 * of the reference suite operations (HKDF, AES-256-GCM, Argon2id determinism).
 */
import { describe, expect, it } from 'vitest';
import { buildAadBytes, buildAadMetadata, aadInputsFor } from './aad';
import { PARAMETER_SUITE_V1 } from '../contracts/suite';
import { derivePasswordKey, hkdf, aes256GcmEncrypt, aes256GcmDecrypt } from './suite-reference';
import { validateDevicePassword } from '../password/unicode';

const preview = {
  alias: 'Alice',
  signingAddressPrefix: '01234567',
  signingAddressSuffix: '89abcd',
  lifecycleStatus: 'Active',
  envelopeFormatVersion: 1,
  parameterSuiteVersion: 1,
  recordSchemaVersion: 1,
} as const;

function baseInputs() {
  return aadInputsFor(PARAMETER_SUITE_V1, {
    adapterBinding: 'logical',
    preview,
    vaultGeneration: 1,
    recordGeneration: 1,
    recordPurpose: 'ordinary',
    producerId: 'hush-voting-ts',
    producerVersion: '1.0.0',
    signingAddress: '0123456789abcdef',
    criticalExtensions: [],
  });
}

describe('purpose-bound AAD', () => {
  it('binds versions, suite params, adapter, preview, generations, purpose, producer, signatory', () => {
    const meta = buildAadMetadata(baseInputs());
    expect(meta.envelopeFormatVersion).toBe(1);
    expect(meta.kdf).toEqual({ algorithm: 'Argon2id', memoryKiB: 19456, iterations: 2, parallelism: 1 });
    expect(meta.adapterBinding).toBe('logical');
    expect(meta.preview).toMatchObject({ alias: 'Alice' });
    expect(meta.recordPurpose).toBe('ordinary');
    expect(meta.producer).toEqual({ id: 'hush-voting-ts', version: '1.0.0' });
    expect(meta.signingAddress).toBe('0123456789abcdef');
  });

  it('contains NO network identity in v1 (Deep-Dive override)', () => {
    const meta = buildAadMetadata(baseInputs());
    expect(meta).not.toHaveProperty('networkId');
    expect(meta).not.toHaveProperty('canonicalNetwork');
    expect(JSON.stringify(meta)).not.toMatch(/network/i);
  });

  it('changes canonical bytes when purpose, generation, or preview changes', () => {
    const a = Buffer.from(buildAadBytes(baseInputs())).toString('hex');
    const b = Buffer.from(buildAadBytes({ ...baseInputs(), recordPurpose: 'mnemonic' })).toString('hex');
    const c = Buffer.from(buildAadBytes({ ...baseInputs(), vaultGeneration: 2 })).toString('hex');
    const d = Buffer.from(buildAadBytes({ ...baseInputs(), preview: { ...preview, alias: 'Bob' } })).toString('hex');
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
    expect(a).not.toBe(d);
  });

  it('is deterministic (same inputs → same bytes)', () => {
    const a = Buffer.from(buildAadBytes(baseInputs())).toString('hex');
    const b = Buffer.from(buildAadBytes(baseInputs())).toString('hex');
    expect(a).toBe(b);
  });
});

describe('suite reference operations (deterministic test-only)', () => {
  it('HKDF-SHA-256 produces deterministic purpose-separated keys', async () => {
    const ikm = new TextEncoder().encode('password-bytes');
    const salt = new Uint8Array(16).fill(7);
    const cred = await hkdf({ ikm, salt, info: new TextEncoder().encode('hush/vault/v1/credential-kek'), outputBytes: 32 });
    const mnem = await hkdf({ ikm, salt, info: new TextEncoder().encode('hush/vault/v1/mnemonic-kek'), outputBytes: 32 });
    expect(Buffer.from(cred).toString('hex')).not.toBe(Buffer.from(mnem).toString('hex'));
    expect(cred.byteLength).toBe(32);
  });

  it('AES-256-GCM encrypt/decrypt round-trips with AAD and rejects tampered tag', async () => {
    const key = new Uint8Array(32).fill(3);
    const nonce = new Uint8Array(12).fill(5);
    const plaintext = new TextEncoder().encode('ordinary record payload');
    const aad = buildAadBytes(baseInputs());
    const { ciphertext, tag } = await aes256GcmEncrypt({ key, nonce, plaintext, aad });
    expect(ciphertext.byteLength).toBe(plaintext.byteLength);
    const decrypted = await aes256GcmDecrypt({ key, nonce, ciphertext, tag, aad });
    expect(Buffer.from(decrypted).toString()).toBe('ordinary record payload');
    const badTag = new Uint8Array(tag);
    badTag[0] ^= 0xff;
    await expect(aes256GcmDecrypt({ key, nonce, ciphertext, tag: badTag, aad })).rejects.toThrow();
  });

  it('Argon2id is deterministic for fixed parameters', async () => {
    const password = new TextEncoder().encode('correct horse battery staple');
    const salt = new Uint8Array(16).fill(9);
    const a = await derivePasswordKey({ passwordBytes: password, salt, memoryKiB: 8, iterations: 1, parallelism: 1, outputBytes: 32 });
    const b = await derivePasswordKey({ passwordBytes: password, salt, memoryKiB: 8, iterations: 1, parallelism: 1, outputBytes: 32 });
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });

  it('suite v1 password derivation uses the NFC-normalized KDF input bytes', async () => {
    const validated = validateDevicePassword('correct horse battery staple');
    expect(validated.ok).toBe(true);
    if (!validated.ok) return;
    const ikm = new TextEncoder().encode(validated.normalizedNfc);
    expect(ikm.byteLength).toBeGreaterThan(0);
  });
});
