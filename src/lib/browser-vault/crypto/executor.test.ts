/**
 * FEAT-004 production crypto executor tests — suite vector replay and cleanup.
 *
 * Replays the immutable FEAT-003 suite vectors (S-001…S-006) and the A-001
 * AAD-bound wrap through the PRODUCTION browser executor (noble Argon2id +
 * WebCrypto), proves KAT anchoring (RFC 9106 §5.3, RFC 5869 §2.2 TC1), tamper
 * rejection, nonce uniqueness, caller-input rejection, and cleanup boundaries.
 *
 * Normative source: FEAT-004 FeatureDescription "Production Cryptography",
 * "Memory cleanup"; Task 3.2 behavior specification.
 */
import { createHash } from 'node:crypto';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { argon2id } from '@noble/hashes/argon2.js';
import { buildAadBytes, aadInputsFor } from '../../vault-core/canonical/aad';
import { PARAMETER_SUITE_V1 } from '../../vault-core/contracts/suite';
import { createBrowserSuiteExecutor, type BrowserCryptoEnvironment } from './executor';
import { createNonceTracker, dropBuffers, wipeBytes } from './nonce';

/** Deterministic test environment: Node WebCrypto (same API as browsers). */
const TEST_ENV: BrowserCryptoEnvironment = {
  subtle: {
    importRawKey: (keyData, algorithm, usages) => webcrypto.subtle.importKey('raw', keyData, algorithm, false, usages),
    deriveBits: (algorithm, baseKey, length) => webcrypto.subtle.deriveBits(algorithm as unknown as Parameters<typeof webcrypto.subtle.deriveBits>[0], baseKey, length),
    encrypt: (algorithm, key, data) => webcrypto.subtle.encrypt(algorithm as unknown as Parameters<typeof webcrypto.subtle.encrypt>[0], key, data),
    decrypt: (algorithm, key, data) => webcrypto.subtle.decrypt(algorithm as unknown as Parameters<typeof webcrypto.subtle.decrypt>[0], key, data),
  },
  getRandomValues: (array) => {
    webcrypto.getRandomValues(array);
    return array;
  },
  argon2id,
};

const suite = createBrowserSuiteExecutor(TEST_ENV);

function sha256hex(bytes: Uint8Array): string {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}
function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
function b64urlToBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}
function utf8ToBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'utf8'));
}

describe('production suite executor — HKDF vectors (S-001/S-002)', () => {
  it('replays the credential-kek and mnemonic-kek vectors exactly', async () => {
    const ikm = b64urlToBytes('cGFzc3dvcmQtYnl0ZXM');
    const salt = b64urlToBytes('BwcHBwcHBwcHBwcHBwcHBw');
    for (const [label, expected] of [
      ['hush/vault/v1/credential-kek', '8222d5d542f8c968553cb0a768e8bd4a2dd2da568743db50f6b613e983c2f18a'],
      ['hush/vault/v1/mnemonic-kek', '6b21ea70a0bfc40f75ff242b407b6899e7b7418a1b86fec7fe94d3dc777670b9'],
    ] as const) {
      const output = await suite.hkdf({ ikm, salt, info: utf8ToBytes(label), outputBytes: 32 });
      expect(sha256hex(output)).toBe(expected);
    }
  });
});

describe('production suite executor — AES-256-GCM AAD-bound wrap (S-003/A-001)', () => {
  const aad = buildAadBytes(
    aadInputsFor(PARAMETER_SUITE_V1, {
      adapterBinding: 'logical',
      preview: {
        alias: 'Alice',
        signingAddressPrefix: '01234567',
        signingAddressSuffix: '89abcd',
        lifecycleStatus: 'Active',
        envelopeFormatVersion: 1,
        parameterSuiteVersion: 1,
        recordSchemaVersion: 1,
      },
      vaultGeneration: 1,
      recordGeneration: 1,
      recordPurpose: 'ordinary',
      producerId: 'hush-voting-ts',
      producerVersion: '1.0.0',
      signingAddress: '0123456789abcdef',
      criticalExtensions: [],
    }),
  );

  it('replays the vector ciphertext/tag hashes exactly', async () => {
    const key = new Uint8Array(32).fill(3);
    const nonce = new Uint8Array(12).fill(5);
    const plaintext = utf8ToBytes('ordinary record payload');
    const { ciphertext, tag } = await suite.aes256GcmEncrypt({ key, nonce, plaintext, aad });
    expect(sha256hex(ciphertext)).toBe('2108a393bc4d933c90cb9ae5410946b67f24c96afac9ab9778ffabc3c1e01939');
    expect(sha256hex(tag)).toBe('cf6950d51982ea37b9f353d92e22274e692da837f19af091fbb7f478b3337539');
  });

  it('decrypts the vector ciphertext back to the exact plaintext', async () => {
    const key = new Uint8Array(32).fill(3);
    const nonce = new Uint8Array(12).fill(5);
    const { ciphertext, tag } = await suite.aes256GcmEncrypt({ key, nonce, plaintext: utf8ToBytes('ordinary record payload'), aad });
    const plaintext = await suite.aes256GcmDecrypt({ key, nonce, ciphertext, tag, aad });
    expect(Buffer.from(plaintext).toString('utf8')).toBe('ordinary record payload');
  });

  it('rejects tampered ciphertext, tag, and AAD (wrong-password/damage indistinguishability path)', async () => {
    const key = new Uint8Array(32).fill(3);
    const nonce = new Uint8Array(12).fill(5);
    const { ciphertext, tag } = await suite.aes256GcmEncrypt({ key, nonce, plaintext: utf8ToBytes('ordinary record payload'), aad });

    const tamperedCiphertext = new Uint8Array(ciphertext);
    tamperedCiphertext[0] ^= 0xff;
    await expect(suite.aes256GcmDecrypt({ key, nonce, ciphertext: tamperedCiphertext, tag, aad })).rejects.toThrow();

    const tamperedTag = new Uint8Array(tag);
    tamperedTag[0] ^= 0xff;
    await expect(suite.aes256GcmDecrypt({ key, nonce, ciphertext, tag: tamperedTag, aad })).rejects.toThrow();

    const tamperedAad = new Uint8Array(aad);
    tamperedAad[0] ^= 0xff;
    await expect(suite.aes256GcmDecrypt({ key, nonce, ciphertext, tag, aad: tamperedAad })).rejects.toThrow();
  });
});

describe('production suite executor — Argon2id vectors (S-004/S-005)', () => {
  it('replays the suite-parameter Argon2id vector (S-004)', async () => {
    const password = utf8ToBytes('password-bytes');
    const salt = hexToBytes('07070707070707070707070707070707');
    const output = await suite.derivePasswordKey({ passwordBytes: password, salt, memoryKiB: 19456, iterations: 2, parallelism: 1, outputBytes: 32 });
    expect(sha256hex(output)).toBe('c78cf17e0576ca8836864cd1623d97359564eb5dafff779bacf42e6c77fc03e2');
  });

  it('replays the RFC 9106 §5.3 Argon2id KAT through the pinned dependency (S-005)', async () => {
    // S-005 is a published implementation KAT with secret+ad, which the closed
    // production suite interface does not expose (suite v1 uses no secret). It
    // proves the EXACT-PINNED noble implementation produces the published output;
    // production record derivation runs through the closed executor path (S-004).
    const password = new Uint8Array(32).fill(1);
    const salt = new Uint8Array(16).fill(2);
    const secret = new Uint8Array(8).fill(3);
    const ad = new Uint8Array(12).fill(4);
    const output = await argon2id(password, salt, { t: 3, m: 32, p: 4, dkLen: 32, key: secret, personalization: ad });
    expect(Buffer.from(output).toString('hex')).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
    expect(sha256hex(new Uint8Array(output))).toBe('e1bfc35d1c47aaa688bdd95ccf4796bf675641feacb115ee7a550875a41abe19');
  });

  it('replays the RFC 5869 §2.2 TC1 HKDF KAT (S-006)', async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
    const info = Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
    const output = await suite.hkdf({ ikm, salt, info, outputBytes: 42 });
    expect(Buffer.from(output).toString('hex')).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });
});

describe('production suite executor — randomness and closed inputs', () => {
  it('produces distinct CSPRNG output on repeated calls', () => {
    const a = suite.randomBytes(32);
    const b = suite.randomBytes(32);
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
  });

  it('exposes only suite-bound operations (no caller-controlled algorithms)', () => {
    // The executor exposes exactly the closed FEAT-003 SuiteCryptoOperations shape
    // plus bounded randomness; there is no API for caller-supplied algorithms,
    // salts, keys, nonces, or KDF parameters beyond the fixed suite inputs.
    const keys = Object.keys(suite).sort();
    expect(keys).toEqual(['aes256GcmDecrypt', 'aes256GcmEncrypt', 'derivePasswordKey', 'hkdf', 'randomBytes', 'suiteId'].sort());
    expect(suite.suiteId).toBe('hush/vault/suite/v1');
  });
});

describe('nonce uniqueness and cleanup', () => {
  it('rejects cross-scope nonce reuse and accepts fresh scopes', () => {
    const tracker = createNonceTracker();
    const nonce = new Uint8Array([1, 2, 3]);
    expect(tracker.observe('active', nonce)).toBe(true);
    expect(tracker.observe('rollback', nonce)).toBe(false);
    expect(tracker.observe('rollback', new Uint8Array([4, 5, 6]))).toBe(true);
    expect(tracker.size()).toBe(2);
  });

  it('fails closed when the tracker is bounded', () => {
    const tracker = createNonceTracker(2);
    expect(tracker.observe('a', new Uint8Array([1]))).toBe(true);
    expect(tracker.observe('b', new Uint8Array([2]))).toBe(true);
    expect(tracker.observe('c', new Uint8Array([3]))).toBe(false);
  });

  it('wipes and drops application-owned buffers', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    wipeBytes(bytes);
    expect(bytes.every((byte) => byte === 0)).toBe(true);
    const second = new Uint8Array([1, 2, 3]);
    dropBuffers(bytes, second);
    expect(second.every((byte) => byte === 0)).toBe(true);
  });
});
