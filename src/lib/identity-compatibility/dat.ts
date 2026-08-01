/**
 * FEAT-001 identity compatibility API — pure .dat v1 operations (contract C-C).
 *
 * Bounded compatibility operations only: envelope inspection, exact legacy
 * password-byte decryption, strict PortableCredentials parsing with an exact
 * property allowlist (unknown/duplicate properties fail deterministically),
 * and private/public + mnemonic/key consistency checks. No file pickers,
 * password prompts, storage, or UI.
 *
 * Uses Web Crypto-compatible interfaces (globalThis.crypto.subtle) so it runs
 * in browsers, workers, and Node.
 */
import { deriveP01Keys, deriveP02Keys, normalizeMnemonicOlimpo } from './producers.js';
import { bytesToHexLower, hexToBytesStrict } from './crypto.js';
import { getPublicKey as secpGetPublicKey } from '@noble/secp256k1';
import type { CompatibilityResult, CompatibilityFailure, DatDecodeResult, PortableCredentialsRecord } from './types.js';

export const DAT_MAGIC = 'HUSH';
export const DAT_VERSION = 1;
export const DAT_SALT_SIZE = 16;
export const DAT_NONCE_SIZE = 12;
export const DAT_PBKDF2_ITERATIONS = 100_000;
export const DAT_MAX_ENVELOPE_BYTES = 1024 * 1024; // 1 MiB (corpus maxEnvelopeBytes)
export const PROFILE_NAME_MAX_LENGTH = 64;

const failure = (code: CompatibilityFailure['code'], message: string): CompatibilityFailure => ({ ok: false, code, message });
const ENCODER = new TextEncoder();

const subtle = (): SubtleCrypto => {
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
    throw new Error('Web Crypto unavailable');
  }
  return globalThis.crypto.subtle;
};

function int32LE(bytes: Uint8Array, offset: number): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 4);
  return view.getInt32(0, true);
}

/** Structural envelope checks (magic, version, minimums, size bound). */
export function inspectDatEnvelope(envelope: Uint8Array): CompatibilityResult<{ readonly version: number }> {
  if (envelope.byteLength < 36) {
    return failure('DAT_MALFORMED', 'envelope shorter than structural minimum');
  }
  if (envelope.byteLength > DAT_MAX_ENVELOPE_BYTES) {
    return failure('DAT_MALFORMED', 'envelope exceeds size bound');
  }
  const magic = new TextDecoder().decode(envelope.slice(0, 4));
  if (magic !== DAT_MAGIC) {
    return failure('DAT_INVALID_MAGIC', 'missing HUSH magic');
  }
  const version = int32LE(envelope, 4);
  if (version !== DAT_VERSION) {
    return failure('DAT_UNSUPPORTED_VERSION', `unsupported envelope version ${version}`);
  }
  return { ok: true, value: { version } };
}

async function deriveDatKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await subtle().importKey('raw', ENCODER.encode(password), 'PBKDF2', false, ['deriveKey']);
  const saltBuffer = salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer;
  return subtle().deriveKey(
    { name: 'PBKDF2', salt: saltBuffer, iterations: DAT_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
}

/** Decrypt a v1 envelope with the exact legacy password-byte behavior. */
export async function decryptDatV1(envelope: Uint8Array, password: string): Promise<CompatibilityResult<string>> {
  const inspection = inspectDatEnvelope(envelope);
  if (!inspection.ok) return inspection;
  const salt = envelope.slice(8, 8 + DAT_SALT_SIZE);
  const nonce = envelope.slice(24, 24 + DAT_NONCE_SIZE);
  const ciphertext = envelope.slice(36);
  try {
    const key = await deriveDatKey(password, salt);
    const plaintext = await subtle().decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, ciphertext);
    return { ok: true, value: new TextDecoder().decode(plaintext) };
  } catch {
    return failure('DAT_WRONG_PASSWORD', 'AES-GCM authentication failed');
  }
}

/** Detect duplicate object keys in a JSON text (strict parser requirement). */
function hasDuplicateKeys(jsonText: string): boolean {
  const keys = [...jsonText.matchAll(/"((?:[^"\\]|\\.)*)"\s*:/g)].map((m) => m[1]);
  return new Set(keys).size !== keys.length;
}

const ALLOWED_FIELDS = new Set(['ProfileName', 'PublicSigningAddress', 'PrivateSigningKey', 'PublicEncryptAddress', 'PrivateEncryptKey', 'IsPublic', 'Mnemonic']);

function isWellFormedJson(jsonText: string): boolean {
  try {
    JSON.parse(jsonText);
    return true;
  } catch {
    return false;
  }
}

/**
 * Strict parse of the decrypted PortableCredentials JSON: exact property
 * allowlist; unknown, duplicate, missing, null, and wrong-type fields fail
 * deterministically (never ignored or preserved).
 */
export function parsePortableCredentialsStrict(jsonText: string): CompatibilityResult<PortableCredentialsRecord> {
  if (!isWellFormedJson(jsonText)) return failure('DAT_MALFORMED', 'decrypted payload is not valid JSON');
  if (hasDuplicateKeys(jsonText)) return failure('DAT_DUPLICATE_FIELD', 'duplicate property in portable credentials');
  const parsed = JSON.parse(jsonText) as Record<string, unknown>;
  for (const key of Object.keys(parsed)) {
    if (!ALLOWED_FIELDS.has(key)) return failure('DAT_UNKNOWN_FIELD', `unknown property: ${key}`);
  }
  for (const key of ALLOWED_FIELDS) {
    if (!(key in parsed)) return failure('DAT_MISSING_FIELD', `missing required property: ${key}`);
  }
  const s = (key: string): string => {
    const v = parsed[key];
    if (typeof v !== 'string') return '';
    return v;
  };
  const profileName = s('ProfileName');
  const signingAddress = s('PublicSigningAddress');
  const signingPrivate = s('PrivateSigningKey');
  const encryptAddress = s('PublicEncryptAddress');
  const encryptPrivate = s('PrivateEncryptKey');
  const mnemonic = parsed.Mnemonic;
  const isPublic = parsed.IsPublic;
  if (profileName.length === 0 || profileName.length > PROFILE_NAME_MAX_LENGTH || /[\u0000-\u001f\u007f]/.test(profileName)) {
    return failure('DAT_INVALID_FIELD', 'ProfileName violates compatibility bounds');
  }
  if (signingAddress.length === 0 || signingPrivate.length === 0 || encryptAddress.length === 0 || encryptPrivate.length === 0) {
    return failure('DAT_INVALID_FIELD', 'empty key field');
  }
  if (typeof isPublic !== 'boolean') return failure('DAT_INVALID_FIELD', 'IsPublic must be a boolean');
  if (mnemonic !== null && typeof mnemonic !== 'string') return failure('DAT_INVALID_FIELD', 'Mnemonic must be a string or null');
  return {
    ok: true,
    value: {
      ProfileName: profileName,
      PublicSigningAddress: signingAddress,
      PrivateSigningKey: signingPrivate,
      PublicEncryptAddress: encryptAddress,
      PrivateEncryptKey: encryptPrivate,
      IsPublic: isPublic,
      Mnemonic: typeof mnemonic === 'string' ? mnemonic : null,
    },
  };
}

/**
 * Key consistency checks: private/public pairs must match; when a mnemonic is
 * present it must derive the stored key pairs under an approved contract.
 */
export function validateKeyConsistency(record: PortableCredentialsRecord): { readonly privatePublicConsistent: boolean; readonly mnemonicKeyConsistent: boolean } {
  const derivePublicFromPrivate = (privateKeyHex: string, encoding: 'COMPRESSED' | 'UNCOMPRESSED'): string | null => {
    try {
      return bytesToHexLower(secpGetPublicKey(hexToBytesStrict(privateKeyHex), encoding === 'COMPRESSED'));
    } catch {
      return null;
    }
  };
  const signingPub = derivePublicFromPrivate(record.PrivateSigningKey, record.PublicSigningAddress.startsWith('04') ? 'UNCOMPRESSED' : 'COMPRESSED');
  const encryptPub = derivePublicFromPrivate(record.PrivateEncryptKey, record.PublicEncryptAddress.startsWith('04') ? 'UNCOMPRESSED' : 'COMPRESSED');
  const privatePublicConsistent =
    signingPub !== null && signingPub === record.PublicSigningAddress && encryptPub !== null && encryptPub === record.PublicEncryptAddress;

  let mnemonicKeyConsistent = false;
  if (record.Mnemonic !== null) {
    const p01 = deriveP01Keys(record.Mnemonic);
    const p02 = deriveP02Keys(normalizeMnemonicOlimpo(record.Mnemonic));
    const candidatePairs = [p01, p02].flatMap((r) => (r.ok ? [{ signing: r.value.signingAddress, encryption: r.value.encryptionAddress }] : []));
    mnemonicKeyConsistent = candidatePairs.some((p) => p.signing === record.PublicSigningAddress && p.encryption === record.PublicEncryptAddress);
  } else {
    mnemonicKeyConsistent = true; // no mnemonic present: nothing to compare
  }
  return { privatePublicConsistent, mnemonicKeyConsistent };
}

/** Full pure .dat v1 decode: decrypt -> strict parse -> consistency. */
export async function decodeDatV1(envelope: Uint8Array, password: string): Promise<CompatibilityResult<DatDecodeResult>> {
  const decrypted = await decryptDatV1(envelope, password);
  if (!decrypted.ok) return decrypted;
  const parsed = parsePortableCredentialsStrict(decrypted.value);
  if (!parsed.ok) return parsed;
  const consistency = validateKeyConsistency(parsed.value);
  if (!consistency.privatePublicConsistent) return failure('DAT_KEY_MISMATCH', 'private/public key pair mismatch');
  if (!consistency.mnemonicKeyConsistent) return failure('DAT_MNEMONIC_KEY_MISMATCH', 'mnemonic does not derive the stored keys');
  return { ok: true, value: { record: parsed.value, ...consistency } };
}

export { bytesToHexLower };
