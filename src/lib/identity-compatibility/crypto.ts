/**
 * FEAT-001 identity compatibility API — cryptographic primitives.
 *
 * Implements the exact evidence contracts using the reviewed lockfile-pinned
 * libraries (bip39, @noble/hashes, @noble/secp256k1 — the same dependency
 * ranges as the historical Hush Feeds web client) so the API derives the same
 * keys the historical producers derived. No DOM, storage, or transport.
 */
import { mnemonicToSeedSync } from 'bip39';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import * as secp from '@noble/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { CompatibilityFailure, PublicKeyEncoding } from './types.js';

// noble v3 requires explicit hash registration (the historical producer runtime
// registers these once; we do the same at module load).
secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256 = (key, message) => hmac(sha256, key, message);

/** secp256k1 curve order N. */
export const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const ENCODER = new TextEncoder();

export function utf8Bytes(text: string): Uint8Array {
  return ENCODER.encode(text);
}

export function bytesToHexLower(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function hexToBytesStrict(hex: string): Uint8Array {
  return hexToBytes(hex);
}

/**
 * BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic".
 * The raw bip39 result can be a Buffer (Node/bundler polyfills); copy into a
 * plain Uint8Array so noble v2's strict isBytes() check accepts it in every
 * runtime and test realm.
 */
export function mnemonicToSeed(mnemonic: string): Uint8Array {
  return new Uint8Array(mnemonicToSeedSync(mnemonic));
}

/**
 * HKDF-SHA256 with an unprovided salt (RFC 5869 default of 32 zero bytes).
 * This matches both the historical TS producer (noble `undefined` salt) and
 * the .NET producer (BouncyCastle `null` salt).
 */
export function hkdfSha256(ikm: Uint8Array, info: string, length = 32): Uint8Array {
  return hkdf(sha256, ikm, undefined, ENCODER.encode(info), length);
}

/** True when a private scalar is usable on secp256k1 (0 < d < N). */
export function isUsableScalar(privateKeyHex: string): boolean {
  try {
    const value = BigInt('0x' + privateKeyHex);
    return value > 0n && value < CURVE_ORDER;
  } catch {
    return false;
  }
}

/** Derive an secp256k1 public key from a private scalar in the requested encoding. */
export function derivePublicKey(privateKeyHex: string, encoding: PublicKeyEncoding): string {
  if (!isUsableScalar(privateKeyHex)) {
    throw new Error('invalid private scalar');
  }
  return bytesToHex(secp.getPublicKey(hexToBytes(privateKeyHex), encoding === 'COMPRESSED'));
}

/** Decode a compressed/uncompressed secp256k1 public key to its point coordinates. */
export function decodePublicKeyPoint(publicKeyHex: string): { readonly xHex: string; readonly yHex: string } | null {
  try {
    const point = secp.Point.fromHex(publicKeyHex);
    return {
      xHex: point.x.toString(16).padStart(64, '0'),
      yHex: point.y.toString(16).padStart(64, '0'),
    };
  } catch {
    return null;
  }
}

/** SHA-256 digest of bytes as lowercase hex. */
export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

/**
 * Compact 64-byte r||s signature -> DER SEQUENCE { INTEGER r, INTEGER s }.
 * Correct DER includes the INTEGER type/length octets.
 */
export function compactToDer(rBytes: Uint8Array, sBytes: Uint8Array): Uint8Array {
  const encodeInt = (n: bigint): Uint8Array => {
    let h = n.toString(16);
    if (h.length % 2 !== 0) h = '0' + h;
    const b = hexToBytes(h);
    return b[0] & 0x80 ? new Uint8Array([0x00, ...b]) : b;
  };
  const r = encodeInt(BigInt('0x' + bytesToHex(rBytes)));
  const s = encodeInt(BigInt('0x' + bytesToHex(sBytes)));
  const body = new Uint8Array([0x02, r.length, ...r, 0x02, s.length, ...s]);
  return new Uint8Array([0x30, body.length, ...body]);
}

function padTo32(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 32) return bytes;
  if (bytes.length === 33 && bytes[0] === 0x00) return bytes.slice(1);
  throw new Error('unexpected integer length');
}

/**
 * DER signature -> compact 64-byte r||s. Throws when the structure is not a
 * well-formed ECDSA signature SEQUENCE of two INTEGERs.
 */
export function derToCompact(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30) throw new Error('not a DER sequence');
  const seqLen = der[1];
  if (seqLen !== der.length - 2) throw new Error('DER sequence length mismatch');
  if (der[2] !== 0x02) throw new Error('missing INTEGER tag for r');
  const rLen = der[3];
  if (rLen < 1 || rLen > 33) throw new Error('invalid r length');
  const sTagIndex = 4 + rLen;
  if (der[sTagIndex] !== 0x02) throw new Error('missing INTEGER tag for s');
  const sLen = der[sTagIndex + 1];
  if (sLen < 1 || sLen > 33) throw new Error('invalid s length');
  if (sTagIndex + 2 + sLen !== der.length) throw new Error('trailing bytes after s');
  return new Uint8Array([...padTo32(der.slice(4, 4 + rLen)), ...padTo32(der.slice(sTagIndex + 2, sTagIndex + 2 + sLen))]);
}

export type { CompatibilityFailure };
