/**
 * FEAT-010 worker-safe BIP-39 helpers (Task 7.3).
 *
 * bip39's own `generateMnemonic`/`entropyToMnemonic`/`validateMnemonic` rely
 * on Node's Buffer, which is undefined in SharedWorkers. This module
 * reimplements the exact BIP-39 mappings (entropy → 24 words and mnemonic →
 * entropy with checksum verification) over plain Uint8Array using the SAME
 * pinned bip39 english wordlist, so the sealed worker derives identical
 * mnemonics without any Node dependency.
 *
 * Framework-neutral, runs in workers/browsers/Node.
 */
import { wordlists } from 'bip39';
import { sha256 } from '@noble/hashes/sha2.js';

const WORDLIST = wordlists.english;

function toBinaryString(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += byte.toString(2).padStart(8, '0');
  }
  return binary;
}

/** Entropy (16/20/24/28/32 bytes) → BIP-39 mnemonic (exact bip39 mapping). */
export function entropyToMnemonicWorker(entropy: Uint8Array): string {
  const ENT = entropy.byteLength * 8;
  const CS = ENT / 32;
  if (entropy.byteLength < 16 || entropy.byteLength > 32 || entropy.byteLength % 4 !== 0) {
    throw new TypeError('invalid entropy');
  }
  const hash = sha256(entropy);
  const binary = toBinaryString(entropy) + toBinaryString(hash).slice(0, CS);
  const words: string[] = [];
  for (let i = 0; i < binary.length; i += 11) {
    const index = parseInt(binary.slice(i, i + 11), 2);
    const word = WORDLIST[index];
    if (typeof word !== 'string') {
      throw new Error('wordlist index out of range');
    }
    words.push(word);
  }
  return words.join(' ');
}

/** Mnemonic → entropy bytes; returns null when invalid (checksum verified). */
export function mnemonicToEntropyWorker(mnemonic: string): Uint8Array | null {
  const normalized = mnemonic
    .toLowerCase()
    .split(/[ \t\n\r]+/)
    .filter((word) => word.length > 0)
    .join(' ');
  const words = normalized.split(' ');
  const validCounts = new Set([12, 15, 18, 21, 24]);
  if (!validCounts.has(words.length)) {
    return null;
  }
  const indexByWord = new Map<string, number>();
  WORDLIST.forEach((word, index) => {
    indexByWord.set(word, index);
  });
  let binary = '';
  for (const word of words) {
    const index = indexByWord.get(word);
    if (index === undefined) {
      return null;
    }
    binary += index.toString(2).padStart(11, '0');
  }
  const CS = words.length / 3;
  const ENT = binary.length - CS;
  const entropyBits = binary.slice(0, ENT);
  const checksumBits = binary.slice(ENT);
  const entropy = new Uint8Array(ENT / 8);
  for (let i = 0; i < entropy.length; i += 1) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }
  const hash = sha256(entropy);
  const expected = toBinaryString(hash).slice(0, CS);
  if (expected !== checksumBits) {
    return null;
  }
  return entropy;
}

/** Worker-safe validateMnemonic equivalent. */
export function validateMnemonicWorker(mnemonic: string): boolean {
  return mnemonicToEntropyWorker(mnemonic) !== null;
}

// ---------------------------------------------------------------------------
// Worker-safe BIP-39 seed + producer key derivation (no Node Buffer).
// ---------------------------------------------------------------------------

import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { hkdfSha256, derivePublicKey, isUsableScalar, bytesToHexLower } from '../../identity-compatibility/crypto';
import type { PublicKeyEncoding } from '../../identity-compatibility/types';

/** BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic"+passphrase). */
export function mnemonicToSeedWorker(mnemonic: string, passphrase = ''): Uint8Array {
  const encoder = new TextEncoder();
  // noble v3 pbkdf2(PRF, password, salt, opts) — opts without `async` runs
  // the sync path; hmac factory takes the hash constructor.
  // noble v3 pbkdf2(hash, password, salt, opts) — HMAC is applied internally.
  return pbkdf2(sha512, encoder.encode(mnemonic), encoder.encode(`mnemonic${passphrase}`), { c: 2048, dkLen: 64 });
}

/** Worker-safe P-01 derivation (mirrors identity-compatibility deriveP01Keys). */
export function deriveP01KeysWorker(mnemonic: string): {
  readonly signingPrivateKey: string;
  readonly encryptionPrivateKey: string;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly publicKeyEncoding: PublicKeyEncoding;
} | null {
  const seed = mnemonicToSeedWorker(mnemonic);
  const signingPrivateKey = bytesToHexLower(hkdfSha256(seed, 'signing'));
  const encryptionPrivateKey = bytesToHexLower(hkdfSha256(seed, 'encryption'));
  if (!isUsableScalar(signingPrivateKey) || !isUsableScalar(encryptionPrivateKey)) {
    return null;
  }
  return {
    signingPrivateKey,
    encryptionPrivateKey,
    signingAddress: derivePublicKey(signingPrivateKey, 'COMPRESSED'),
    encryptionAddress: derivePublicKey(encryptionPrivateKey, 'COMPRESSED'),
    publicKeyEncoding: 'COMPRESSED',
  };
}

/** Worker-safe P-02 derivation (mirrors identity-compatibility deriveP02Keys). */
export function deriveP02KeysWorker(mnemonic: string): {
  readonly signingPrivateKey: string;
  readonly encryptionPrivateKey: string;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly publicKeyEncoding: PublicKeyEncoding;
} | null {
  const seed = mnemonicToSeedWorker(mnemonic);
  const deriveWithRetry = (info: string): string => {
    let attempt = 0;
    let keyMaterial = hkdfSha256(seed, info);
    while (!isUsableScalar(bytesToHexLower(keyMaterial))) {
      attempt += 1;
      keyMaterial = hkdfSha256(seed, `${info}/${attempt}`);
    }
    return bytesToHexLower(keyMaterial);
  };
  const signingPrivateKey = deriveWithRetry('hush/signing/secp256k1/v1');
  const encryptionPrivateKey = deriveWithRetry('hush/encrypt/secp256k1/v1');
  return {
    signingPrivateKey,
    encryptionPrivateKey,
    signingAddress: derivePublicKey(signingPrivateKey, 'UNCOMPRESSED'),
    encryptionAddress: derivePublicKey(encryptionPrivateKey, 'UNCOMPRESSED'),
    publicKeyEncoding: 'UNCOMPRESSED',
  };
}
