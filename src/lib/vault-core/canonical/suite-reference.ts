/**
 * FEAT-003 vault-core canonical — deterministic suite reference operations.
 *
 * REFERENCE-ONLY: this module exists to generate and validate corpus vectors and to
 * prove known-answer behavior. It is NOT a production implementation and must never be
 * imported by production composition, the app bundle, or the Tauri runtime. The
 * production-exclusion scan (`conformance/vault/v1/scripts/validate.mjs`) and Phase 5/6
 * import-graph checks enforce this boundary. Deterministic randomness is exposed only
 * through `DETERMINISTIC_TEST_PROVIDER`-tagged helpers that are structurally impossible
 * to select in a production composition.
 *
 * Primitives: Argon2id via @noble/hashes (already a locked dependency), HKDF-SHA-256 and
 * AES-256-GCM via node:crypto. Suite v1 parameters are pinned in contracts/suite.ts.
 *
 * Normative source: FEAT-003 FeatureDescription "Cryptographic Suite", "Randomness".
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { PARAMETER_SUITE_V1 } from '../contracts/suite';
import type { SuiteCryptoOperations } from '../contracts/ports';

/** Non-production marker used by the exclusion scan (never appears in production paths). */
export const DETERMINISTIC_TEST_PROVIDER = 'DETERMINISTIC_TEST_PROVIDER';

/** Deterministic Argon2id per suite v1 (memoryKiB/iterations/parallelism/salt/output). */
export async function derivePasswordKey(params: {
  readonly passwordBytes: Uint8Array;
  readonly salt: Uint8Array;
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly outputBytes: number;
}): Promise<Uint8Array> {
  const result = await argon2id(params.passwordBytes, params.salt, {
    t: params.iterations,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: params.outputBytes,
    // Suite v1 uses no secret; output is 32 bytes.
  });
  return result;
}

/** HKDF-SHA-256 via node:crypto (RFC 5869). */
export async function hkdf(params: {
  readonly ikm: Uint8Array;
  readonly salt: Uint8Array;
  readonly info: Uint8Array;
  readonly outputBytes: number;
}): Promise<Uint8Array> {
  return new Uint8Array(
    Buffer.from(hkdfSync('sha256', Buffer.from(params.ikm), Buffer.from(params.salt), Buffer.from(params.info), params.outputBytes))
  );
}

/** AES-256-GCM encrypt (fresh nonce supplied by caller/adapter). */
export async function aes256GcmEncrypt(params: {
  readonly key: Uint8Array;
  readonly nonce: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly aad: Uint8Array;
}): Promise<{ readonly ciphertext: Uint8Array; readonly tag: Uint8Array }> {
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(params.key), Buffer.from(params.nonce));
  cipher.setAAD(Buffer.from(params.aad));
  const out = Buffer.concat([cipher.update(Buffer.from(params.plaintext)), cipher.final()]);
  return { ciphertext: new Uint8Array(out), tag: new Uint8Array(cipher.getAuthTag()) };
}

/** AES-256-GCM decrypt with tag verification (throws on authentication failure). */
export async function aes256GcmDecrypt(params: {
  readonly key: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly aad: Uint8Array;
}): Promise<Uint8Array> {
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(params.key), Buffer.from(params.nonce));
  decipher.setAAD(Buffer.from(params.aad));
  decipher.setAuthTag(Buffer.from(params.tag));
  return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(params.ciphertext)), decipher.final()]));
}

/** Reference suite operations bound to the closed v1 suite. */
export const SUITE_REFERENCE_OPERATIONS: SuiteCryptoOperations = {
  derivePasswordKey,
  hkdf,
  aes256GcmEncrypt,
  aes256GcmDecrypt,
} as const;

/** Deterministic test-only randomness (tagged; never selectable in production). */
export const DETERMINISTIC_RANDOM = {
  /** Deterministic byte stream from a seed (test vectors only). */
  seededBytes(seed: string, length: number): Uint8Array {
    let acc = seed;
    const out = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      const digest = requireSha256(acc);
      const take = Math.min(digest.length, length - offset);
      out.set(digest.subarray(0, take), offset);
      offset += take;
      acc = Buffer.from(digest).toString('hex');
    }
    return out;
  },
  /** Production-grade random bytes (adapter-owned in production; reference only here). */
  secureBytes(length: number): Uint8Array {
    return new Uint8Array(randomBytes(length));
  },
} as const;

import { createHash } from 'node:crypto';

function requireSha256(input: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest());
}

/** Convenience: suite v1 password-key derivation with the pinned minimum parameters. */
export function suiteV1PasswordParams() {
  return {
    memoryKiB: PARAMETER_SUITE_V1.kdf.minMemoryKiB,
    iterations: PARAMETER_SUITE_V1.kdf.iterations,
    parallelism: PARAMETER_SUITE_V1.kdf.parallelism,
    outputBytes: PARAMETER_SUITE_V1.kdf.outputBytes,
  };
}
