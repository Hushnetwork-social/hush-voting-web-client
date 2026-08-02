/**
 * FEAT-004 browser-vault crypto — production suite executor.
 *
 * Executes the closed FEAT-003 suite v1 through PRODUCTION browser primitives
 * inside the secret authority:
 *
 * - Argon2id via `@noble/hashes` `argon2id` (asynchronous, worker-local, exact
 *   pinned dependency; no Rust/WASM sidecar);
 * - HKDF-SHA-256 and AES-256-GCM via browser WebCrypto;
 * - cryptographic randomness via `crypto.getRandomValues()`.
 *
 * Production callers can never supply salts, keys, nonces, algorithms, KDF
 * parameters, or deterministic sources: every operation takes suite-bound
 * inputs only. Primitive injection keeps the executor deterministic in unit
 * tests while the production path always resolves browser globals.
 *
 * The environment uses a narrow structural WebCrypto surface (the few methods
 * the executor needs) so both DOM and Node implementations satisfy it without
 * cross-library type friction; production still resolves the browser global.
 *
 * Normative source: FEAT-004 FeatureDescription "Production Cryptography",
 * "Dependency pinning"; FEAT-003 `contracts/ports.ts` `SuiteCryptoOperations`.
 */
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import type { SuiteCryptoOperations } from '../../vault-core/contracts/ports';

/** Suite v1 closed parameters (FEAT-003 canonical). */
export const SUITE_V1_KDF = {
  algorithm: 'Argon2id',
  memoryKiB: 19456,
  iterations: 2,
  parallelism: 1,
  outputBytes: 32,
} as const;

/** AES-GCM authentication tag length in bytes. */
export const AES_GCM_TAG_BYTES = 16 as const;

/** Narrow WebCrypto surface used by the suite executor. */
export interface SubtleLike {
  readonly importRawKey: (keyData: Uint8Array, algorithm: string | Algorithm, usages: KeyUsage[]) => Promise<CryptoKey>;
  readonly deriveBits: (algorithm: HkdfParams, baseKey: CryptoKey, length: number) => Promise<ArrayBuffer>;
  readonly encrypt: (algorithm: AesGcmParams, key: CryptoKey, data: Uint8Array) => Promise<ArrayBuffer>;
  readonly decrypt: (algorithm: AesGcmParams, key: CryptoKey, data: Uint8Array) => Promise<ArrayBuffer>;
}

/**
 * Browser primitives injected into the suite executor. Production resolves the
 * browser globals; tests inject deterministic/fixed providers.
 */
export interface BrowserCryptoEnvironment {
  readonly subtle: SubtleLike;
  readonly getRandomValues: (array: Uint8Array) => Uint8Array;
  readonly argon2id: typeof nobleArgon2id;
}

/** Copy a byte view into a fresh ArrayBuffer-backed view (DOM BufferSource-safe). */
function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

/** Production default environment (browser globals; never deterministic). */
export function resolveBrowserCryptoEnvironment(): BrowserCryptoEnvironment {
  const subtle = typeof globalThis !== 'undefined' && 'crypto' in globalThis && globalThis.crypto ? globalThis.crypto.subtle : null;
  if (!subtle) {
    throw new Error('WebCrypto is unavailable; production vault operations fail closed before secret work');
  }
  return {
    subtle: {
      importRawKey: (keyData, algorithm, usages) => subtle.importKey('raw', toBufferSource(keyData), algorithm, false, usages),
      deriveBits: (algorithm, baseKey, length) => subtle.deriveBits(algorithm, baseKey, length),
      encrypt: (algorithm, key, data) => subtle.encrypt(algorithm, key, toBufferSource(data)),
      decrypt: (algorithm, key, data) => subtle.decrypt(algorithm, key, toBufferSource(data)),
    },
    getRandomValues: (array) => {
      globalThis.crypto.getRandomValues(array);
      return array;
    },
    argon2id: nobleArgon2id,
  };
}

/** Production default (evaluated lazily so SSR/build tools never require crypto). */
export const BROWSER_CRYPTO_ENVIRONMENT: BrowserCryptoEnvironment = {
  subtle: {
    importRawKey: () => {
      throw new Error('browser crypto environment not initialized; call resolveBrowserCryptoEnvironment in web runtime');
    },
    deriveBits: () => {
      throw new Error('browser crypto environment not initialized; call resolveBrowserCryptoEnvironment in web runtime');
    },
    encrypt: () => {
      throw new Error('browser crypto environment not initialized; call resolveBrowserCryptoEnvironment in web runtime');
    },
    decrypt: () => {
      throw new Error('browser crypto environment not initialized; call resolveBrowserCryptoEnvironment in web runtime');
    },
  },
  getRandomValues: (array) => array,
  argon2id: nobleArgon2id,
};

function toBytes(value: Uint8Array): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

/** HKDF-SHA-256 via WebCrypto (RFC 5869). */
async function webCryptoHkdf(
  subtle: SubtleLike,
  params: { readonly ikm: Uint8Array; readonly salt: Uint8Array; readonly info: Uint8Array; readonly outputBytes: number },
): Promise<Uint8Array> {
  const key = await subtle.importRawKey(toBufferSource(toBytes(params.ikm)), 'HKDF', ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: toBufferSource(toBytes(params.salt)), info: toBufferSource(toBytes(params.info)) },
    key,
    params.outputBytes * 8,
  );
  return new Uint8Array(bits);
}

/** AES-256-GCM encrypt via WebCrypto; splits ciphertext and 16-byte tag. */
async function webCryptoAesGcmEncrypt(
  subtle: SubtleLike,
  params: { readonly key: Uint8Array; readonly nonce: Uint8Array; readonly plaintext: Uint8Array; readonly aad: Uint8Array },
): Promise<{ readonly ciphertext: Uint8Array; readonly tag: Uint8Array }> {
  const key = await subtle.importRawKey(toBufferSource(toBytes(params.key)), { name: 'AES-GCM' }, ['encrypt']);
  const combined = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toBufferSource(toBytes(params.nonce)),
      additionalData: toBufferSource(toBytes(params.aad)),
      tagLength: AES_GCM_TAG_BYTES * 8,
    },
    key,
    toBufferSource(toBytes(params.plaintext)),
  );
  const bytes = new Uint8Array(combined);
  const tag = bytes.subarray(bytes.length - AES_GCM_TAG_BYTES);
  const ciphertext = bytes.subarray(0, bytes.length - AES_GCM_TAG_BYTES);
  return { ciphertext: new Uint8Array(ciphertext), tag: new Uint8Array(tag) };
}

/** AES-256-GCM decrypt with tag verification; throws on authentication failure. */
async function webCryptoAesGcmDecrypt(
  subtle: SubtleLike,
  params: { readonly key: Uint8Array; readonly nonce: Uint8Array; readonly ciphertext: Uint8Array; readonly tag: Uint8Array; readonly aad: Uint8Array },
): Promise<Uint8Array> {
  const key = await subtle.importRawKey(toBufferSource(toBytes(params.key)), { name: 'AES-GCM' }, ['decrypt']);
  const combined = new Uint8Array(toBytes(params.ciphertext).length + AES_GCM_TAG_BYTES);
  combined.set(toBytes(params.ciphertext), 0);
  combined.set(toBytes(params.tag), toBytes(params.ciphertext).length);
  const plaintext = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toBufferSource(toBytes(params.nonce)),
      additionalData: toBufferSource(toBytes(params.aad)),
      tagLength: AES_GCM_TAG_BYTES * 8,
    },
    key,
    toBufferSource(combined),
  );
  return new Uint8Array(plaintext);
}

/** Production CSPRNG (suite-bound output lengths only). */
function randomBytes(env: BrowserCryptoEnvironment, length: number): Uint8Array {
  const out = new Uint8Array(length);
  env.getRandomValues(out);
  return out;
}

/**
 * Create the production suite executor bound to suite v1. The returned object
 * implements the FEAT-003 `SuiteCryptoOperations` shape so downstream vault
 * code consumes browser crypto through the identical closed interface.
 */
export function createBrowserSuiteExecutor(
  env: BrowserCryptoEnvironment = BROWSER_CRYPTO_ENVIRONMENT,
): SuiteCryptoOperations & { readonly randomBytes: (length: number) => Uint8Array; readonly suiteId: string } {
  return {
    derivePasswordKey: async (params) => {
      // Suite v1: Argon2id with authenticated closed parameters; no caller influence.
      if (!Number.isFinite(params.memoryKiB) || params.memoryKiB < 1024 || !Number.isFinite(params.iterations) || params.iterations < 1 || !Number.isFinite(params.parallelism) || params.parallelism < 1 || !Number.isFinite(params.outputBytes) || params.outputBytes < 1) {
        // Internal misuse guard: calibration/assertStoredParamsUsable enforce the
        // closed suite bounds before any secret work; this is a programming-error
        // boundary, never an expected user failure.
        throw new Error('invalid closed suite KDF parameters');
      }
      const output = await env.argon2id(toBytes(params.passwordBytes), toBytes(params.salt), {
        t: params.iterations,
        m: params.memoryKiB,
        p: params.parallelism,
        dkLen: params.outputBytes,
      });
      return new Uint8Array(output);
    },
    hkdf: (params) => webCryptoHkdf(env.subtle, params),
    aes256GcmEncrypt: (params) => webCryptoAesGcmEncrypt(env.subtle, params),
    aes256GcmDecrypt: (params) => webCryptoAesGcmDecrypt(env.subtle, params),
    randomBytes: (length) => randomBytes(env, length),
    suiteId: 'hush/vault/suite/v1',
  };
}
