/** FEAT-004 capability preflight: public synthetic data, never credential material. */
export interface PrimitivePreflightEnvironment {
  readonly secureContext: boolean;
  readonly sharedModuleWorker: boolean;
  readonly crypto: Crypto | null;
  readonly encode: (text: string) => Uint8Array;
  readonly decode: (bytes: Uint8Array) => string;
  readonly transfer: (bytes: Uint8Array) => Uint8Array;
  readonly persisted?: () => Promise<boolean>;
  readonly estimate?: () => Promise<StorageEstimate>;
}

export type PrimitivePreflightResult =
  | { readonly ok: true; readonly persisted: boolean | null; readonly estimateAvailable: boolean }
  | { readonly ok: false; readonly reason: 'insecure-context' | 'worker-unavailable' | 'crypto-unavailable' | 'transfer-unavailable' | 'preflight-timeout' };

function currentEnvironment(): PrimitivePreflightEnvironment {
  const manager = globalThis.navigator?.storage;
  return {
    secureContext: globalThis.isSecureContext === true,
    // This first-party entry is emitted as ESM. Reaching it in the actual
    // SharedWorker realm proves module-worker construction/execution.
    sharedModuleWorker: globalThis.constructor?.name === 'SharedWorkerGlobalScope',
    crypto: globalThis.crypto ?? null,
    encode: text => new TextEncoder().encode(text),
    decode: bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    transfer: bytes => structuredClone(bytes, { transfer: [bytes.buffer] }),
    persisted: manager?.persisted ? () => manager.persisted() : undefined,
    estimate: manager?.estimate ? () => manager.estimate() : undefined,
  };
}

/** Optional storage reports cannot turn missing/imprecise data into mandatory failure. */
async function advisory<T>(read: (() => Promise<T>) | undefined): Promise<T | null> {
  if (!read) return null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([Promise.resolve().then(read), new Promise<null>(resolve => { timer = setTimeout(() => resolve(null), 500); })]);
  } catch { return null; }
  finally { clearTimeout(timer); }
}

export async function probeWorkerPrimitives(env: PrimitivePreflightEnvironment = currentEnvironment()): Promise<PrimitivePreflightResult> {
  if (!env.secureContext) return { ok: false, reason: 'insecure-context' };
  if (!env.sharedModuleWorker) return { ok: false, reason: 'worker-unavailable' };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const probe = async (): Promise<PrimitivePreflightResult> => {
    try {
      const source = new Uint8Array(env.encode('HushVoting ✓'));
      const expected = Array.from(source);
      const transferred = env.transfer(source);
      if (source.byteLength !== 0 || transferred.byteLength !== expected.length
        || !expected.every((value, index) => transferred[index] === value)
        || env.decode(transferred) !== 'HushVoting ✓') return { ok: false, reason: 'transfer-unavailable' };
    } catch { return { ok: false, reason: 'transfer-unavailable' }; }
    const keyBytes = new Uint8Array(32), nonce = new Uint8Array(12);
    try {
      const provider = env.crypto;
      if (!provider?.subtle) return { ok: false, reason: 'crypto-unavailable' };
      provider.getRandomValues(keyBytes);
      provider.getRandomValues(nonce);
      const hkdf = await provider.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);
      const derived = await provider.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(16), info: new Uint8Array([72, 86]) }, hkdf, 256);
      const derivedBytes = new Uint8Array(derived);
      const correctLength = derivedBytes.byteLength === 32;
      derivedBytes.fill(0);
      if (!correctLength) return { ok: false, reason: 'crypto-unavailable' };
      const aes = await provider.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
      const plaintext = new Uint8Array([72, 86, 1]);
      const ciphertext = await provider.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aes, plaintext);
      const restored = new Uint8Array(await provider.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aes, ciphertext));
      const valid = restored.length === plaintext.length && plaintext.every((value, index) => restored[index] === value);
      restored.fill(0);
      if (!valid) return { ok: false, reason: 'crypto-unavailable' };
    } catch { return { ok: false, reason: 'crypto-unavailable' }; }
    finally { keyBytes.fill(0); nonce.fill(0); }
    const [persisted, estimate] = await Promise.all([advisory(env.persisted), advisory(env.estimate)]);
    return { ok: true, persisted: typeof persisted === 'boolean' ? persisted : null,
      estimateAvailable: typeof estimate?.quota === 'number' && Number.isFinite(estimate.quota)
        && typeof estimate.usage === 'number' && Number.isFinite(estimate.usage) };
  };
  try {
    return await Promise.race([probe(), new Promise<PrimitivePreflightResult>(resolve => {
      timer = setTimeout(() => resolve({ ok: false, reason: 'preflight-timeout' }), 5_000);
    })]);
  } finally { clearTimeout(timer); }
}
