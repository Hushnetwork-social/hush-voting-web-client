import { afterEach, describe, expect, it, vi } from 'vitest';

const observed = vi.hoisted(() => ({ seeds: [] as Uint8Array[], keys: [] as Uint8Array[], failPublicKey: false }));
vi.mock('@noble/hashes/pbkdf2.js', async importOriginal => {
  const actual = await importOriginal<typeof import('@noble/hashes/pbkdf2.js')>();
  return { ...actual, pbkdf2: (...args: Parameters<typeof actual.pbkdf2>) => {
    const seed = actual.pbkdf2(...args); observed.seeds.push(seed); return seed;
  } };
});
vi.mock('../../identity-compatibility/crypto', async importOriginal => {
  const actual = await importOriginal<typeof import('../../identity-compatibility/crypto')>();
  return { ...actual,
    hkdfSha256: (...args: Parameters<typeof actual.hkdfSha256>) => {
      const key = actual.hkdfSha256(...args); observed.keys.push(key); return key;
    },
    derivePublicKey: (...args: Parameters<typeof actual.derivePublicKey>) => {
      if (observed.failPublicKey) throw new Error('Controlled public-key failure');
      return actual.derivePublicKey(...args);
    },
  };
});
import { deriveP01KeysWorker, deriveP02KeysWorker } from './bip39-worker';

afterEach(() => {
  for (const bytes of [...observed.seeds, ...observed.keys]) bytes.fill(0);
  observed.seeds.length = 0; observed.keys.length = 0; observed.failPublicKey = false;
});

// EPIC-001 -> FEAT-008 AC-008-037 -> Phase 3 Tasks 3.5/3.6.
// Public synthetic phrase; observe actual crypto-owned buffers, without copying their bytes.
describe('HushVotingApp TwinTests — worker derivation buffer cleanup', () => {
  for (const [producer, derive] of [['P-01', deriveP01KeysWorker], ['P-02', deriveP02KeysWorker]] as const) {
    it.each([false, true])(`${producer} wipes temporary seed and key buffers on failure=%s`, failure => {
      observed.failPublicKey = failure;
      const deriveKeys = () => derive([...Array<string>(23).fill('abandon'), 'art'].join(' '));
      if (failure) expect(deriveKeys).toThrow('Controlled public-key failure');
      else {
        const keys = deriveKeys();
        expect(keys?.signingPrivateKey.length).toBe(64);
        expect(keys?.encryptionPrivateKey.length).toBe(64);
      }
      expect(observed.seeds).toHaveLength(1);
      expect(observed.keys).toHaveLength(2);
      expect([...observed.seeds, ...observed.keys].every(bytes => bytes.every(byte => byte === 0))).toBe(true);
    });
  }
});
