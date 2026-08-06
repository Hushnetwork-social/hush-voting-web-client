/**
 * FEAT-010 Task 7.3 — worker-safe BIP-39 equivalence tests.
 *
 * Proves entropyToMnemonicWorker/mnemonicToEntropyWorker round-trip and
 * produce the SAME words as the pinned bip39 library (Node path) for known
 * vectors, and that invalid mnemonics (bad checksum/unknown words/counts)
 * are rejected.
 */
import { describe, expect, it } from 'vitest';
import { entropyToMnemonicWorker, mnemonicToEntropyWorker, validateMnemonicWorker, mnemonicToSeedWorker, deriveP01KeysWorker } from './bip39-worker';
import { entropyToMnemonic, validateMnemonic } from 'bip39';

describe('worker-safe BIP-39', () => {
  it('matches the pinned bip39 library word-for-word for random entropies', () => {
    for (let i = 0; i < 5; i += 1) {
      const entropy = new Uint8Array(32);
      crypto.getRandomValues(entropy);
      const worker = entropyToMnemonicWorker(entropy);
      const reference = entropyToMnemonic(Buffer.from(entropy));
      expect(worker).toBe(reference);
      expect(worker.split(' ')).toHaveLength(24);
    }
  });

  it('round-trips mnemonic → entropy → mnemonic', () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    const mnemonic = entropyToMnemonicWorker(entropy);
    const recovered = mnemonicToEntropyWorker(mnemonic);
    expect(recovered).not.toBeNull();
    expect(recovered && Buffer.from(recovered).equals(Buffer.from(entropy))).toBe(true);
  });

  it('matches the pinned validateMnemonic on valid and invalid phrases', () => {
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    const mnemonic = entropyToMnemonicWorker(entropy);
    expect(validateMnemonicWorker(mnemonic)).toBe(true);
    expect(validateMnemonic(mnemonic)).toBe(true);

    expect(validateMnemonicWorker('abandon abandon abandon')).toBe(false);
    // Flip one word and assert EXACT equivalence with the pinned library.
    // BIP-39 checksums are weak (8 bits for 24 words): a flipped phrase
    // coincidentally validates with probability ~1/256, so a hardcoded
    // `false` here is inherently flaky. The contract is worker == pinned.
    const words = mnemonic.split(' ');
    words[0] = words[0] === 'abandon' ? 'ability' : 'abandon';
    const flipped = words.join(' ');
    expect(validateMnemonicWorker(flipped)).toBe(validateMnemonic(flipped));
    // Unknown word.
    expect(validateMnemonicWorker('notaword '.repeat(24).trim())).toBe(false);
  });
});

describe('worker-safe derivation equivalence', () => {
  it('matches identity-compatibility P-01/P-02 derivation exactly', async () => {
    const { deriveP01Keys } = await import('../../identity-compatibility/producers');
    const { mnemonicToSeed } = await import('../../identity-compatibility/crypto');
    const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
    const reference = deriveP01Keys(words);
    const worker = deriveP01KeysWorker(words);
    expect(reference.ok).toBe(true);
    expect(worker).not.toBeNull();
    if (reference.ok && worker) {
      expect(worker.signingPrivateKey).toBe(reference.value.signingPrivateKey);
      expect(worker.encryptionPrivateKey).toBe(reference.value.encryptionPrivateKey);
      expect(worker.signingAddress).toBe(reference.value.signingAddress);
    }
    // Seed equivalence.
    const seedWorker = mnemonicToSeedWorker(words);
    expect(Buffer.from(seedWorker).equals(Buffer.from(mnemonicToSeed(words)))).toBe(true);
  });
});
