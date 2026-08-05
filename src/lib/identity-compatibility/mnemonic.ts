/**
 * FEAT-001 identity compatibility API — mnemonic normalization and validation.
 *
 * Input validation is deterministic and producer-specific:
 *   P-01 (TypeScript): strict BIP-39 (12 or 24 words; lowercase; wordlist;
 *                      checksum) — matches the historical bip39-based producer.
 *   P-02/.NET: normalization (lowercase, split on space/tab/newline/CR,
 *              single-space rejoin), 24 words only, wordlist, checksum —
 *              matches MnemonicGenerator.ValidateMnemonic.
 * Expected failures are typed data; nothing throws.
 */
import { wordlists } from 'bip39';
import { sha256 } from '@noble/hashes/sha2.js';
import { normalizeMnemonicOlimpo, countWords } from './producers';
import type { CompatibilityFailure, CompatibilityResult } from './types';

export type MnemonicValidationResult = { readonly valid: true } | { readonly valid: false; readonly code: CompatibilityFailure['code'] };

const ENGLISH_WORDS: ReadonlySet<string> = new Set(wordlists.english);

const failure = (code: CompatibilityFailure['code'], message: string): CompatibilityFailure => ({ ok: false, code, message });

/** BIP-39 checksum check over an entropy reconstructed from word indices. */
function checksumMatches(words: readonly string[]): boolean {
  const bitsPerWord = 11;
  let bits = '';
  for (const w of words) {
    const idx = wordlists.english.indexOf(w);
    if (idx < 0) return false;
    bits += idx.toString(2).padStart(bitsPerWord, '0');
  }
  const totalBits = words.length * bitsPerWord;
  const checksumBits = totalBits % 32; // 8 for 24 words, 4 for 12 words
  const entropyBits = totalBits - checksumBits;
  const entropyBytes: number[] = [];
  for (let i = 0; i < entropyBits; i += 8) {
    entropyBytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const hash = sha256(new Uint8Array(entropyBytes));
  const expectedChecksum = hash[0].toString(2).padStart(8, '0').slice(0, checksumBits);
  return bits.slice(entropyBits) === expectedChecksum;
}

/** Validate for a specific producer; returns typed failure on rejection. */
export function validateMnemonicForProducer(mnemonic: string, producerId: string): MnemonicValidationResult {
  if (producerId === 'P-01') {
    if (mnemonic.trim().length === 0) return { valid: false, code: 'INVALID_MNEMONIC' };
    const words = mnemonic.trim().split(/[ \t\n\r]+/);
    if (words.length !== 12 && words.length !== 24) return { valid: false, code: 'INVALID_WORD_COUNT' };
    if (words.some((w) => w !== w.toLowerCase())) return { valid: false, code: 'INVALID_MNEMONIC' };
    if (words.some((w) => !ENGLISH_WORDS.has(w))) return { valid: false, code: 'UNKNOWN_WORD' };
    if (!checksumMatches(words)) return { valid: false, code: 'INVALID_CHECKSUM' };
    return { valid: true };
  }
  if (producerId === 'P-02' || producerId === 'P-03') {
    if (mnemonic.trim().length === 0) return { valid: false, code: 'INVALID_MNEMONIC' };
    const normalized = normalizeMnemonicOlimpo(mnemonic);
    const words = normalized.split(' ');
    if (words.length !== 24) return { valid: false, code: 'INVALID_WORD_COUNT' };
    if (words.some((w) => !ENGLISH_WORDS.has(w))) return { valid: false, code: 'UNKNOWN_WORD' };
    if (!checksumMatches(words)) return { valid: false, code: 'INVALID_CHECKSUM' };
    return { valid: true };
  }
  return { valid: false, code: 'UNSUPPORTED_PRODUCER' };
}

/** Normalize + validate the supplied compatibility input (empty passphrase only). */
export function validateInput(mnemonic: string, passphrase: string | undefined): CompatibilityResult<{ readonly normalized: string; readonly wordCount: number }> {
  if (passphrase && passphrase.length > 0) {
    return failure('UNSUPPORTED_PASSPHRASE', 'approved contracts require an empty BIP-39 passphrase');
  }
  if (mnemonic.trim().length === 0) {
    return failure('INVALID_MNEMONIC', 'empty mnemonic input');
  }
  const wordCount = countWords(mnemonic);
  return { ok: true, value: { normalized: mnemonic.trim(), wordCount } };
}

export { countWords };
