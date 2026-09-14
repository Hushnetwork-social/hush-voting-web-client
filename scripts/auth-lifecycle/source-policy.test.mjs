// EPIC-001 -> FEAT-010 AC-010-089/097/098 -> Phase 7 Tasks 7.7/7.8.
import test from 'node:test';
import assert from 'node:assert/strict';
import { wordlists } from 'bip39';
import { isMnemonicLiteral, hasNativeBrowserFallback } from './source-policy.mjs';

test('ordinary long test titles do not become mnemonic findings', () => {
  assert.equal(isMnemonicLiteral("'retains the verified preview for fresh confirmed removal after live cleanup fails'"), false);
});

for (const count of [12, 15, 18, 21, 24]) {
  test(`mnemonic-like literals with ${count} dictionary words remain prohibited regardless of checksum`, () => {
    // Synthetic dictionary material only; assertions and test names emit booleans/counts.
    const value = `'${wordlists.english.slice(0, count).join(' ')}'`;
    assert.equal(isMnemonicLiteral(value), true);
  });
}

test('a comment forbidding native browser fallback does not manufacture a code seam', () => {
  assert.equal(hasNativeBrowserFallback(`
    /** Native targets fail closed; no browser fallback. */
    export function select(target) {
      return target === 'native' ? nativeAuthority() : browserAuthority();
    }
  `), false);
});

test('executable native to browser fallback remains prohibited even beside a denial comment', () => {
  assert.equal(hasNativeBrowserFallback(`
    // No native browser fallback is allowed.
    export function select(nativeAuthority) { return nativeAuthority || browserFallback(); }
  `), true);
});

test('string-based native browser fallback remains visible to the detector', () => {
  assert.equal(hasNativeBrowserFallback("export const policy = 'native browser fallback';"), true);
});
