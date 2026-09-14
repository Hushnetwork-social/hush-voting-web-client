/** FEAT-010 Phase 7 Tasks 7.7/7.8: classify source without logging its contents. */
import { wordlists } from 'bip39';
import ts from 'typescript';

const englishWords = new Set(wordlists.english);

// Do not require a valid checksum: malformed mnemonic material is still secret.
// A natural-language test title containing non-BIP39 words is not a mnemonic.
export function isMnemonicLiteral(value) {
  const words = value.slice(1, -1).split(/\s+/);
  return words.length >= 12 && words.length <= 24 && words.every(word => englishWords.has(word));
}

export function hasNativeBrowserFallback(source) {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.JSX, source);
  let code = '';
  for (let token = scanner.scan(); token !== ts.SyntaxKind.EndOfFileToken; token = scanner.scan()) {
    // Comments can describe a forbidden seam without implementing it. Keep
    // strings and executable tokens so string-based selection remains checked.
    if (token !== ts.SyntaxKind.SingleLineCommentTrivia && token !== ts.SyntaxKind.MultiLineCommentTrivia) {
      code += scanner.getTokenText();
    } else {
      code += ' ';
    }
  }
  return /browser/i.test(code) && /native[^]*fallback|fallback[^]*native/i.test(code);
}
