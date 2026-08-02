/**
 * FEAT-003 vault-core password — Unicode normalization and counting contract.
 *
 * One versioned Unicode contract across TypeScript and Rust (v1 pins Unicode data
 * version 16.0.0):
 * - normalize device-password input to Unicode NFC;
 * - preserve case and exact resulting UTF-8 bytes as Argon2id input;
 * - count Unicode Extended Grapheme Clusters under UAX #29;
 * - require 6–64 grapheme clusters and at most 256 UTF-8 bytes;
 * - reject invalid encoding and unpaired surrogate input before KDF execution;
 * - a separate NFKC/case-folded comparison representation is used ONLY for
 *   common/compromised and identity-similarity checks — never KDF input.
 *
 * Normative source: FEAT-003 FeatureDescription "Device-Password Contract".
 */

/** Pinned Unicode data version for v1 conformance. */
export const UNICODE_VERSION = '16.0.0' as const;

export type UnicodeValidation =
  | { readonly ok: true; readonly normalizedNfc: string; readonly graphemeClusters: number; readonly utf8Bytes: number }
  | { readonly ok: false; readonly code: 'INVALID_ENCODING' | 'UNPAIRED_SURROGATE' | 'TOO_FEW_GRAPHEMES' | 'TOO_MANY_GRAPHEMES' | 'TOO_MANY_BYTES'; readonly message: string };

const MIN_GRAPHEMES = 6 as const;
const MAX_GRAPHEMES = 64 as const;
const MAX_UTF8_BYTES = 256 as const;

const GRAPHEME_SEGMENTER = new Intl.Segmenter('und', { granularity: 'grapheme' });

function countGraphemes(value: string): number {
  return [...GRAPHEME_SEGMENTER.segment(value)].length;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

/**
 * Validate and normalize a device password.
 * Rejects lone surrogates (unpaired) before any normalization, then applies NFC.
 */
export function validateDevicePassword(input: string): UnicodeValidation {
  // Reject unpaired surrogates (encoding-level correctness before KDF).
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = input.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return { ok: false, code: 'UNPAIRED_SURROGATE', message: 'unpaired high surrogate' };
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return { ok: false, code: 'UNPAIRED_SURROGATE', message: 'unpaired low surrogate' };
    }
  }
  let normalized: string;
  try {
    normalized = input.normalize('NFC');
  } catch {
    return { ok: false, code: 'INVALID_ENCODING', message: 'cannot normalize input' };
  }
  const graphemes = countGraphemes(normalized);
  const bytes = utf8Length(normalized);
  if (graphemes < MIN_GRAPHEMES) {
    return { ok: false, code: 'TOO_FEW_GRAPHEMES', message: `requires at least ${MIN_GRAPHEMES} grapheme clusters` };
  }
  if (graphemes > MAX_GRAPHEMES) {
    return { ok: false, code: 'TOO_MANY_GRAPHEMES', message: `exceeds ${MAX_GRAPHEMES} grapheme clusters` };
  }
  if (bytes > MAX_UTF8_BYTES) {
    return { ok: false, code: 'TOO_MANY_BYTES', message: `exceeds ${MAX_UTF8_BYTES} UTF-8 bytes` };
  }
  return { ok: true, normalizedNfc: normalized, graphemeClusters: graphemes, utf8Bytes: bytes };
}

/**
 * Comparison representation for common/compromised and identity-similarity checks only.
 * NFKC + lower-case folding. NEVER KDF input and never persisted as a password derivative.
 */
export function comparisonRepresentation(input: string): string {
  return input.normalize('NFKC').toLocaleLowerCase('und');
}

/** Exact NFC UTF-8 bytes used as Argon2id input. */
export function kdfInputBytes(normalizedNfc: string): Uint8Array {
  return new TextEncoder().encode(normalizedNfc);
}
