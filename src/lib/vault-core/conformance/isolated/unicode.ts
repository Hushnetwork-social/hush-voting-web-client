/**
 * FEAT-003 isolated conformance — independent Unicode password contract.
 *
 * Recomputes the versioned Unicode device-password contract from the native platform
 * primitives (String.normalize, Intl.Segmenter, TextEncoder) without importing the
 * primary `../password/unicode.ts` implementation:
 * - NFC normalization for KDF input bytes;
 * - UAX #29 Extended Grapheme Cluster counting;
 * - 6–64 grapheme clusters, at most 256 UTF-8 bytes;
 * - unpaired-surrogate rejection before normalization.
 *
 * v1 pins Unicode data version 16.0.0 (delivered by the Node 22 runtime).
 */
export const UNICODE_VERSION = '16.0.0' as const;

const MIN_GRAPHEMES = 6 as const;
const MAX_GRAPHEMES = 64 as const;
const MAX_UTF8_BYTES = 256 as const;

const GRAPHEME_SEGMENTER = new Intl.Segmenter('und', { granularity: 'grapheme' });

export type IsolatedUnicodeOutcome =
  | { readonly ok: true; readonly normalizedNfc: string; readonly graphemes: number; readonly utf8Bytes: number }
  | { readonly ok: false; readonly code: 'INVALID_ENCODING' | 'UNPAIRED_SURROGATE' | 'TOO_FEW_GRAPHEMES' | 'TOO_MANY_GRAPHEMES' | 'TOO_MANY_BYTES' };

function hasUnpairedSurrogate(input: string): boolean {
  for (let i = 0; i < input.length; i++) {
    const unit = input.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = input.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** Validate and normalize a device password using only native Unicode primitives. */
export function isolatedUnicodeCheck(input: string): IsolatedUnicodeOutcome {
  if (hasUnpairedSurrogate(input)) {
    return { ok: false, code: 'UNPAIRED_SURROGATE' };
  }
  let normalized: string;
  try {
    normalized = input.normalize('NFC');
  } catch {
    return { ok: false, code: 'INVALID_ENCODING' };
  }
  const graphemes = [...GRAPHEME_SEGMENTER.segment(normalized)].length;
  const utf8Bytes = new TextEncoder().encode(normalized).length;
  if (graphemes < MIN_GRAPHEMES) return { ok: false, code: 'TOO_FEW_GRAPHEMES' };
  if (graphemes > MAX_GRAPHEMES) return { ok: false, code: 'TOO_MANY_GRAPHEMES' };
  if (utf8Bytes > MAX_UTF8_BYTES) return { ok: false, code: 'TOO_MANY_BYTES' };
  return { ok: true, normalizedNfc: normalized, graphemes, utf8Bytes };
}

/**
 * Comparison representation for common/identity checks only: NFKC + case folding.
 * Never KDF input and never persisted as a password derivative.
 */
export function isolatedComparison(input: string): string {
  return input.normalize('NFKC').toLocaleLowerCase('und');
}
