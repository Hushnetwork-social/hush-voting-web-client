/**
 * FEAT-003 vault-core canonical tests — bounded strict parser.
 *
 * Covers Task 3.1/3.2: duplicate-key rejection, size/depth/collection bounds,
 * base64url strictness, trailing data, unknown root properties, unpaired surrogates.
 */
import { describe, expect, it } from 'vitest';
import { parseBoundedJson, DEFAULT_PARSE_LIMITS, isUnpaddedBase64Url } from './parse';

const enc = (s: string) => new TextEncoder().encode(s);

describe('bounded strict parser', () => {
  it('parses valid documents and reports consumed bytes', () => {
    const out = parseBoundedJson(enc('{"a":[1,2,{"b":null}]}'));
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.value).toEqual({ a: [1, 2, { b: null }] });
      expect(out.consumed).toBe(22);
    }
  });

  it('does NOT misclassify legitimate objects shaped like {ok:false} as parse failures', () => {
    const out = parseBoundedJson(enc('{"ok":false,"code":"x"}'));
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.value).toEqual({ ok: false, code: 'x' });
    }
  });

  it('rejects duplicate keys (JSON.parse alone is insufficient)', () => {
    const out = parseBoundedJson(enc('{"a":1,"a":2}'));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.code).toBe('DUPLICATE_KEY');
  });

  it('rejects oversized input before parsing', () => {
    const big = enc(`{"x":"${'y'.repeat(2000)}"}`);
    const out = parseBoundedJson(big, { limits: { maxBytes: 64, maxNestingDepth: 16, maxCollections: 64 } });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.code).toBe('OVERSIZED_INPUT');
  });

  it('rejects excessive nesting and collection counts', () => {
    const deep = enc('{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}}}}}}}}}');
    const out = parseBoundedJson(deep, { limits: { maxBytes: 1024, maxNestingDepth: 4, maxCollections: 64 } });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.code).toBe('TOO_DEEP');
  });

  it('rejects trailing data, malformed literals, and non-finite numbers', () => {
    expect(parseBoundedJson(enc('{} extra')).ok).toBe(false);
    expect(parseBoundedJson(enc('{')).ok).toBe(false);
    expect(parseBoundedJson(enc('tru')).ok).toBe(false);
    expect(parseBoundedJson(enc('1e999')).ok).toBe(false);
    expect(parseBoundedJson(enc('NaN')).ok).toBe(false);
  });

  it('rejects unpaired surrogates', () => {
    const out = parseBoundedJson(enc('{"s":"\\ud800"}'));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.code).toBe('UNPAIRED_SURROGATE');
  });

  it('rejects unknown root properties when a closed list is provided', () => {
    const out = parseBoundedJson(enc('{"networkId":"x","preview":{}}'), {
      unknownRootProperties: ['preview'],
    });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.code).toBe('UNKNOWN_ROOT_PROPERTY');
  });

  it('validates unpadded base64url strictly', () => {
    expect(isUnpaddedBase64Url('abc123_-')).toBe(true);
    expect(isUnpaddedBase64Url('abc=')).toBe(false); // padded
    expect(isUnpaddedBase64Url('ab c')).toBe(false); // whitespace
    expect(isUnpaddedBase64Url('a')).toBe(false); // invalid length mod 4 == 1
    expect(isUnpaddedBase64Url('ab+cd')).toBe(false); // non-url alphabet
  });

  it('honors DEFAULT_PARSE_LIMITS from the closed suite', () => {
    expect(DEFAULT_PARSE_LIMITS.maxBytes).toBe(1_048_576);
    expect(DEFAULT_PARSE_LIMITS.maxNestingDepth).toBe(16);
    expect(DEFAULT_PARSE_LIMITS.maxCollections).toBe(64);
  });
});
