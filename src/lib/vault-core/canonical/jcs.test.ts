/**
 * FEAT-003 vault-core canonical tests — RFC 8785 JCS.
 *
 * Covers Task 3.1/3.2: canonical JSON bytes, minimal escaping, canonical numbers,
 * sorted keys, and determinism across insertion orders.
 */
import { describe, expect, it } from 'vitest';
import { canonicalizeJson, canonicalizeJsonBytes, escapeJsonString } from './jcs';

describe('RFC 8785 JCS canonicalizer', () => {
  it('sorts object keys lexicographically', () => {
    expect(canonicalizeJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalizeJson({ z: { y: 1, x: 2 }, a: 3 })).toBe('{"a":3,"z":{"x":2,"y":1}}');
  });

  it('escapes minimal characters per RFC 8785 §3.2.2.2', () => {
    expect(canonicalizeJson({ s: 'a"b\\c\nd' })).toBe('{"s":"a\\"b\\\\c\\nd"}');
    expect(escapeJsonString('hello')).toBe('"hello"');
    expect(escapeJsonString('a\x01b')).toBe('"a\\u0001b"');
  });

  it('serializes integers without a fraction and rejects non-finite', () => {
    expect(canonicalizeJson(1)).toBe('1');
    expect(canonicalizeJson(-42)).toBe('-42');
    expect(canonicalizeJson(0)).toBe('0');
    expect(() => canonicalizeJson(NaN)).toThrow();
    expect(() => canonicalizeJson(Infinity)).toThrow();
  });

  it('uses ECMAScript shortest round-trip for exponent numbers (RFC 8785 §3.2.2.1)', () => {
    // RFC 8785 delegates to ES6 Number::toString; exponent thresholds are preserved.
    expect(canonicalizeJson(1e-7)).toBe('1e-7');
    expect(canonicalizeJson(1e+21)).toBe('1e+21');
    expect(canonicalizeJson(-1e-7)).toBe('-1e-7');
    // |n| < 1e21 serializes as an integer without a fraction.
    expect(canonicalizeJson(100000000000000000000)).toBe('100000000000000000000');
    // Negative zero normalizes to 0.
    expect(canonicalizeJson(-0)).toBe('0');
  });

  it('is byte-deterministic across property insertion orders', () => {
    const a = canonicalizeJsonBytes({ alias: 'Alice', lifecycleStatus: 'Active', signingAddressPrefix: '01234567' });
    const b = canonicalizeJsonBytes({ lifecycleStatus: 'Active', alias: 'Alice', signingAddressPrefix: '01234567' });
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });

  it('omits undefined and preserves null', () => {
    expect(canonicalizeJson({ a: undefined, b: null })).toBe('{"b":null}');
  });
});
