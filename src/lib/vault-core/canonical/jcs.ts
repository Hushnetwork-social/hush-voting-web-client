/**
 * FEAT-003 vault-core canonical — RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Deterministic canonical JSON bytes used for authenticated metadata and AAD.
 * Rules (RFC 8785):
 * - object keys sorted lexicographically (UTF-16 code unit order per RFC 8785 §3.2.3);
 * - strings with the minimal escaping required by RFC 8785 §3.2.2.2 (no U+2028/U+2029
 *   escapes unless present as code points; escape `"` `\` and control characters);
 * - numbers canonical per §3.2.2.1 (reject NaN/Infinity, serialize as shortest round-trip);
 * - no undefined values; `null` preserved; arrays/objects recurse.
 *
 * The output is UTF-8 bytes. Human formatting, property insertion order, line endings,
 * and locale never influence AAD.
 *
 * Normative source: FEAT-003 FeatureDescription "Serialization and Schema".
 */

/** RFC 8785 minimal escape set for characters that must be escaped. */
const ESCAPES: Readonly<Record<number, string>> = {
  0x22: '\\"',
  0x5c: '\\\\',
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
};

/** Escape a string per RFC 8785 §3.2.2.2 (control chars as \uXXXX). */
export function escapeJsonString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const esc = ESCAPES[code];
    if (esc !== undefined) {
      out += esc;
    } else if (code < 0x20) {
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    } else {
      out += value[i];
    }
  }
  return out + '"';
}

/**
 * RFC 8785 §3.2.2.1 canonical number serialization.
 *
 * RFC 8785 requires ECMAScript's shortest round-trip number-to-string conversion
 * (ES6 Number::toString, ECMA-262 §7.1.12.1). `String(value)` preserves the engine's
 * fixed/exponent thresholds exactly (`1e-7` stays `1e-7`; `1e21` stays `1e+21`;
 * `1e20` serializes as the integer `100000000000000000000`) and normalizes `-0` to
 * `0`. Expanding exponent forms into decimal notation is NOT RFC 8785 compliant and
 * would produce non-canonical authenticated bytes.
 */
export function canonicalNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError('JCS: non-finite number cannot be canonicalized');
  }
  return String(value);
}

/** Canonical serialization of a JSON value to a string (RFC 8785). */
export function canonicalizeJson(value: unknown, depth = 0): string {
  if (depth > 512) throw new TypeError('JCS: nesting too deep');
  if (value === null) return 'null';
  if (typeof value === 'string') return escapeJsonString(value);
  if (typeof value === 'number') return canonicalNumber(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalizeJson(v, depth + 1)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const parts: string[] = [];
    for (const key of keys) {
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) continue; // undefined omitted per RFC 8785
      parts.push(`${escapeJsonString(key)}:${canonicalizeJson(item, depth + 1)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new TypeError(`JCS: cannot canonicalize value of type ${typeof value}`);
}

/** Canonicalize to UTF-8 bytes (deterministic AAD input). */
export function canonicalizeJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalizeJson(value));
}
