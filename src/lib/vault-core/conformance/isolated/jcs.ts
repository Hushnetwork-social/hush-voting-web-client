/**
 * FEAT-003 isolated conformance — independent RFC 8785 JCS implementation.
 *
 * This module is the ISOLATED calculation path for canonical authenticated bytes. It
 * is written independently from `../canonical/jcs.ts` (the primary implementation) and
 * must never import it. Both implementations implement the same RFC 8785 rules and the
 * corpus pins their agreement; divergence fails the conformance gate.
 *
 * Rules (RFC 8785):
 * - object keys sorted lexicographically by UTF-16 code units (§3.2.3);
 * - strings minimally escaped per §3.2.2.2 (`"` `\` and control characters only);
 * - numbers serialized with ES6 shortest round-trip Number::toString (§3.2.2.1);
 * - `undefined` omitted, `null` preserved, non-finite numbers rejected.
 */
const ESCAPE_TABLE: Readonly<Record<number, string>> = {
  0x22: '\\"',
  0x5c: '\\\\',
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
};

/** Escape one JSON string per RFC 8785 §3.2.2.2. */
export function quoteString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if (code < 0x20 || code === 0x22 || code === 0x5c) {
      const short = ESCAPE_TABLE[code];
      out += short ?? `\\u${code.toString(16).padStart(4, '0')}`;
    } else {
      out += ch;
    }
  }
  return out + '"';
}

/**
 * RFC 8785 §3.2.2.1: ECMAScript shortest round-trip number formatting.
 * `String(n)` reproduces the engine's Number::toString thresholds (e.g. `1e-7`,
 * `1e+21`, integer form for |n| < 1e21) and normalizes `-0` to `0`.
 */
export function numberToString(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError('isolated JCS: non-finite number cannot be canonicalized');
  }
  return String(value);
}

/** Canonicalize a JSON value to a string (RFC 8785). */
export function canonicalize(value: unknown, depth = 0): string {
  if (depth > 512) throw new TypeError('isolated JCS: nesting too deep');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return quoteString(value);
    case 'number':
      return numberToString(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalize(item, depth + 1)).join(',')}]`;
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      const parts: string[] = [];
      for (const key of keys) {
        const item = record[key];
        if (item === undefined) continue;
        parts.push(`${quoteString(key)}:${canonicalize(item, depth + 1)}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new TypeError(`isolated JCS: cannot canonicalize ${typeof value}`);
  }
}

/** Canonicalize to deterministic UTF-8 bytes. */
export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
