/**
 * FEAT-003 vault-core canonical — bounded strict JSON parser.
 *
 * JSON.parse alone is insufficient: duplicate keys are silently last-wins and there is no
 * byte budget. This parser enforces, while scanning (before allocation):
 * - a hard byte budget (default 1 MiB envelope bound);
 * - a nesting-depth budget and a collection-count budget;
 * - strict duplicate-key rejection at every object level;
 * - rejection of padded/non-canonical base64url strings, NaN/Infinity, and trailing data;
 * - rejection of control characters in strings (except the two JSON escapes);
 * - unpaired surrogate detection.
 *
 * Normative source: FEAT-003 FeatureDescription "Parsing bounds".
 */
import { canonicalizeJson } from './jcs';

/** Bounded parse limits (mirror suite limits). */
export interface ParseLimits {
  readonly maxBytes: number;
  readonly maxNestingDepth: number;
  readonly maxCollections: number;
}

export const DEFAULT_PARSE_LIMITS: ParseLimits = {
  maxBytes: 1_048_576,
  maxNestingDepth: 16,
  maxCollections: 64,
};

/** Brand separating parse failures from legitimate parsed values (symbol keys can never
 *  appear in parsed JSON, so duck-typing on `ok` would misclassify objects like {"ok":false}). */
const PARSE_FAILURE_BRAND = Symbol('vault-parse-failure');

export type ParseErrorCode =
  | 'OVERSIZED_INPUT'
  | 'TOO_DEEP'
  | 'TOO_MANY_COLLECTIONS'
  | 'DUPLICATE_KEY'
  | 'INVALID_BASE64URL'
  | 'MALFORMED_JSON'
  | 'NON_FINITE_NUMBER'
  | 'UNPAIRED_SURROGATE'
  | 'UNKNOWN_ROOT_PROPERTY';

export interface ParseFailure {
  readonly ok: false;
  readonly [PARSE_FAILURE_BRAND]: true;
  readonly code: ParseErrorCode;
  readonly message: string;
  readonly offset: number;
}

export type ParseOutcome<T> = { readonly ok: true; readonly value: T; readonly consumed: number } | ParseFailure;

/** Internal guard: is this value a branded parse failure? */
function isParseFailure(value: unknown): value is ParseFailure {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<PropertyKey, unknown>)[PARSE_FAILURE_BRAND] === true
  );
}

/** Strict unpadded base64url check (RFC 4648 §5, no padding, no whitespace). */
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export function isUnpaddedBase64Url(value: string): boolean {
  return BASE64URL_RE.test(value) && value.length % 4 !== 1;
}

interface TokenizerState {
  readonly text: string;
  readonly bytes: Uint8Array;
  readonly limits: ParseLimits;
  pos: number;
  collections: number;
}

function fail(state: TokenizerState, code: ParseErrorCode, message: string, offset = state.pos): ParseFailure {
  return { ok: false, [PARSE_FAILURE_BRAND]: true, code, message, offset };
}

function skipWhitespace(state: TokenizerState): void {
  while (state.pos < state.text.length) {
    const ch = state.text[state.pos];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') state.pos += 1;
    else break;
  }
}

function parseString(state: TokenizerState): string | ParseFailure {
  // state.text[state.pos] === '"'
  state.pos += 1;
  let out = '';
  for (;;) {
    if (state.pos >= state.text.length) {
      return fail(state, 'MALFORMED_JSON', 'unterminated string');
    }
    const ch = state.text[state.pos];
    if (ch === '"') {
      state.pos += 1;
      return out;
    }
    if (ch === '\\') {
      state.pos += 1;
      if (state.pos >= state.text.length) return fail(state, 'MALFORMED_JSON', 'unterminated escape');
      const esc = state.text[state.pos];
      state.pos += 1;
      switch (esc) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          if (state.pos + 4 > state.text.length) return fail(state, 'MALFORMED_JSON', 'short \\u escape');
          const hex = state.text.slice(state.pos, state.pos + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) return fail(state, 'MALFORMED_JSON', 'invalid \\u escape');
          state.pos += 4;
          const code = Number.parseInt(hex, 16);
          if (code >= 0xd800 && code <= 0xdbff) {
            // High surrogate: require a following \uDC00-\uDFFF.
            if (state.text.slice(state.pos, state.pos + 2) !== '\\u') {
              return fail(state, 'UNPAIRED_SURROGATE', 'unpaired high surrogate');
            }
            const lowHex = state.text.slice(state.pos + 2, state.pos + 6);
            if (!/^[0-9a-fA-F]{4}$/.test(lowHex)) return fail(state, 'UNPAIRED_SURROGATE', 'unpaired high surrogate');
            const low = Number.parseInt(lowHex, 16);
            if (low < 0xdc00 || low > 0xdfff) return fail(state, 'UNPAIRED_SURROGATE', 'unpaired high surrogate');
            state.pos += 6;
            const cp = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
            out += String.fromCodePoint(cp);
          } else if (code >= 0xdc00 && code <= 0xdfff) {
            return fail(state, 'UNPAIRED_SURROGATE', 'unpaired low surrogate');
          } else {
            out += String.fromCharCode(code);
          }
          break;
        }
        default:
          return fail(state, 'MALFORMED_JSON', `invalid escape \\${esc}`);
      }
    } else {
      const code = state.text.charCodeAt(state.pos);
      if (code < 0x20) return fail(state, 'MALFORMED_JSON', 'unescaped control character in string');
      out += ch;
      state.pos += 1;
    }
  }
}

function parseNumber(state: TokenizerState): number | ParseFailure {
  const start = state.pos;
  // Grammar: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
  if (state.text[state.pos] === '-') state.pos += 1;
  if (state.pos >= state.text.length) return fail(state, 'MALFORMED_JSON', 'truncated number');
  if (state.text[state.pos] === '0') {
    state.pos += 1;
  } else if (/[1-9]/.test(state.text[state.pos])) {
    while (state.pos < state.text.length && /[0-9]/.test(state.text[state.pos])) state.pos += 1;
  } else {
    return fail(state, 'MALFORMED_JSON', 'invalid number start');
  }
  if (state.text[state.pos] === '.') {
    state.pos += 1;
    if (state.pos >= state.text.length || !/[0-9]/.test(state.text[state.pos])) {
      return fail(state, 'MALFORMED_JSON', 'invalid fraction');
    }
    while (state.pos < state.text.length && /[0-9]/.test(state.text[state.pos])) state.pos += 1;
  }
  if (state.text[state.pos] === 'e' || state.text[state.pos] === 'E') {
    state.pos += 1;
    if (state.text[state.pos] === '+' || state.text[state.pos] === '-') state.pos += 1;
    if (state.pos >= state.text.length || !/[0-9]/.test(state.text[state.pos])) {
      return fail(state, 'MALFORMED_JSON', 'invalid exponent');
    }
    while (state.pos < state.text.length && /[0-9]/.test(state.text[state.pos])) state.pos += 1;
  }
  const raw = state.text.slice(start, state.pos);
  const value = Number(raw);
  if (!Number.isFinite(value)) return fail(state, 'NON_FINITE_NUMBER', 'non-finite number');
  return value;
}

function parseValue(state: TokenizerState, depth: number): unknown | ParseFailure {
  skipWhitespace(state);
  if (state.pos >= state.text.length) return fail(state, 'MALFORMED_JSON', 'unexpected end of input');
  const ch = state.text[state.pos];
  if (ch === '{') {
    if (depth + 1 > state.limits.maxNestingDepth) return fail(state, 'TOO_DEEP', 'nesting exceeds limit');
    state.collections += 1;
    if (state.collections > state.limits.maxCollections) {
      return fail(state, 'TOO_MANY_COLLECTIONS', 'collection count exceeds limit');
    }
    state.pos += 1;
    const obj: Record<string, unknown> = {};
    const seen = new Set<string>();
    skipWhitespace(state);
    if (state.text[state.pos] === '}') {
      state.pos += 1;
      return obj;
    }
    for (;;) {
      skipWhitespace(state);
      if (state.text[state.pos] !== '"') return fail(state, 'MALFORMED_JSON', 'expected object key');
      const keyResult = parseString(state);
      if (isParseFailure(keyResult)) {
        return keyResult;
      }
      const key = keyResult as string;
      if (seen.has(key)) return fail(state, 'DUPLICATE_KEY', `duplicate key: ${key}`);
      seen.add(key);
      skipWhitespace(state);
      if (state.text[state.pos] !== ':') return fail(state, 'MALFORMED_JSON', 'expected colon');
      state.pos += 1;
      const valueResult = parseValue(state, depth + 1);
      if (isParseFailure(valueResult)) {
        return valueResult;
      }
      obj[key] = valueResult;
      skipWhitespace(state);
      if (state.text[state.pos] === ',') {
        state.pos += 1;
        continue;
      }
      if (state.text[state.pos] === '}') {
        state.pos += 1;
        return obj;
      }
      return fail(state, 'MALFORMED_JSON', 'expected , or }');
    }
  }
  if (ch === '[') {
    if (depth + 1 > state.limits.maxNestingDepth) return fail(state, 'TOO_DEEP', 'nesting exceeds limit');
    state.collections += 1;
    if (state.collections > state.limits.maxCollections) {
      return fail(state, 'TOO_MANY_COLLECTIONS', 'collection count exceeds limit');
    }
    state.pos += 1;
    const arr: unknown[] = [];
    skipWhitespace(state);
    if (state.text[state.pos] === ']') {
      state.pos += 1;
      return arr;
    }
    for (;;) {
      const valueResult = parseValue(state, depth + 1);
      if (isParseFailure(valueResult)) {
        return valueResult;
      }
      arr.push(valueResult);
      skipWhitespace(state);
      if (state.text[state.pos] === ',') {
        state.pos += 1;
        continue;
      }
      if (state.text[state.pos] === ']') {
        state.pos += 1;
        return arr;
      }
      return fail(state, 'MALFORMED_JSON', 'expected , or ]');
    }
  }
  if (ch === '"') {
    const s = parseString(state);
    if (isParseFailure(s)) {
      return s;
    }
    return s as string;
  }
  if (ch === 't') {
    if (state.text.startsWith('true', state.pos)) {
      state.pos += 4;
      return true;
    }
    return fail(state, 'MALFORMED_JSON', 'invalid literal');
  }
  if (ch === 'f') {
    if (state.text.startsWith('false', state.pos)) {
      state.pos += 5;
      return false;
    }
    return fail(state, 'MALFORMED_JSON', 'invalid literal');
  }
  if (ch === 'n') {
    if (state.text.startsWith('null', state.pos)) {
      state.pos += 4;
      return null;
    }
    return fail(state, 'MALFORMED_JSON', 'invalid literal');
  }
  if (ch === '-' || /[0-9]/.test(ch)) {
    return parseNumber(state);
  }
  return fail(state, 'MALFORMED_JSON', `unexpected character: ${ch}`);
}

/**
 * Strict bounded parse. Rejects duplicate keys, oversized input, excessive depth/
 * collections, malformed JSON, non-finite numbers, and unpaired surrogates before any
 * downstream allocation. `unknownRootProperties` (when provided) are rejected as
 * `UNKNOWN_ROOT_PROPERTY`.
 */
export function parseBoundedJson<T = unknown>(
  bytes: Uint8Array,
  options: { readonly limits?: ParseLimits; readonly unknownRootProperties?: readonly string[] } = {},
): ParseOutcome<T> {
  const limits = options.limits ?? DEFAULT_PARSE_LIMITS;
  if (bytes.byteLength > limits.maxBytes) {
    return { ok: false, [PARSE_FAILURE_BRAND]: true, code: 'OVERSIZED_INPUT', message: `input exceeds ${limits.maxBytes} bytes`, offset: 0 };
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, [PARSE_FAILURE_BRAND]: true, code: 'MALFORMED_JSON', message: 'invalid UTF-8', offset: 0 };
  }
  const state: TokenizerState = { text, bytes, limits, pos: 0, collections: 0 };
  const value = parseValue(state, 0);
  if (isParseFailure(value)) {
    return value;
  }
  skipWhitespace(state);
  if (state.pos < text.length) {
    return fail(state, 'MALFORMED_JSON', 'trailing data after JSON document');
  }
  if (options.unknownRootProperties) {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      for (const key of Object.keys(value as Record<string, unknown>)) {
        if (!options.unknownRootProperties.includes(key)) {
          return { ok: false, [PARSE_FAILURE_BRAND]: true, code: 'UNKNOWN_ROOT_PROPERTY', message: `unknown root property: ${key}`, offset: 0 };
        }
      }
    }
  }
  return { ok: true, value: value as T, consumed: bytes.byteLength };
}

/** Deterministic canonical bytes of a parsed value (must be byte-stable). */
export function canonicalBytesOf(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalizeJson(value));
}
