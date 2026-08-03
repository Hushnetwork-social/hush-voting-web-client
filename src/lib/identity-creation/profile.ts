/**
 * FEAT-007 identity-creation — profile validation and canonical transaction
 * description.
 *
 * Deterministic alias/visibility validation (NFC, Unicode 16.0.0 grapheme
 * clusters, UTF-8 byte bound, disallowed controls/bidi/invisible text) and the
 * exact FullIdentity transaction construction inputs: CSPRNG UUIDv4, corpus
 * UTC timestamp, historical property order, UTF-8 payload size, payload GUID,
 * signatory binding, and digest metadata.
 *
 * Framework-neutral: no React/DOM/storage/transport dependencies. Reuses the
 * FEAT-001 canonical serializer (`identity-compatibility/canonical.ts`) for the
 * byte-exact representation; this module owns the reviewed-profile inputs.
 *
 * Normative source: FEAT-007 FeatureDescription "Profile Contract",
 * "Canonical Transaction Construction"; FEAT-001 corpus timestamp/UUID rules.
 */
import { canonicalBytes, payloadSizeBytes, serializeUnsignedTransaction, type CanonicalPayload, type CanonicalUnsignedTransaction } from '../identity-compatibility/canonical.js';

/** Pinned Unicode data version (matches FEAT-003 v1). */
export const UNICODE_VERSION = '16.0.0' as const;

/** The exact payload kind GUID for a FullIdentity transaction. */
export const FULL_IDENTITY_PAYLOAD_KIND = '351cd60b-3fdf-48d4-b608-e93c0100f7d0' as const;

export const ALIAS_MIN_GRAPHEMES = 1 as const;
export const ALIAS_MAX_GRAPHEMES = 64 as const;
export const ALIAS_MAX_UTF8_BYTES = 256 as const;

export type AliasValidation =
  | { readonly ok: true; readonly normalizedNfc: string; readonly graphemeClusters: number; readonly utf8Bytes: number }
  | {
      readonly ok: false;
      readonly code: 'INVALID_ENCODING' | 'UNPAIRED_SURROGATE' | 'EMPTY_AFTER_TRIM' | 'TOO_MANY_GRAPHEMES' | 'TOO_MANY_BYTES' | 'DISALLOWED_CHARACTER';
      readonly message: string;
    };

const GRAPHEME_SEGMENTER = new Intl.Segmenter('und', { granularity: 'grapheme' });

function countGraphemes(value: string): number {
  return [...GRAPHEME_SEGMENTER.segment(value)].length;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

/**
 * Disallowed code points: C0/C1 controls, DEL, line/paragraph separators,
 * bidi formatting/override controls, and unsafe invisible text (zero-width
 * space, word joiner, BOM, soft hyphen). ZWJ (U+200D) and ZWNJ (U+200C) are
 * deliberately ALLOWED: they are legitimate context joiners in emoji
 * sequences and writing systems (e.g., Persian), and Intl.Segmenter folds
 * them into single visible graphemes. Permitted internal spacing includes
 * regular spaces and other visible Unicode text.
 */
const DISALLOWED_CODE_POINTS = new Set<number>([
  0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000c,
  0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019,
  0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f, 0x007f, 0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085,
  0x0086, 0x0087, 0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092,
  0x0093, 0x0094, 0x0095, 0x0096, 0x0097, 0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
  0x00ad, // soft hyphen (format control / unsafe invisible)
  0x200b, // zero width space
  0x200e, // left-to-right mark
  0x200f, // right-to-left mark
  0x2028, // line separator
  0x2029, // paragraph separator
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi embedding/override/pop
  0x2060, // word joiner
  0x2066, 0x2067, 0x2068, 0x2069, // bidi isolates
  0xfeff, // zero width no-break space / BOM
]);;

function hasUnpairedSurrogate(input: string): boolean {
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = input.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return true;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** Trim outer Unicode whitespace (grapheme-aware). */
function trimUnicode(value: string): string {
  return value.replace(/^\s+|\s+$/gu, '');
}

/**
 * Validate and normalize an alias. Trims outer Unicode whitespace, normalizes
 * to NFC, rejects disallowed controls/bidi/invisible text, and enforces the
 * 1–64 grapheme / ≤256 UTF-8 byte bounds. Must be called identically before
 * review, signing, and server submission.
 */
export function validateAlias(input: string): AliasValidation {
  if (hasUnpairedSurrogate(input)) {
    return { ok: false, code: 'UNPAIRED_SURROGATE', message: 'alias contains unpaired surrogate' };
  }
  let normalized: string;
  try {
    normalized = input.normalize('NFC');
  } catch {
    return { ok: false, code: 'INVALID_ENCODING', message: 'cannot normalize alias' };
  }
  const trimmed = trimUnicode(normalized);
  if (trimmed.length === 0) {
    return { ok: false, code: 'EMPTY_AFTER_TRIM', message: 'alias must contain at least one character' };
  }
  for (const ch of trimmed) {
    if (DISALLOWED_CODE_POINTS.has(ch.codePointAt(0) ?? -1)) {
      return { ok: false, code: 'DISALLOWED_CHARACTER', message: 'alias contains a disallowed control or invisible character' };
    }
  }
  const graphemes = countGraphemes(trimmed);
  if (graphemes > ALIAS_MAX_GRAPHEMES) {
    return { ok: false, code: 'TOO_MANY_GRAPHEMES', message: `alias must not exceed ${ALIAS_MAX_GRAPHEMES} grapheme clusters` };
  }
  const bytes = utf8Length(trimmed);
  if (bytes > ALIAS_MAX_UTF8_BYTES) {
    return { ok: false, code: 'TOO_MANY_BYTES', message: `alias must not exceed ${ALIAS_MAX_UTF8_BYTES} UTF-8 bytes` };
  }
  return { ok: true, normalizedNfc: trimmed, graphemeClusters: graphemes, utf8Bytes: bytes };
}

/** Initial visibility choice with explicit Public acknowledgement requirement. */
export type VisibilityChoice = 'private' | 'public';

export interface PublicAcknowledgment {
  readonly acknowledged: true;
}

/** Inputs for the canonical FullIdentity transaction description. */
export interface TransactionDescriptionInput {
  readonly normalizedAlias: string;
  readonly publicSigningAddress: string;
  readonly publicEncryptAddress: string;
  readonly visibility: VisibilityChoice;
  /** CSPRNG-generated RFC 4122 UUIDv4 (created by the caller inside the authority). */
  readonly transactionId: string;
  /** Corpus-exact UTC timestamp (ISO 8601 with 3-digit milliseconds, `...Z`). */
  readonly timestamp: string;
}

export interface CanonicalTransactionDescription {
  readonly payload: CanonicalPayload;
  readonly unsignedTransaction: CanonicalUnsignedTransaction;
  readonly payloadSize: number;
  readonly signatory: string;
  readonly signatoryBindsToPayload: true;
  /** UTF-8 digest bytes of the canonical transaction JSON (for the sealed record). */
  readonly canonicalBytes: Uint8Array;
}

/** Payload kind validation — must equal the sealed FullIdentity GUID. */
export function isFullIdentityPayloadKind(kind: string): boolean {
  return kind === FULL_IDENTITY_PAYLOAD_KIND;
}

/**
 * Build the canonical FullIdentity transaction description from reviewed
 * profile fields and exact candidate addresses. Signatory always equals the
 * payload signing address; no password or private credential participates.
 * Returns typed failure when the transaction ID or timestamp is not in the
 * corpus-compatible form (fail closed).
 */
export function describeCanonicalTransaction(input: TransactionDescriptionInput): { readonly ok: true; readonly value: CanonicalTransactionDescription } | { readonly ok: false; readonly code: 'INVALID_TRANSACTION_ID' | 'INVALID_TIMESTAMP'; readonly message: string } {
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRe.test(input.transactionId)) {
    return { ok: false, code: 'INVALID_TRANSACTION_ID', message: 'transaction id must be a CSPRNG RFC 4122 UUIDv4' };
  }
  const tsRe = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  if (!tsRe.test(input.timestamp)) {
    return { ok: false, code: 'INVALID_TIMESTAMP', message: 'timestamp must be corpus-exact UTC ISO-8601 with 3-digit milliseconds' };
  }
  const payload: CanonicalPayload = {
    IdentityAlias: input.normalizedAlias,
    PublicSigningAddress: input.publicSigningAddress,
    PublicEncryptAddress: input.publicEncryptAddress,
    IsPublic: input.visibility === 'public',
  };
  const payloadSize = payloadSizeBytes(payload);
  const unsignedTransaction: CanonicalUnsignedTransaction = {
    TransactionId: input.transactionId,
    PayloadKind: FULL_IDENTITY_PAYLOAD_KIND,
    TransactionTimeStamp: input.timestamp,
    Payload: payload,
    PayloadSize: payloadSize,
  };
  return {
    ok: true,
    value: {
      payload,
      unsignedTransaction,
      payloadSize,
      signatory: input.publicSigningAddress,
      signatoryBindsToPayload: true,
      // Digest must be byte-exact to the FEAT-001 canonical serializer (not a
      // parallel stringify), so exact-byte retention and retry reuse match.
      canonicalBytes: canonicalBytes(serializeUnsignedTransaction(unsignedTransaction)),
    },
  };
}

/** Generate a CSPRNG RFC 4122 UUIDv4 (Node ≥16 and modern browsers). */
export function createUuidV4(): string {
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new Error('crypto.getRandomValues unavailable');
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Corpus-exact UTC timestamp (ISO 8601 with 3-digit milliseconds). */
export function corpusTimestamp(date: Date = new Date()): string {
  return date.toISOString();
}
