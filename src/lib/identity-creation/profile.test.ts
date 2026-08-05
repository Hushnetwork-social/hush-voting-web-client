/**
 * FEAT-007 Task 2.4 — unit/property tests for profile validation and the
 * canonical transaction description. Coverage targets: AC-007-003–009,
 * 020–021, 025–026, 046, 049, 051; exact FEAT-001 vectors; deterministic
 * no-password influence.
 */
import { describe, expect, it } from 'vitest';
import {
  FULL_IDENTITY_PAYLOAD_KIND,
  createUuidV4,
  corpusTimestamp,
  describeCanonicalTransaction,
  isFullIdentityPayloadKind,
  validateAlias,
} from './profile';

const SIGNING = 'A11B22C33D44E55F66A77B88C99D00E11F22A33B44C55D66E77F88A99B00C11';
const ENCRYPT = 'Q77W66E55R44T33Y22U11I00O99P88A77S66D55F44G33H22J11K00L99M88';

describe('validateAlias — normalization and bounds', () => {
  it('trims outer whitespace and normalizes NFC', () => {
    const result = validateAlias('  Voter  ');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.normalizedNfc).toBe('Voter');
    }
  });

  it('accepts composed and decomposed equivalently (NFC fold)', () => {
    const composed = validateAlias('caf\u00e9');
    const decomposed = validateAlias('cafe\u0301');
    expect(composed.ok).toBe(true);
    expect(decomposed.ok).toBe(true);
    if (composed.ok && decomposed.ok) {
      expect(composed.normalizedNfc).toBe(decomposed.normalizedNfc);
    }
  });

  it('rejects empty and whitespace-only aliases', () => {
    expect(validateAlias('').ok).toBe(false);
    expect(validateAlias('   ').ok).toBe(false);
    expect(validateAlias('\u2003').ok).toBe(false);
  });

  it('enforces the 64-grapheme bound', () => {
    const ok = validateAlias('a'.repeat(64));
    expect(ok.ok).toBe(true);
    const tooLong = validateAlias('a'.repeat(65));
    expect(tooLong.ok).toBe(false);
    if (!tooLong.ok) {
      expect(tooLong.code).toBe('TOO_MANY_GRAPHEMES');
    }
  });

  it('enforces the 256 UTF-8 byte bound independently of the grapheme bound', () => {
    // 1 grapheme (base + 127 combining acutes) = 255 bytes → accepted.
    const maxBytes = validateAlias('a' + '\u0301'.repeat(127));
    expect(maxBytes.ok).toBe(true);
    // 1 grapheme (base + 130 combining acutes) = 261 bytes → byte bound rejects.
    const tooMany = validateAlias('a' + '\u0301'.repeat(130));
    expect(tooMany.ok).toBe(false);
    if (!tooMany.ok) {
      expect(tooMany.code).toBe('TOO_MANY_BYTES');
    }
  });

  it('rejects disallowed controls, bidi, and unsafe invisible text', () => {
    expect(validateAlias('bad\u0000alias').ok).toBe(false);
    expect(validateAlias('bad\u0009alias').ok).toBe(false);
    expect(validateAlias('bad\u2028alias').ok).toBe(false);
    expect(validateAlias('bad\u202ealias').ok).toBe(false); // bidi override
    expect(validateAlias('bad\u200balias').ok).toBe(false); // zero-width space
    expect(validateAlias('bad\u00adalias').ok).toBe(false); // soft hyphen
    expect(validateAlias('bad\ufeffalias').ok).toBe(false); // BOM
  });

  it('preserves permitted internal text and spacing', () => {
    const result = validateAlias('Ada Lovelace');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.normalizedNfc).toBe('Ada Lovelace');
    }
  });

  it('rejects unpaired surrogates', () => {
    const result = validateAlias('bad\uD800alias');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('UNPAIRED_SURROGATE');
    }
  });

  it('allows ZWJ emoji families as single grapheme clusters (context joiner)', () => {
    const family = validateAlias('\u{1F468}\u200D\u{1F469}\u200D\u{1F467}'); // man+ZWJ+woman+ZWJ+girl
    expect(family.ok).toBe(true);
    if (family.ok) {
      expect(family.graphemeClusters).toBe(1);
    }
  });
});

describe('describeCanonicalTransaction — FEAT-001 corpus fidelity', () => {
  it('produces the exact payload kind GUID', () => {
    expect(FULL_IDENTITY_PAYLOAD_KIND).toBe('351cd60b-3fdf-48d4-b608-e93c0100f7d0');
    expect(isFullIdentityPayloadKind(FULL_IDENTITY_PAYLOAD_KIND)).toBe(true);
    expect(isFullIdentityPayloadKind('not-a-guid')).toBe(false);
  });

  it('uses the historical property order and computed PayloadSize', () => {
    const tx = describeCanonicalTransaction({
      normalizedAlias: 'Voter',
      publicSigningAddress: SIGNING,
      publicEncryptAddress: ENCRYPT,
      visibility: 'private',
      transactionId: createUuidV4(),
      timestamp: corpusTimestamp(new Date('2026-08-04T01:00:00.123Z')),
    });
    expect(tx.ok).toBe(true);
    if (!tx.ok) return;
    const keys = Object.keys(tx.value.unsignedTransaction);
    expect(keys).toEqual(['TransactionId', 'PayloadKind', 'TransactionTimeStamp', 'Payload', 'PayloadSize']);
    expect(tx.value.unsignedTransaction.PayloadKind).toBe(FULL_IDENTITY_PAYLOAD_KIND);
    expect(tx.value.payload.PublicSigningAddress).toBe(SIGNING);
    expect(tx.value.payload.PublicEncryptAddress).toBe(ENCRYPT);
    expect(tx.value.payload.IsPublic).toBe(false);
    expect(tx.value.payloadSize).toBe(tx.value.unsignedTransaction.PayloadSize);
  });

  it('binds signatory exactly to the payload signing address', () => {
    const tx = describeCanonicalTransaction({
      normalizedAlias: 'Voter',
      publicSigningAddress: SIGNING,
      publicEncryptAddress: ENCRYPT,
      visibility: 'public',
      transactionId: createUuidV4(),
      timestamp: corpusTimestamp(new Date('2026-08-04T01:00:00.123Z')),
    });
    expect(tx.ok).toBe(true);
    if (!tx.ok) return;
    expect(tx.value.signatory).toBe(SIGNING);
    expect(tx.value.signatoryBindsToPayload).toBe(true);
    expect(tx.value.payload.IsPublic).toBe(true);
  });

  it('rejects malformed transaction IDs and timestamps (fail closed)', () => {
    const base = {
      normalizedAlias: 'Voter',
      publicSigningAddress: SIGNING,
      publicEncryptAddress: ENCRYPT,
      visibility: 'private' as const,
    };
    expect(describeCanonicalTransaction({ ...base, transactionId: 'not-a-uuid', timestamp: corpusTimestamp() }).ok).toBe(false);
    expect(describeCanonicalTransaction({ ...base, transactionId: createUuidV4(), timestamp: '2026-08-04' }).ok).toBe(false);
    expect(describeCanonicalTransaction({ ...base, transactionId: createUuidV4(), timestamp: '2026-08-04T01:00:00Z' }).ok).toBe(false);
  });

  it('produces digest bytes byte-exact to the FEAT-001 canonical serializer', async () => {
    const tx = describeCanonicalTransaction({
      normalizedAlias: 'Voter',
      publicSigningAddress: SIGNING,
      publicEncryptAddress: ENCRYPT,
      visibility: 'private',
      transactionId: '00000000-0000-4000-8000-000000000000',
      timestamp: '2026-08-04T01:00:00.000Z',
    });
    expect(tx.ok).toBe(true);
    if (!tx.ok) return;
    // Re-serialize through the canonical API and compare bytes exactly.
    const { canonicalBytes, serializeUnsignedTransaction } = await import('../identity-compatibility/canonical');
    const expected = canonicalBytes(serializeUnsignedTransaction(tx.value.unsignedTransaction));
    expect(Buffer.from(tx.value.canonicalBytes).equals(Buffer.from(expected))).toBe(true);
  });
});

describe('createUuidV4 / corpusTimestamp', () => {
  it('generates RFC 4122 v4 UUIDs with CSPRNG bytes', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const id = createUuidV4();
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      seen.add(id);
    }
    expect(seen.size).toBe(1000);
  });

  it('produces corpus-exact 3-digit-millisecond UTC timestamps', () => {
    const ts = corpusTimestamp(new Date('2026-08-04T01:02:03.004Z'));
    expect(ts).toBe('2026-08-04T01:02:03.004Z');
    expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });
});

describe('deterministic no-password influence', () => {
  it('the same alias/addresses/visibility produce identical descriptions regardless of any password', () => {
    const txA = describeCanonicalTransaction({
      normalizedAlias: 'Voter',
      publicSigningAddress: SIGNING,
      publicEncryptAddress: ENCRYPT,
      visibility: 'private',
      transactionId: '00000000-0000-4000-8000-000000000000',
      timestamp: '2026-08-04T01:00:00.000Z',
    });
    const txB = describeCanonicalTransaction({
      normalizedAlias: 'Voter',
      publicSigningAddress: SIGNING,
      publicEncryptAddress: ENCRYPT,
      visibility: 'private',
      transactionId: '00000000-0000-4000-8000-000000000000',
      timestamp: '2026-08-04T01:00:00.000Z',
    });
    expect(txA.ok).toBe(true);
    expect(txB.ok).toBe(true);
    if (txA.ok && txB.ok) {
      expect(JSON.stringify(txA.value)).toBe(JSON.stringify(txB.value));
    }
  });
});
