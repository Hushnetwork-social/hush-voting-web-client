/**
 * Negative matrix completeness tests (Task 2.6)
 * =============================================
 * Verifies the corpus covers every mandatory negative/tamper category with
 * stable error codes, unique fixture IDs, and no contradictory expected
 * outcomes, and that controlled lookup outcomes cover zero/one/multiple
 * matches plus exact-pair deduplication.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
const raw = (rel) => readFileSync(join(ROOT, rel), 'utf8');

const negative = read('vectors/negative-vectors.json');
const dat = read('vectors/dat-vectors.json');
const key = read('vectors/key-vectors.json');
const signature = read('vectors/signature-vectors.json');
const mnemonic = read('vectors/mnemonic-vectors.json');
const canonical = read('vectors/canonical-byte-vectors.json');
const lookup = read('lookup/outcomes.json');

const STABLE_ERROR_CODES = new Set([
  'INVALID_WORD_COUNT',
  'UNKNOWN_WORD',
  'INVALID_CHECKSUM',
  'INVALID_MNEMONIC',
  'UNSUPPORTED_PRODUCER',
  'UNSUPPORTED_VERSION',
  'UNSUPPORTED_PASSPHRASE',
  'INVALID_KEY_ENCODING',
  'INVALID_PRIVATE_SCALAR',
  'DAT_INVALID_MAGIC',
  'DAT_UNSUPPORTED_VERSION',
  'DAT_MALFORMED',
  'DAT_WRONG_PASSWORD',
  'DAT_MISSING_FIELD',
  'DAT_UNKNOWN_FIELD',
  'DAT_DUPLICATE_FIELD',
  'DAT_INVALID_FIELD',
  'DAT_MNEMONIC_KEY_MISMATCH',
  'DAT_KEY_MISMATCH',
  'SIGNATURE_MALFORMED',
  'DERIVATION_FAILURE',
  'CANONICAL_MISMATCH',
]);

test('all fixture IDs are unique across the corpus', () => {
  const all = [...mnemonic.vectors, ...key.vectors, ...dat.vectors, ...canonical.vectors, ...signature.vectors, ...negative.vectors];
  const ids = all.map((v) => v.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate fixture IDs detected');
});

test('every ERROR vector carries a stable documented error code', () => {
  const vectors = [...key.vectors, ...dat.vectors, ...signature.vectors, ...negative.vectors];
  for (const v of vectors) {
    if (v.expected === 'ERROR') {
      assert.ok(v.errorCode, `${v.id} has no errorCode`);
      assert.ok(STABLE_ERROR_CODES.has(v.errorCode), `${v.id} uses undocumented code ${v.errorCode}`);
    }
  }
});

test('negative matrix covers every mandatory mnemonic category', () => {
  const codes = new Set(negative.vectors.map((v) => v.errorCode));
  for (const code of ['INVALID_WORD_COUNT', 'UNKNOWN_WORD', 'INVALID_CHECKSUM', 'INVALID_MNEMONIC', 'UNSUPPORTED_PRODUCER', 'UNSUPPORTED_VERSION', 'UNSUPPORTED_PASSPHRASE']) {
    assert.ok(codes.has(code), `missing negative code ${code}`);
  }
});

test('12-word rejection for P-02 is present', () => {
  const v = negative.vectors.find((x) => x.producerId === 'P-02' && x.errorCode === 'INVALID_WORD_COUNT');
  assert.ok(v, 'missing P-02 12-word rejection');
  assert.equal(v.input.split(' ').length, 12);
});

test('dat vectors cover every envelope and JSON failure mode', () => {
  const codes = new Set(dat.vectors.map((v) => v.errorCode).filter(Boolean));
  for (const code of [
    'DAT_INVALID_MAGIC',
    'DAT_UNSUPPORTED_VERSION',
    'DAT_MALFORMED',
    'DAT_WRONG_PASSWORD',
    'DAT_MISSING_FIELD',
    'DAT_UNKNOWN_FIELD',
    'DAT_DUPLICATE_FIELD',
    'DAT_INVALID_FIELD',
    'DAT_MNEMONIC_KEY_MISMATCH',
    'DAT_KEY_MISMATCH',
  ]) {
    assert.ok(codes.has(code), `dat vectors missing ${code}`);
  }
  const ops = new Set(dat.vectors.map((v) => v.operation));
  for (const op of ['DECRYPT', 'PARSE', 'OVERSIZED', 'KEY_CONSISTENCY']) {
    assert.ok(ops.has(op), `dat vectors missing operation ${op}`);
  }
});

test('key vectors cover malformed encodings and invalid scalars', () => {
  const codes = new Set(key.vectors.map((v) => v.errorCode).filter(Boolean));
  for (const code of ['INVALID_KEY_ENCODING', 'INVALID_PRIVATE_SCALAR']) {
    assert.ok(codes.has(code), `key vectors missing ${code}`);
  }
  const zero = key.vectors.find((v) => v.id === 'K-010');
  assert.equal(zero.privateScalarHex, '00'.repeat(32));
  const aboveN = key.vectors.find((v) => v.id === 'K-012');
  assert.ok(BigInt('0x' + aboveN.privateScalarHex) > BigInt('0x' + 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'));
});

test('signature vectors cover wrong-key, wrong-message, mutation, and malformed encodings', () => {
  assert.ok(signature.vectors.some((v) => v.id === 'S-003' && v.expected === 'INVALID'), 'wrong-message vector missing');
  assert.ok(signature.vectors.some((v) => v.id === 'S-004' && v.expected === 'INVALID'), 'mutated-signature vector missing');
  assert.ok(signature.vectors.some((v) => v.id === 'S-005' && v.expected === 'INVALID'), 'wrong-key vector missing');
  assert.ok(signature.vectors.some((v) => v.errorCode === 'SIGNATURE_MALFORMED'), 'malformed signature vectors missing');
  assert.ok(signature.vectors.some((v) => v.expected === 'VALID' && v.producerId === 'P-01'), 'P-01 valid fixture missing');
  assert.ok(signature.vectors.some((v) => v.expected === 'VALID' && v.producerId === 'P-02'), 'P-02 valid fixture missing');
  assert.ok(signature.vectors.some((v) => v.expected === 'VALID' && v.producerId === 'P-07'), 'P-07 DER verification fixture missing');
});

test('canonical byte vectors cover every tamper class', () => {
  const mutations = new Set(canonical.vectors.filter((v) => v.operation === 'TAMPER').map((v) => v.mutation));
  for (const m of ['REORDER_PAYLOAD_FIELDS', 'CHANGE_TIMESTAMP_MS', 'CHANGE_PAYLOAD_SIZE', 'CHANGE_TRANSACTION_ID', 'CHANGE_PAYLOAD_KIND', 'CHANGE_ALIAS_VALUE', 'NON_ASCII_UTF8_ALIAS']) {
    assert.ok(mutations.has(m), `missing canonical tamper ${m}`);
  }
  const base = canonical.vectors.find((v) => v.id === 'CB-001');
  assert.equal(base.utf8Hex.length / 2, base.utf8Length, 'CB-001 utf8Hex length mismatch');
  assert.equal(base.payloadSize, new TextEncoder().encode(JSON.parse(base.json).Payload ? JSON.stringify(JSON.parse(base.json).Payload) : '').length, 'CB-001 payloadSize mismatch');
});

test('lookup outcomes cover zero, one, multiple, and dedup scenarios', () => {
  const counts = lookup.scenarios.map((s) => s.expected.matchCount);
  assert.ok(counts.includes(0), 'no zero-match scenario');
  assert.ok(counts.includes(1), 'no one-match scenario');
  assert.ok(counts.includes(2), 'no multiple-match scenario');
  const dedup = lookup.scenarios.find((s) => s.expected.deduplicated);
  assert.ok(dedup, 'no dedup scenario');
  assert.deepEqual(dedup.expected.producers.sort(), ['P-02', 'P-03']);
  const multi = lookup.scenarios.find((s) => s.expected.ambiguous);
  assert.ok(multi, 'no ambiguous multi-match scenario');
});

test('corpus contains no private-key markers or placeholder secrets', () => {
  const joined = [
    raw('vectors/negative-vectors.json'),
    raw('vectors/dat-vectors.json'),
    raw('vectors/key-vectors.json'),
    raw('vectors/signature-vectors.json'),
    raw('vectors/mnemonic-vectors.json'),
    raw('vectors/canonical-byte-vectors.json'),
    raw('lookup/outcomes.json'),
  ].join('\n');
  assert.ok(!joined.includes('BEGIN PRIVATE KEY'), 'PEM private key material found');
  assert.ok(!joined.includes('BEGIN RSA PRIVATE KEY'), 'RSA private key material found');
  assert.ok(!joined.includes('PRIVATE_KEY_HEX'), 'placeholder secret markers found');
});
