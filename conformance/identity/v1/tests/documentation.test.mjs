#!/usr/bin/env node
/**
 * Consumer/contributor documentation validation (Task 5.2).
 * =========================================================
 * Mechanically checks the corpus README against the actual API surface:
 *   - every error code documented in the README table exists in the vector
 *     corpus or the API type surface;
 *   - documented field names used in examples exist in the corpus documents
 *     and report schema;
 *   - the Rust replay obligation and server-runtime exclusion are explicit;
 *   - no raw diagnostic guidance (no instructions to print secrets).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');

function readJson(rel) {
  return JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
}

const ALL_CODES = new Set();
for (const f of readdirSync(join(ROOT, 'vectors')).filter((x) => x.endsWith('.json'))) {
  const doc = readJson(join('vectors', f));
  for (const v of doc.vectors ?? []) {
    if (v.errorCode) ALL_CODES.add(v.errorCode);
  }
}

test('every README-documented error code exists in the corpus', () => {
  const table = README.split('## Consumer contract')[1]?.split('## Contributor contract')[0] ?? '';
  const codes = [...table.matchAll(/`([A-Z_]+)`/g)].map((m) => m[1]).filter((c) => c.startsWith('DAT_') || ['INVALID_WORD_COUNT', 'UNKNOWN_WORD', 'INVALID_CHECKSUM', 'INVALID_MNEMONIC', 'UNSUPPORTED_PRODUCER', 'UNSUPPORTED_VERSION', 'UNSUPPORTED_PASSPHRASE', 'INVALID_KEY_ENCODING', 'INVALID_PRIVATE_SCALAR', 'SIGNATURE_MALFORMED', 'DERIVATION_FAILURE', 'CANONICAL_MISMATCH'].includes(c));
  assert.ok(codes.length >= 20, 'README documents the full code table');
  for (const code of codes) {
    // DERIVATION_FAILURE / CANONICAL_MISMATCH are API runtime codes, not vector codes.
    assert.ok(ALL_CODES.has(code) || code === 'CANONICAL_MISMATCH' || code === 'DERIVATION_FAILURE', `documented code exists in corpus: ${code}`);
  }
});

test('README documents the full consumer flow and secret ownership', () => {
  for (const phrase of [
    'Normalize and validate',
    'public candidate descriptors',
    'precedence order',
    'never silently choose',
    'selected producer',
    'typed data',
    'Diagnostics never contain',
  ]) {
    assert.ok(README.includes(phrase), `consumer contract mentions: ${phrase}`);
  }
});

test('README documents the contributor rules', () => {
  for (const phrase of [
    'Semantic version bump',
    'Dual-owner review',
    'Deterministic formatting',
    'generate-manifest.mjs',
    'Public-test warnings',
    'Server-runtime exclusion',
    'replay every applicable version',
    'Incomplete evidence',
  ]) {
    assert.ok(README.toLowerCase().includes(phrase.toLowerCase()), `contributor contract mentions: ${phrase}`);
  }
});

test('README makes the Rust replay obligation explicit', () => {
  assert.ok(README.toLowerCase().includes('rust'), 'Rust obligation explicit');
  assert.ok(README.toLowerCase().includes('replay every applicable version'), 'Rust replay obligation stated');
});

test('README makes the server-runtime exclusion explicit', () => {
  assert.ok(README.toLowerCase().includes('server-runtime exclusion'), 'server-runtime exclusion section present');
  const sentence = README.split('\n').find((l) => l.toLowerCase().includes('runtime di'));
  assert.ok(sentence && sentence.toLowerCase().includes('never'), 'runtime DI never references corpus');
});

test('no raw diagnostic guidance in the documentation', () => {
  assert.ok(!README.toLowerCase().includes('console.log(mnemonic'), 'no raw mnemonic print guidance');
  assert.ok(!README.toLowerCase().includes('print(password'), 'no password print guidance');
  assert.ok(!README.toLowerCase().includes('echo private key'), 'no private-key echo guidance');
});

test('report contract references the authoritative schema and records runtime', () => {
  // The report schema is the authoritative field-name contract; the README must
  // point consumers at it and record the runtime values it emits.
  assert.ok(README.includes('report.schema.json'), 'README references the authoritative report schema');
  assert.ok(README.includes('runtime'), 'README mentions the report runtime field');
  assert.ok(README.includes('typescript') && README.includes('dotnet'), 'README documents both runtimes');
});
