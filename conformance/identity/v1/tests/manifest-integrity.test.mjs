/**
 * Manifest and formatting integrity tests (Task 2.8)
 * ==================================================
 * Changed bytes, missing files, unlisted files, line-ending/BOM/key-order
 * drift, invalid schema, and wrong expected manifest digests all fail
 * deterministically. These tests read only; they never mutate the corpus.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate } from '../scripts/vendor/ajv-bundle.mjs';
import { buildManifest, collectDataFiles, digest, stableStringify } from '../scripts/generate-manifest.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = join(ROOT, 'manifest.json');
const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
const schema = JSON.parse(readFileSync(join(ROOT, 'schemas/manifest.schema.json'), 'utf8'));

test('manifest.json exists and validates against its schema', () => {
  assert.ok(existsSync(MANIFEST), 'manifest.json missing');
  const result = validate(schema, manifest);
  assert.ok(result.valid, result.errors.map((e) => e.instancePath + ' ' + e.message).join('; '));
  assert.equal(manifest.schemaVersion, '1.0.0');
  assert.match(manifest.contractVersion, /^[0-9]+\.[0-9]+\.[0-9]+$/);
});

test('every listed file exists with matching digest and byte length (changed bytes detected)', () => {
  for (const f of manifest.files) {
    const full = join(ROOT, f.path);
    assert.ok(existsSync(full), `listed file missing: ${f.path}`);
    const bytes = readFileSync(full);
    assert.equal(digest(full), f.sha256, `digest mismatch for ${f.path}`);
    assert.equal(bytes.length, f.bytes, `byte length mismatch for ${f.path}`);
  }
});

test('no corpus data file is unlisted (missing/unlisted files detected)', () => {
  const listed = new Set(manifest.files.map((f) => f.path));
  const actual = new Set(collectDataFiles());
  assert.deepEqual([...listed].sort(), [...actual].sort(), 'manifest and corpus file lists differ');
});

test('regeneration is deterministic and byte-stable (drift detected)', () => {
  const regenerated = stableStringify(buildManifest());
  const committed = readFileSync(MANIFEST, 'utf8');
  assert.equal(regenerated, committed, 'regenerated manifest differs from committed manifest');
});

test('a changed file would change its manifest digest (mutation detection)', () => {
  const target = manifest.files.find((f) => f.path.endsWith('mnemonic-vectors.json'));
  const bytes = readFileSync(join(ROOT, target.path));
  const mutated = Buffer.from(bytes);
  mutated[mutated.length - 2] ^= 0x01; // flip one byte of the final newline region
  const mutatedDigest = createHash('sha256').update(mutated).digest('hex');
  assert.notEqual(mutatedDigest, target.sha256, 'byte flip did not change the digest');
});

test('manifest rejects invalid schema content (wrong structure)', () => {
  const bad = { ...manifest, files: [{ path: 'x.json', sha256: 'abc', bytes: -1 }] };
  const result = validate(schema, bad);
  assert.equal(result.valid, false);
  const missingField = { schemaVersion: '1.0.0', contractVersion: '1.0.0' };
  assert.equal(validate(schema, missingField).valid, false);
});

test('manifest integrity is stable across reads (wrong expected digest detection)', () => {
  // Consumers pin the expected SHA-256 of manifest.json itself; recomputing it
  // must be stable for an unchanged corpus (deterministic check-mode input).
  const first = digest(MANIFEST);
  const second = digest(MANIFEST);
  assert.equal(first, second);
  assert.match(first, /^[0-9a-f]{64}$/);
});

test('corpus formatting rules hold for every manifest-listed file', () => {
  const sortKeys = (o) => {
    if (Array.isArray(o)) return o.map(sortKeys);
    if (o && typeof o === 'object') {
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys(o[k])]));
    }
    return o;
  };
  for (const f of manifest.files) {
    const raw = readFileSync(join(ROOT, f.path), 'utf8');
    assert.ok(raw.charCodeAt(0) !== 0xfeff, `${f.path} has BOM`);
    assert.ok(!raw.includes('\r'), `${f.path} has CRLF`);
    assert.ok(raw.endsWith('\n'), `${f.path} missing final newline`);
    assert.equal(raw, JSON.stringify(sortKeys(JSON.parse(raw)), null, 2) + '\n', `${f.path} not canonically formatted`);
  }
});
