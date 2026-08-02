/**
 * Vault corpus integrity tests (Task 2.6).
 * Manifest reproduction, drift detection, stable sort, tamper detection, and
 * deterministic generation — mirrors conformance/identity/v1 conventions.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ROOT,
  MANIFEST_PATH,
  collectDataFiles,
  digest,
  generateManifest,
  serializeManifest,
  verifyManifestAgainstDisk,
} from '../scripts/generate-manifest.mjs';

test('manifest reproduces byte-for-byte on repeated generation', () => {
  const a = serializeManifest(generateManifest());
  const b = serializeManifest(generateManifest());
  assert.equal(a, b);
});

test('manifest lists every data file in stable sorted order', () => {
  const files = generateManifest().files;
  const paths = files.map((f) => f.path);
  assert.deepEqual(paths, [...paths].sort());
  const disk = collectDataFiles();
  assert.deepEqual(paths, disk);
});

test('manifest entries carry exact byte lengths and SHA-256 digests', () => {
  for (const f of generateManifest().files) {
    const abs = join(ROOT, f.path);
    assert.equal(f.bytes, readFileSync(abs).length, `${f.path} byte length`);
    assert.equal(f.sha256, digest(abs), `${f.path} digest`);
    assert.match(f.sha256, /^[0-9a-f]{64}$/);
  }
});

test('committed manifest matches disk (no drift)', () => {
  assert.doesNotThrow(() => verifyManifestAgainstDisk());
});

test('tampered or unexpected file fails integrity verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vault-manifest-'));
  const backup = readFileSync(MANIFEST_PATH);
  try {
    writeFileSync(MANIFEST_PATH, serializeManifest({ contractVersion: '1.0.0', corpusVersion: '1.0.0', files: [{ path: 'schemas/envelope.schema.json', bytes: 1, sha256: '0'.repeat(64) }] }));
    assert.throws(() => verifyManifestAgainstDisk(), /manifest drift/);
  } finally {
    writeFileSync(MANIFEST_PATH, backup);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('manifest schema is stable and self-describing', () => {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
  assert.equal(manifest.contractVersion, '1.0.0');
  assert.equal(manifest.corpusVersion, '1.0.0');
  assert.ok(manifest.files.length >= 9, `expected >= 9 data files, got ${manifest.files.length}`);
});
