#!/usr/bin/env node
/**
 * Release archive reproducibility gate (Task 5.4).
 * ==================================================
 * Two builds from identical inputs must produce byte-identical archives;
 * missing required inputs must fail; archives must never contain runtime logs
 * or credential values.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { sha256Hex, collectCorpusFiles } from '../scripts/create-release-archive.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'create-release-archive.mjs');

function runArchive(version, outputDir, extra = []) {
  const args = [SCRIPT, '--version', version, '--output', outputDir, ...extra];
  const stdout = execFileSync(process.execPath, args, { encoding: 'utf8' });
  return stdout;
}

test('two builds produce byte-identical archives and digests', () => {
  const dirA = mkdtempSync(join(tmpdir(), 'hush-rel-a-'));
  const dirB = mkdtempSync(join(tmpdir(), 'hush-rel-b-'));
  try {
    runArchive('1.0.0', dirA);
    runArchive('1.0.0', dirB);
    const archiveA = readFileSync(join(dirA, 'hush-identity-corpus-1.0.0.tar.gz'));
    const archiveB = readFileSync(join(dirB, 'hush-identity-corpus-1.0.0.tar.gz'));
    assert.equal(sha256Hex(archiveA), sha256Hex(archiveB), 'archives must be byte-identical');
    const evidenceA = JSON.parse(readFileSync(join(dirA, 'release-evidence.json'), 'utf8'));
    const evidenceB = JSON.parse(readFileSync(join(dirB, 'release-evidence.json'), 'utf8'));
    assert.deepEqual(evidenceA, evidenceB);
    const digestFile = readFileSync(join(dirA, 'archive.sha256'), 'utf8').trim();
    assert.ok(digestFile.includes(sha256Hex(archiveA)), 'archive.sha256 records the archive digest');
    assert.ok(digestFile.includes('hush-identity-corpus-1.0.0.tar.gz'));
  } finally {
    rmSync(dirA, { recursive: true, force: true });
    rmSync(dirB, { recursive: true, force: true });
  }
});

test('missing required version fails', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hush-rel-fail-'));
  try {
    assert.throws(() => runArchive('', dir), /version/i);
    assert.throws(() => runArchive('1.0', dir), /semantic/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('missing optional report fails explicitly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hush-rel-report-'));
  try {
    assert.throws(() => runArchive('1.0.0', dir, ['--ts-report', join(dir, 'nope.json')]), /not found/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('wrong-runtime report is rejected', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hush-rel-runtime-'));
  try {
    const bogus = join(dir, 'bogus.json');
    writeFileSync(bogus, JSON.stringify({ runtime: 'java', records: [] }));
    assert.throws(() => runArchive('1.0.0', dir, ['--ts-report', bogus]), /runtime mismatch/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('archive contains no runtime logs and no credential values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hush-rel-secret-'));
  try {
    runArchive('1.0.0', dir);
    const archive = readFileSync(join(dir, 'hush-identity-corpus-1.0.0.tar.gz'));
    const text = archive.toString('utf8');
    // No logs: the archive embeds corpus JSON only.
    assert.ok(!text.includes('console.log'), 'no log output embedded');
    assert.ok(!text.includes('RELEASE ARCHIVE FAIL'), 'no failure output embedded');
    // No real-credential markers: corpus is public test material, but the
    // archive must not embed diagnostics or PEM material.
    assert.ok(!text.includes('BEGIN PRIVATE KEY'), 'no PEM private key material');
    // Evidence digest covers every bundled corpus file.
    const evidence = JSON.parse(readFileSync(join(dir, 'release-evidence.json'), 'utf8'));
    assert.equal(evidence.contractVersion, '1.0.0');
    assert.ok(/^[0-9a-f]{64}$/.test(evidence.manifestDigest));
    assert.ok(evidence.files.length > 20, 'all corpus files listed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('collected corpus files match manifest integrity', () => {
  const files = collectCorpusFiles();
  const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  for (const entry of manifest.files) {
    assert.ok(files.includes(entry.path), `manifest file listed: ${entry.path}`);
  }
  for (const f of files) {
    if (f === 'README.md') continue;
    assert.ok(manifest.files.some((e) => e.path === f), `unexpected archive file: ${f}`);
  }
});
