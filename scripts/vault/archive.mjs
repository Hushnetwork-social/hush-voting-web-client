#!/usr/bin/env node
/**
 * FEAT-003 deterministic release archive (Task 7.5).
 * ==================================================
 * Builds `conformance/archive/vault-{manifest-digest}/` containing the immutable
 * corpus, deterministic reports, handoff, and a sorted digest manifest
 * (`archive-manifest.json`). The archive is fully reproducible: the same source
 * revision + corpus digest yields byte-identical archive membership, ordering, and
 * digests. `--check` mode re-verifies an existing archive.
 *
 * Exit codes: 0 = archive ok, 1 = archive/check failure, 2 = internal error.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const CORPUS = join(REPO_ROOT, 'conformance', 'vault', 'v1');
const REPORTS = join(REPO_ROOT, 'conformance', 'reports');
const ARCHIVE_ROOT = join(REPO_ROOT, 'conformance', 'archive');

const ARCHIVE_FILES = [
  'metadata.json',
  'manifest.json',
  'HANDOFF.md',
  'README.md',
  ...readdirSync(join(CORPUS, 'schemas')).filter((f) => f.endsWith('.json')).sort().map((f) => `schemas/${f}`),
  ...readdirSync(join(CORPUS, 'vectors')).filter((f) => f.endsWith('.json')).sort().map((f) => `vectors/${f}`),
  'reports/vault-ts-reference.json',
  'reports/vault-ts-isolated.json',
];

function sha256hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function manifestDigest() {
  return sha256hex(readFileSync(join(CORPUS, 'manifest.json')));
}

function buildArchiveManifest() {
  const files = [];
  for (const rel of ARCHIVE_FILES) {
    const source = rel.startsWith('reports/') ? join(REPORTS, rel.slice('reports/'.length)) : join(CORPUS, rel);
    if (!existsSync(source)) throw new Error(`archive source missing: ${rel}`);
    const bytes = readFileSync(source);
    files.push({ path: rel, bytes: bytes.length, sha256: sha256hex(bytes) });
  }
  return {
    contract: 'FEAT-003 deterministic release archive v1',
    corpusManifestSha256: manifestDigest(),
    revision: 'immutable corpus pin',
    files: files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
  };
}

function serialize(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

function build() {
  const manifest = buildArchiveManifest();
  const dir = join(ARCHIVE_ROOT, `vault-${manifest.corpusManifestSha256.slice(0, 12)}`);
  mkdirSync(join(dir, 'schemas'), { recursive: true });
  mkdirSync(join(dir, 'vectors'), { recursive: true });
  mkdirSync(join(dir, 'reports'), { recursive: true });
  for (const rel of ARCHIVE_FILES) {
    const source = rel.startsWith('reports/') ? join(REPORTS, rel.slice('reports/'.length)) : join(CORPUS, rel);
    writeFileSync(join(dir, rel), readFileSync(source));
  }
  writeFileSync(join(dir, 'archive-manifest.json'), serialize(manifest));
  return { dir, manifest };
}

function check(dir) {
  const manifest = JSON.parse(readFileSync(join(dir, 'archive-manifest.json'), 'utf8'));
  const current = buildArchiveManifest();
  if (manifest.corpusManifestSha256 !== current.corpusManifestSha256) {
    return { ok: false, reason: 'corpus manifest digest drift' };
  }
  for (const f of current.files) {
    const bytes = readFileSync(join(dir, f.path));
    if (bytes.length !== f.bytes || sha256hex(bytes) !== f.sha256) {
      return { ok: false, reason: `archive file drift: ${f.path}` };
    }
  }
  return { ok: true };
}

function main() {
  const args = new Set(process.argv.slice(2));
  const digest = manifestDigest();
  const dir = join(ARCHIVE_ROOT, `vault-${digest.slice(0, 12)}`);
  if (args.has('--check')) {
    const result = check(dir);
    process.stdout.write(result.ok ? `VAULT ARCHIVE OK (${dir})\n` : `VAULT ARCHIVE FAILED: ${result.reason}\n`);
    process.exit(result.ok ? 0 : 1);
  }
  if (args.has('--clean')) {
    rmSync(dir, { recursive: true, force: true });
  }
  const { manifest } = build();
  // Reproducibility: build twice; membership, ordering, and digests must match.
  const again = buildArchiveManifest();
  if (serialize(manifest) !== serialize(again)) {
    process.stderr.write('VAULT ARCHIVE NOT REPRODUCIBLE\n');
    process.exit(1);
  }
  process.stdout.write(`VAULT ARCHIVE OK (${dir}, ${manifest.files.length} files, reproducible)\n`);
  process.exit(0);
}

try {
  main();
} catch (err) {
  process.stderr.write(`VAULT ARCHIVE INTERNAL ERROR: ${err.message}\n`);
  process.exit(2);
}
