#!/usr/bin/env node
/**
 * Deterministic vault corpus manifest generator + check mode.
 * ============================================================
 * Generates conformance/vault/v1/manifest.json from the exact corpus formatting bytes
 * (UTF-8 no BOM, LF endings, stable sorted order).
 *
 * Data files covered: schemas/**\/*.json and metadata.json (stable validation inputs).
 * Tooling (scripts/, tests/, README.md) is tracked by git, not the manifest — mirroring
 * conformance/identity/v1 conventions.
 *
 * Exit codes: 0 = ok (or check passed), 1 = integrity failure.
 * Usage:
 *   node conformance/vault/v1/scripts/generate-manifest.mjs            # write manifest
 *   node conformance/vault/v1/scripts/generate-manifest.mjs --check    # verify committed
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const MANIFEST_PATH = join(ROOT, 'manifest.json');
const DATA_DIRS = ['schemas', 'vectors'];
const ROOT_DATA_FILES = ['metadata.json'];

/** Collect every manifest-tracked data file in stable sorted order. */
export function collectDataFiles(root = ROOT) {
  const files = [];
  for (const dir of DATA_DIRS) {
    const dirPath = join(root, dir);
    if (!existsSync(dirPath)) throw new Error(`missing corpus directory: ${dir}`);
    for (const entry of readdirSync(dirPath).sort()) {
      const p = join(dirPath, entry);
      if (!statSync(p).isFile()) continue;
      if (!entry.endsWith('.json')) continue;
      files.push(relative(root, p).split(sep).join('/'));
    }
  }
  for (const f of ROOT_DATA_FILES) {
    if (!existsSync(join(root, f))) throw new Error(`missing corpus file: ${f}`);
    files.push(f);
  }
  return files.sort();
}

/** SHA-256 digest of exact file bytes. */
export function digest(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** Generate the manifest object deterministically. */
export function generateManifest(root = ROOT) {
  const files = collectDataFiles(root).map((p) => {
    const abs = join(root, p);
    const bytes = statSync(abs).size;
    const sha256 = digest(abs);
    return { path: p, bytes, sha256 };
  });
  return { contractVersion: '1.0.0', corpusVersion: '1.0.0', files };
}

/** Serialize exactly as committed (sorted keys, 2-space indent, final newline, LF). */
export function serializeManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

export function verifyManifestAgainstDisk(root = ROOT) {
  const committed = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  const current = generateManifest(root);
  if (serializeManifest(committed) !== serializeManifest(current)) {
    const expected = new Set(committed.files.map((f) => f.path));
    const actual = new Set(current.files.map((f) => f.path));
    const added = [...actual].filter((p) => !expected.has(p));
    const removed = [...expected].filter((p) => !actual.has(p));
    const changed = current.files.filter((c) => {
      const prev = committed.files.find((f) => f.path === c.path);
      return prev && (prev.bytes !== c.bytes || prev.sha256 !== c.sha256);
    });
    throw new Error(
      `manifest drift: added=${JSON.stringify(added)} removed=${JSON.stringify(removed)} changed=${JSON.stringify(
        changed.map((c) => c.path)
      )}`
    );
  }
  return current;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--check')) {
    verifyManifestAgainstDisk();
    process.stdout.write('VAULT MANIFEST OK\n');
    process.exit(0);
  }
  if (args.includes('--print')) {
    process.stdout.write(serializeManifest(generateManifest()));
    process.exit(0);
  }
  writeFileSync(MANIFEST_PATH, serializeManifest(generateManifest()));
  process.stdout.write('VAULT MANIFEST GENERATED\n');
}

main();
