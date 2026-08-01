#!/usr/bin/env node
/**
 * Deterministic corpus manifest generator + check mode
 * =====================================================
 * Generates conformance/identity/v1/manifest.json from the exact corpus
 * formatting bytes (UTF-8 no BOM, LF endings, lexicographically stable object
 * keys, two-space indentation, one final newline).
 *
 * Behavior:
 *   - walks schemas/, producers/, vectors/, lookup/ plus inventory.json;
 *   - lists every file in stable sorted order with relative path, byte length,
 *     and SHA-256 digest;
 *   - fails when a file is missing, unlisted data files exist, or --check
 *     finds drift vs the committed manifest.
 *
 * Exit codes: 0 = ok (or check passed), 1 = integrity failure.
 * Usage:
 *   node scripts/generate-manifest.mjs            # write manifest.json
 *   node scripts/generate-manifest.mjs --check    # verify committed manifest
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const MANIFEST_PATH = join(ROOT, 'manifest.json');
const DATA_DIRS = ['schemas', 'producers', 'vectors', 'lookup'];
const ROOT_DATA_FILES = ['inventory.json'];

export function collectDataFiles() {
  const files = [];
  for (const dir of DATA_DIRS) {
    const dirPath = join(ROOT, dir);
    if (!existsSync(dirPath)) throw new Error(`missing corpus directory: ${dir}`);
    for (const entry of readdirSync(dirPath).sort()) {
      const p = join(dirPath, entry);
      if (!statSync(p).isFile()) continue;
      if (!entry.endsWith('.json')) continue;
      files.push(relative(ROOT, p).split(sep).join('/'));
    }
  }
  for (const f of ROOT_DATA_FILES) {
    if (!existsSync(join(ROOT, f))) throw new Error(`missing corpus file: ${f}`);
    files.push(f);
  }
  return files.sort();
}

export function digest(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function stableStringify(obj) {
  const sort = (o) => {
    if (Array.isArray(o)) return o.map(sort);
    if (o && typeof o === 'object') {
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, sort(o[k])]));
    }
    return o;
  };
  return JSON.stringify(sort(obj), null, 2) + '\n';
}

export function buildManifest() {
  const files = collectDataFiles().map((p) => {
    const full = join(ROOT, p);
    return { path: p, sha256: digest(full), bytes: statSync(full).size };
  });
  return {
    schemaVersion: '1.0.0',
    contractVersion: '1.0.0',
    files,
  };
}

function checkMode() {
  const expected = buildManifest();
  if (!existsSync(MANIFEST_PATH)) {
    console.error('CHECK FAILED: manifest.json is missing (run without --check to generate)');
    process.exitCode = 1;
    return;
  }
  const actualRaw = readFileSync(MANIFEST_PATH, 'utf8');
  const expectedRaw = stableStringify(expected);
  if (actualRaw !== expectedRaw) {
    console.error('CHECK FAILED: manifest.json drifted from corpus bytes');
    console.error('Run `node scripts/generate-manifest.mjs` and commit the regenerated manifest.');
    process.exitCode = 1;
    return;
  }
  console.log(`CHECK OK: ${expected.files.length} files listed, digests match`);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  if (process.argv.includes('--check')) {
    checkMode();
  } else {
    const manifest = buildManifest();
    writeFileSync(MANIFEST_PATH, stableStringify(manifest), { encoding: 'utf8', flag: 'w' });
    console.log(`wrote manifest.json (${manifest.files.length} files)`);
  }
}
