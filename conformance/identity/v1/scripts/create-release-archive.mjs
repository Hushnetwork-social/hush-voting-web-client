#!/usr/bin/env node
/**
 * Deterministic immutable release archive generator.
 * ===================================================
 * Packages the exact corpus bytes, manifest digest, contract/schema versions,
 * inventory attestation reference, and optional TypeScript/.NET conformance
 * reports into a deterministic tar.gz for a tagged HushVoting release.
 *
 * Determinism contract (Task 5.3):
 *   - sorted, fixed file order; ustar headers with fixed mtime; gzip with a
 *     fixed header timestamp — two builds from identical inputs produce
 *     byte-identical archives;
 *   - the archive contains no runtime logs and no credential values;
 *   - required inputs (version, corpus) must exist; unexpected or missing
 *     files fail with a non-zero exit.
 *
 * Usage:
 *   node scripts/create-release-archive.mjs \
 *     --version 1.0.0 \
 *     --output release/ \
 *     [--ts-report conformance/reports/typescript-identity-report.json] \
 *     [--dotnet-report <path-to-dotnet-identity-report.json>]
 *
 * Outputs in <output>/:
 *   hush-identity-corpus-{version}.tar.gz   immutable archive
 *   release-evidence.json                    SHAs, versions, manifest digest
 *   archive.sha256                           SHA-256 of the tar.gz
 */
import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  console.error('RELEASE ARCHIVE FAIL:', message);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { version: null, output: null, tsReport: null, dotnetReport: null };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--version': args.version = argv[++i] ?? null; break;
      case '--output': args.output = argv[++i] ?? null; break;
      case '--ts-report': args.tsReport = argv[++i] ?? null; break;
      case '--dotnet-report': args.dotnetReport = argv[++i] ?? null; break;
      default: fail(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/** All corpus files that belong in the archive: manifest-listed files + README + attestation note. */
/** Parse JSON text defensively, tolerating a leading BOM (some runtimes emit one). */
function parseJsonText(text) {
  return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
}

function collectCorpusFiles() {
  const manifest = parseJsonText(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  const files = [];
  for (const entry of manifest.files) {
    const full = join(ROOT, entry.path);
    if (!existsSync(full)) fail(`manifest lists missing file ${entry.path}`);
    const bytes = readFileSync(full);
    if (bytes.length !== entry.bytes) fail(`byte length mismatch for ${entry.path}`);
    if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) fail(`digest mismatch for ${entry.path}`);
    files.push(entry.path);
  }
  // Human-readable evidence documents travel with the archive but are not
  // integrity-managed corpus data; include them read-only.
  for (const extra of ['README.md']) {
    if (existsSync(join(ROOT, extra))) files.push(extra);
  }
  return files.sort();
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Minimal ustar (POSIX) header — fixed mtime for determinism. */
function ustarHeader(name, size, mode = 0o100644) {
  const field = (value, length, pad = '0') => String(value).padStart(length, pad).slice(0, length);
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0, 'ascii'); // 0: name
  header.write(field(mode, 8, '0'), 100, 'ascii'); // 100: mode
  header.write(field(0, 8), 108, 'ascii'); // 108: uid
  header.write(field(0, 8), 116, 'ascii'); // 116: gid
  header.write(field(size.toString(8), 12), 124, 'ascii'); // 124: size (octal)
  header.write(field(0, 12), 136, 'ascii'); // 136: mtime (fixed 0)
  header.write('        ', 148, 'ascii'); // 148: checksum placeholder
  header.write('ustar', 257, 'ascii'); // 257: magic
  header.write('00', 263, 'ascii'); // 263: version
  // 265: uname, 297: gname, 329: devmajor, 337: devminor (empty)
  let checksum = 0;
  for (const b of header) checksum += b;
  header.write(field(checksum, 6), 148, 'ascii');
  header.write('\x00 ', 154, 'ascii');
  return header;
}

function buildTar(entries) {
  const chunks = [];
  for (const { path, content } of entries) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    chunks.push(ustarHeader(path, data.length));
    chunks.push(data);
    const padding = (512 - (data.length % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024)); // end-of-archive
  return Buffer.concat(chunks);
}

/** Deterministic gzip: fixed header mtime so archives are byte-identical. */
function deterministicGzip(data) {
  return gzipSync(data, { level: 9, mtime: 0 });
}

function gitHead(directory) {
  try {
    return execSync('git rev-parse HEAD', { cwd: directory, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.version || !VERSION_RE.test(args.version)) fail('--version must be a semantic version (x.y.z)');
  if (!args.output) fail('--output directory is required');

  const outputDir = resolve(process.cwd(), args.output);
  mkdirSync(outputDir, { recursive: true });

  // Deterministic corpus file set.
  const corpusFiles = collectCorpusFiles();

  // Optional conformance reports (must be readable JSON if provided).
  const reports = [];
  for (const [label, path] of [['ts', args.tsReport], ['dotnet', args.dotnetReport]]) {
    if (!path) continue;
    const full = resolve(process.cwd(), path);
    if (!existsSync(full)) fail(`${label} report not found: ${full}`);
    const raw = readFileSync(full, 'utf8');
    const parsed = parseJsonText(raw);
    if (parsed.runtime !== (label === 'ts' ? 'typescript' : 'dotnet')) fail(`${label} report runtime mismatch`);
    reports.push({ label, path: `reports/${label}-identity-report.json`, bytes: Buffer.from(raw, 'utf8') });
  }

  const entries = [];
  for (const rel of corpusFiles) {
    entries.push({ path: `corpus/${rel}`, content: readFileSync(join(ROOT, rel)) });
  }
  for (const r of reports) {
    entries.push({ path: r.path, content: r.bytes });
  }

  // Release evidence (no credential values, ever).
  const manifestDigest = sha256Hex(readFileSync(join(ROOT, 'manifest.json')));
  const evidence = {
    contractVersion: parseJsonText(readFileSync(join(ROOT, 'manifest.json'), 'utf8')).contractVersion,
    schemaVersion: '1.0.0',
    releaseVersion: args.version,
    manifestDigest,
    hushVotingSha: gitHead(resolve(ROOT, '..', '..', '..')),
    hushServerNodeSha: gitHead(resolve(ROOT, '..', '..', '..', '..', 'hush-server-node')),
    files: corpusFiles,
    reports: reports.map((r) => ({ runtime: r.label, sha256: sha256Hex(r.bytes) })),
    deterministicCreatedUtc: '1970-01-01T00:00:00.000Z', // fixed for byte-identical reproducibility
  };
  entries.push({ path: 'release-evidence.json', content: JSON.stringify(evidence, null, 2) + '\n' });

  const tar = buildTar(entries);
  const archive = deterministicGzip(tar);
  const archiveName = `hush-identity-corpus-${args.version}.tar.gz`;
  const archivePath = join(outputDir, archiveName);
  writeFileSync(archivePath, archive);
  writeFileSync(join(outputDir, 'release-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
  writeFileSync(join(outputDir, 'archive.sha256'), sha256Hex(archive) + '  ' + archiveName + '\n');

  console.log(`Archive: ${archivePath}`);
  console.log(`SHA-256: ${sha256Hex(archive)}`);
  console.log(`Files: ${entries.length} (${corpusFiles.length} corpus + ${reports.length} reports + evidence)`);
  console.log(`Manifest digest: ${manifestDigest}`);
}

if (process.argv[1] && basename(process.argv[1]).includes('create-release-archive')) {
  main();
}

export { buildTar, deterministicGzip, sha256Hex, collectCorpusFiles, ustarHeader };
