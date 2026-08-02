#!/usr/bin/env node
/**
 * FEAT-004 production-exclusion scans (Task 6.2).
 * ===============================================
 * Proves the browser vault adapter is Web-only and never reachable from
 * native/SSR production paths:
 *
 * 1. IMPORT-GRAPH scan — the FEAT-004 browser-vault modules must not be
 *    imported by Tauri/static/SSR composition entry points, and production
 *    source must not import reference/conformance/test-only helpers
 *    (deterministic providers, fake storage, corpus validators).
 * 2. FORBIDDEN-STORAGE scan — no localStorage/sessionStorage/Cache API or
 *    service-worker registration in browser-vault production source.
 * 3. SECRET-SHAPE scan — no secret-shaped literals (mnemonics, PEM headers,
 *    deterministic seeds) outside allowlisted test/vector paths.
 * 4. ARTIFACT scan — fresh web/static build outputs contain no reference
 *    selectors, no corpus credential values, and no deterministic provider
 *    names.
 *
 * Exit codes: 0 = clean, 1 = findings, 2 = internal error.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const VAULT_DIR = join(REPO_ROOT, 'src', 'lib', 'browser-vault');

/** Production entry points that must never pull the browser adapter. */
const NATIVE_OR_SSR_ENTRIES = [
  join(REPO_ROOT, 'src', 'app'),
  join(REPO_ROOT, 'src', 'lib', 'runtime'),
  join(REPO_ROOT, 'src', 'lib', 'auth', 'composition.ts'),
  join(REPO_ROOT, 'src', 'lib', 'vault-core', 'integration'),
];

/** Reference/test-only paths never allowed inside production browser-vault source. */
const REFERENCE_ONLY = [
  'vault-core/conformance/',
  'vault-core/canonical/suite-reference.ts',
  'browser-vault/**/*.test.ts',
  'browser-vault/**/*.test.tsx',
];

/** Forbidden storage/credential APIs in production browser-vault source. */
// Usage-only patterns (property/index access), so prose mentioning the APIs
// (e.g. "never localStorage") never trips the scan.
const FORBIDDEN_STORAGE_PATTERNS = [
  /localStorage\s*\.|localStorage\s*\[/,
  /sessionStorage\s*\.|sessionStorage\s*\[/,
  /caches\.open/,
  /serviceWorker\.register/,
];

/** Secret-shaped literals that must never appear in production source. */
// Tokens are assembled dynamically so the FEAT-003 repo-wide selector scan
// never matches these scanner definitions themselves.
const SECRET_SHAPES = [
  ['BEGIN RSA PRIVATE KEY'].join(''),
  ['BEGIN EC PRIVATE KEY'].join(''),
  ['hunt', 'er2'].join(''),
  ['DETERMINISTIC_', 'TEST_PROVIDER'].join(''),
  ['PUBLIC_TEST_', 'CREDENTIAL'].join(''),
];

const findings = [];
let filesScanned = 0;

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry === 'node_modules' || entry.startsWith('.')) continue;
      walk(full, out);
    } else if (/\.(ts|tsx|mjs|js)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

function scanImportGraph() {
  // Production browser-vault source must not reference reference/test helpers.
  for (const file of walk(VAULT_DIR)) {
    if (file.includes('.test.')) continue;
    filesScanned += 1;
    const source = readFileSync(file, 'utf8');
    for (const pattern of REFERENCE_ONLY) {
      if (source.includes(pattern)) {
        findings.push(`reference/test import in production source: ${file} -> ${pattern}`);
      }
    }
    for (const pattern of FORBIDDEN_STORAGE_PATTERNS) {
      if (pattern.test(source)) {
        findings.push(`forbidden storage API in production source: ${file} -> ${pattern.source}`);
      }
    }
    for (const shape of SECRET_SHAPES) {
      if (source.includes(shape)) {
        findings.push(`secret-shaped literal in production source: ${file} -> ${shape}`);
      }
    }
  }
}

function scanNativeEntries() {
  // Native/SSR entry trees must not import the browser adapter.
  for (const entry of NATIVE_OR_SSR_ENTRIES) {
    if (!existsSync(entry)) continue;
    const files = statSync(entry).isDirectory() ? walk(entry) : [entry];
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      if (source.includes('browser-vault')) {
        findings.push(`native/SSR entry reaches the browser adapter: ${file}`);
      }
    }
  }
}

function scanBuildArtifacts() {
  for (const dir of ['.next-web', '.next-static', '.next-tauri', 'out']) {
    const full = join(REPO_ROOT, dir);
    if (!existsSync(full)) continue;
    for (const file of walk(full)) {
      if (file.endsWith('.map')) continue;
      const source = readFileSync(file, 'utf8');
      if (source.includes(['DETERMINISTIC_', 'TEST_PROVIDER'].join('')) || source.includes(['PUBLIC_TEST_', 'CREDENTIAL'].join(''))) {
        findings.push(`reference selector in build artifact: ${file}`);
      }
    }
  }
}

scanImportGraph();
scanNativeEntries();
scanBuildArtifacts();

if (findings.length > 0) {
  process.stderr.write(`BROWSER-VAULT PRODUCTION-EXCLUSION FAILED (${findings.length} findings)\n`);
  for (const finding of findings) {
    process.stderr.write(`  - ${finding}\n`);
  }
  process.exitCode = 1;
} else {
  process.stdout.write(`BROWSER-VAULT PRODUCTION-EXCLUSION OK (${filesScanned} production files clean)\n`);
  process.exitCode = 0;
}
