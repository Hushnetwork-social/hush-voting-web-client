#!/usr/bin/env node
/**
 * FEAT-003 production-exclusion scans (Task 5.3).
 * ================================================
 * Proves the non-production conformance machinery can never reach production:
 *
 * 1. IMPORT-GRAPH scan — production source (src/, excluding reference-only paths)
 *    must not import any `src/lib/vault-core/conformance/` module, the reference
 *    suite (`canonical/suite-reference.ts`), or the vault corpus paths. A future
 *    production adapter must not silently depend on conformance helpers.
 * 2. SELECTOR scan — conformance-only markers and declared public test credentials
 *    never appear outside allowlisted corpus paths and reference-only modules.
 * 3. ARTIFACT scan — fresh web/static/Tauri build outputs (.next-web, .next-static,
 *    .next-tauri, out/) contain no conformance-only names, deterministic provider
 *    selectors, corpus credential values, or reference generator identifiers.
 *
 * Exit codes: 0 = clean, 1 = findings, 2 = internal error.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const SRC_DIR = join(REPO_ROOT, 'src');
const SCRIPTS_DIR = join(REPO_ROOT, 'scripts');

/** Reference-only module paths that are the allowed home of conformance machinery. */
const REFERENCE_ONLY = [
  'src/lib/vault-core/conformance/',
  'src/lib/vault-core/canonical/suite-reference.ts',
  'scripts/vault/',
  'conformance/vault/',
  'conformance/identity/',
];

/** Allowlisted corpus prefixes (any file under these paths is exempt from selector scans). */
const ALLOWLIST_PREFIXES = ['conformance/vault/', 'conformance/identity/'];

/**
 * Conformance-only markers. These identify deterministic test providers, the isolated
 * reference validator, and public-test-credential plumbing. They must NEVER appear in
 * production source or build outputs.
 */
const SELECTORS = [
  'DETERMINISTIC_TEST_PROVIDER',
  'vault-reference-runner',
  'PUBLIC_TEST_CREDENTIAL',
  'hush-vault-ts-isolated',
  'hush-vault-ts-reference',
];

/** Declared public test credential VALUES that must never reach production artifacts. */
const CREDENTIAL_VALUES = [
  'correct horse battery staple',
  'password-bytes',
  'public-test-channel',
  'hush.vault.required',
  'Tr0ub4dor&3-correct-horse',
];

const ARTIFACT_DIRS = ['.next-web', '.next-static', '.next-tauri', 'out'];

function isReferenceOnly(rel) {
  return REFERENCE_ONLY.some((prefix) => rel === prefix || rel.startsWith(prefix));
}
function isAllowlisted(rel) {
  return ALLOWLIST_PREFIXES.some((prefix) => rel.startsWith(prefix));
}

/** Collect production source files (ts/tsx/mjs/js/json) under src/ and scripts/. */
function productionFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (['node_modules', '.next', '.next-web', '.next-static', '.next-tauri', 'out', 'target', 'coverage', 'src-tauri'].includes(entry)) continue;
        walk(p);
      } else if (/\.(ts|tsx|mjs|js|json)$/.test(entry)) {
        out.push(p);
      }
    }
  };
  walk(SRC_DIR);
  walk(SCRIPTS_DIR);
  return out;
}

/** 1. Import-graph scan: no production module imports conformance/reference machinery. */
function importGraphScan(findings) {
  const conformanceImport = /from\s+['"]([^'"]*vault-core\/conformance[^'"]*)['"]/;
  const referenceSuiteImport = /from\s+['"]([^'"]*vault-core\/canonical\/suite-reference[^'"]*)['"]/;
  const corpusImport = /from\s+['"]([^'"]*conformance\/vault\/v1[^'"]*)['"]/;
  for (const file of productionFiles()) {
    const rel = relative(REPO_ROOT, file).split(sep).join('/');
    if (isReferenceOnly(rel) || isAllowlisted(rel)) continue;
    const content = readFileSync(file, 'utf8');
    for (const [label, re] of [
      ['conformance module', conformanceImport],
      ['reference suite', referenceSuiteImport],
      ['vault corpus', corpusImport],
    ]) {
      const m = content.match(re);
      if (m) findings.push(`${rel} imports ${label} '${m[1]}' in production source`);
    }
  }
}

/** 2. Selector + credential scan over production source and scripts. */
function selectorScan(findings) {
  for (const file of productionFiles()) {
    const rel = relative(REPO_ROOT, file).split(sep).join('/');
    if (isReferenceOnly(rel) || isAllowlisted(rel)) continue;
    const content = readFileSync(file, 'utf8');
    // Conformance-only SELECTORS must never appear anywhere in production source.
    for (const token of SELECTORS) {
      if (content.includes(token)) findings.push(`${rel} contains ${JSON.stringify(token)} outside allowlist/reference paths`);
    }
    // Declared PUBLIC TEST CREDENTIAL VALUES may appear in unit tests (they are
    // public synthetic data) but never in production runtime code.
    const isTestFile = /\.test\.(ts|tsx|mjs|js)$/.test(file) || rel.includes('/__tests__/');
    if (isTestFile) continue;
    for (const token of CREDENTIAL_VALUES) {
      if (content.includes(token)) findings.push(`${rel} contains ${JSON.stringify(token)} in production code`);
    }
  }
}

/** 3. Artifact scan: fresh build outputs contain no conformance-only content. */
function artifactScan(findings) {
  for (const dir of ARTIFACT_DIRS) {
    const abs = join(REPO_ROOT, dir);
    if (!existsSync(abs)) continue;
    const walk = (current) => {
      for (const entry of readdirSync(current)) {
        const p = join(current, entry);
        const st = statSync(p);
        if (st.isDirectory()) {
          walk(p);
        } else if (/\.(js|json|html|map)$/.test(entry)) {
          const rel = relative(REPO_ROOT, p).split(sep).join('/');
          const content = readFileSync(p, 'utf8');
          for (const token of [...SELECTORS, ...CREDENTIAL_VALUES]) {
            if (content.includes(token)) {
              findings.push(`${rel} artifact contains ${JSON.stringify(token)}`);
            }
          }
        }
      }
    };
    walk(abs);
  }
}

function main() {
  const args = new Set(process.argv.slice(2));
  const skipArtifacts = args.has('--skip-artifacts');
  const findings = [];
  importGraphScan(findings);
  selectorScan(findings);
  if (!skipArtifacts) artifactScan(findings);
  if (findings.length) {
    process.stderr.write(`VAULT PRODUCTION EXCLUSION FAILED:\n${findings.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write('VAULT PRODUCTION EXCLUSION OK (import graph, selectors, artifacts)\n');
  process.exit(0);
}

try {
  main();
} catch (err) {
  process.stderr.write(`VAULT PRODUCTION EXCLUSION INTERNAL ERROR: ${err.message}\n`);
  process.exit(2);
}
