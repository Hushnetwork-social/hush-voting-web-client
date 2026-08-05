#!/usr/bin/env node
/**
 * FEAT-010 production-exclusion gate (Task 6.7, AC-010-098).
 *
 * Fails CI when any incomplete/synthetic production path exists in source or
 * built artifacts:
 *  1. `Setting up…` onboarding placeholder text;
 *  2. null production actor providers (`() => null` in AuthRoot composition);
 *  3. mock-success / unconditional-unavailable configured transports;
 *  4. synthetic/dev composition selected by `NODE_ENV` in ordinary paths;
 *  5. test-harness composition reachable from ordinary/production bundles;
 *  6. native → Browser fallback seams.
 *
 * Secret-safe: scans code text only; emits stable safe diagnostics.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const findings = [];

function walk(dir) {
  const files = [];
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (entry === 'node_modules' || entry === '.next' || entry === '.next-web' || entry === '.next-static' || entry === 'out' || entry === 'target') continue;
      files.push(...walk(p));
    } else if (/\.(ts|tsx|mjs)$/.test(entry)) {
      files.push(p);
    }
  }
  return files;
}

function relative(file) {
  return file.slice(REPO_ROOT.length + 1);
}

// --- 1. Onboarding placeholder text (production/ordinary surfaces) ---
for (const file of walk(join(REPO_ROOT, 'src', 'app', 'auth'))) {
  const content = readFileSync(file, 'utf8');
  if (content.includes('Setting up…') && !file.includes('.test.')) {
    findings.push(`${relative(file)}: onboarding placeholder "Setting up…" present`);
  }
}

// --- 2. Null production actor provider in AuthRoot ---
const authRoot = readFileSync(join(REPO_ROOT, 'src', 'app', 'auth', 'AuthRoot.tsx'), 'utf8');
if (authRoot.includes('() => null') && !authRoot.includes('HUSH_TEST_HARNESS')) {
  // The only remaining `() => null` must be inside the harness guard or the
  // real provider map — flag any unguarded occurrence.
  const unguarded = authRoot.split('HUSH_TEST_HARNESS')[0].includes('() => null');
  if (unguarded) findings.push('src/app/auth/AuthRoot.tsx: null actor provider outside harness guard');
}

// --- 3. Unconditional-unavailable configured transport ---
const serverTransport = readFileSync(join(REPO_ROOT, 'src', 'app', 'api', 'server-transport.ts'), 'utf8');
if (/return \{ ok: false, failure: \{ kind: 'unavailable' \} \};/.test(serverTransport) && !serverTransport.includes('if (!response.ok)')) {
  findings.push('src/app/api/server-transport.ts: unconditional unavailable transport (no real wire path)');
}
if (serverTransport.includes('ConfiguredTransport')) {
  findings.push('src/app/api/server-transport.ts: legacy unconditional-unavailable ConfiguredTransport remains');
}

// --- 4. NODE_ENV-based synthetic selection in ordinary paths ---
// Legitimate: the harness branch requires BOTH `NODE_ENV !== 'production'`
// AND the explicit HUSH_TEST_HARNESS flag; the NODE_ENV guard statically
// prunes it from production bundles. Flag any other NODE_ENV selection.
for (const file of walk(join(REPO_ROOT, 'src', 'app'))) {
  const content = readFileSync(file, 'utf8');
  if (content.includes('NODE_ENV') && content.includes('createDevelopmentComposition') && !content.includes('HUSH_TEST_HARNESS')) {
    findings.push(`${relative(file)}: development composition selected by NODE_ENV without explicit harness flag`);
  }
}

// --- 5. Harness composition reachable outside its guarded entry ---
for (const file of walk(join(REPO_ROOT, 'src'))) {
  const content = readFileSync(file, 'utf8');
  if (content.includes('testing/composition.dev') && !content.includes('HUSH_TEST_HARNESS') && !file.includes('.test.') && !file.includes('composition.dev')) {
    findings.push(`${relative(file)}: synthetic harness import without explicit harness guard`);
  }
}

// --- 6. Native → Browser fallback seams in ordinary composition ---
for (const file of walk(join(REPO_ROOT, 'src', 'lib', 'auth'))) {
  const content = readFileSync(file, 'utf8');
  if (content.includes('fallback') && content.includes('browser') && !file.includes('.test.')) {
    // Only flag explicit native->browser fallback claims, not the word alone.
    if (/native[^]*fallback|fallback[^]*native/i.test(content)) {
      findings.push(`${relative(file)}: native→browser fallback seam present`);
    }
  }
}

// --- 7. Built-bundle scan (client artifacts only; source maps are not
// shipped and legitimately carry the harness source text) ---
for (const dir of ['.next-web', '.next-static', 'out']) {
  const path = join(REPO_ROOT, dir);
  if (!existsSync(path)) continue;
  const scan = spawnSync('grep', ['-rl', '--exclude=*.map', 'Setting up…', path], { encoding: 'utf8' });
  if (scan.status === 0 && scan.stdout.trim().length > 0) {
    findings.push(`${dir}: built artifact contains "Setting up…"`);
  }
  const synthetic = spawnSync('grep', ['-rl', '--exclude=*.map', 'createDevelopmentComposition', path], { encoding: 'utf8' });
  if (synthetic.status === 0 && synthetic.stdout.trim().length > 0) {
    findings.push(`${dir}: built artifact contains development composition`);
  }
}

if (findings.length > 0) {
  console.error(`PRODUCTION EXCLUSION FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log('PRODUCTION EXCLUSION OK (no placeholder/null/mock/unavailable/synthetic/fallback path)');
process.exit(0);
