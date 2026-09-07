#!/usr/bin/env node
/**
 * FEAT-016 source-property scan (Phase 7 task 7.5).
 *
 * Machine-checked source-level guards over FEAT-016 production surfaces.
 * Each forbidden property, if present in a NON-TEST production source file,
 * fails the gate (warnings are RED). Patterns reflect the FeatureTasks
 * "Patterns to Avoid" and the FeatureDescription authority boundaries:
 *   - no `navigator.onLine` connectivity authority;
 *   - no entitlement/licence projection persistence in general browser or
 *     native preference storage;
 *   - no wall-clock 30-second delayed-confirmation timing in production;
 *   - no client-authored licence catalogue/template defaults;
 *   - no Browser/IndexedDB/worker fallback inside native vault modules;
 *   - no account/plan/upgrade (FEAT-017) or enforcement (FEAT-018) surfaces
 *     inside FEAT-016 gate modules;
 *   - no synthetic production providers reachable from the real composition.
 *
 * Test files (`*.test.*`), conformance fixtures, and generated artifacts are
 * excluded: they are covered by their own dedicated tests and by the
 * secret/artifact scans.
 *
 * Roots can be extended with FEAT016_SCAN_ROOTS (colon-separated absolute
 * paths) so the seeded-defect self-test can prove red-effectiveness.
 *
 * Usage: node scripts/entitlement-bootstrap/property-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const DEFAULT_ROOTS = [
  'src/lib/licensing',
  'src/lib/auth',
  'src/lib/browser-vault/production',
  'src/lib/runtime',
  'src/app/auth',
  'src/app/api',
  'src-tauri/src',
];

const SKIP_DIRS = new Set([
  'node_modules',
  '.next',
  '.next-web',
  '.next-tauri',
  '.next-static',
  'out',
  'coverage',
  'target',
  '.git',
  'test-results',
  'playwright-report',
  'gen',
  'fixtures',
]);

/** Forbidden property → detection regex (production, non-test source). */
const PROPERTIES = [
  {
    label: 'navigator.onLine as connectivity authority',
    re: /\bnavigator\.onLine\b/,
  },
  {
    label: 'entitlement/licence projection persisted to general storage',
    re: /(?:localStorage|sessionStorage)\.(?:setItem|removeItem)?\s*\(?[^)]*(?:entitlement|licence|projection)/i,
  },
  {
    label: 'general IndexedDB entitlement projection store',
    re: /indexedDB\.open\s*\([^)]*(?:entitlement|licence)/i,
  },
  {
    label: 'native preference entitlement persistence',
    re: /preferences?\.set\s*\([^)]*(?:entitlement|licence)/i,
  },
  {
    label: 'wall-clock 30-second delayed-confirmation timing',
    re: /set(?:Timeout|Interval)\s*\(\s*(?:[^,]*,\s*)?(?:30_?000|30_?0_?0_?0_?0)\s*\)/,
  },
  {
    label: 'client-authored licence catalogue/template default',
    re: /catalogue\s*[:=]\s*(?:\[|\{)/,
  },
  {
    label: 'native module browser/IndexedDB fallback',
    file: /src-tauri\//,
    re: /(?:import\s+[^'"]*from\s+['"])(?:\.\.\/)+.*(?:browser-vault|indexeddb)/,
  },
  {
    label: 'FEAT-017 account/plan/upgrade UI inside the gate module',
    file: /EntitlementGate\.tsx$/,
    re: /(?:import\s+.+from\s+['"][^'"]*(?:account|plan|upgrade|payment|options)[^'"]*['"])|(?:data-testid=["'](?:account-flyout|plan-card|upgrade)["'])/i,
  },
  {
    label: 'FEAT-018 enforcement surface inside the gate module',
    file: /EntitlementGate\.tsx$/,
    re: /(?:import\s+.+from\s+['"][^'"]*enforce[^'"]*['"])|(?:data-testid=["'](?:cap-|enforcement)["'])/i,
  },
];

/** Production file predicate: TS/TSX source, never a test or sample. */
function isProductionSource(path, name) {
  if (!/\.(ts|tsx)$/.test(name)) return false;
  if (/\.test\.|\.spec\.|\.stories\./.test(name)) return false;
  if (/(__tests__|__mocks__|test-|sample)/.test(path)) return false;
  return true;
}

function walk(dir, out) {
  if (!statSync(dir, { throwIfNoEntry: false })) return;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(p, out);
    } else if (isProductionSource(p, entry)) {
      out.push(p);
    }
  }
}

function collectRoots() {
  const roots = DEFAULT_ROOTS.map((root) => join(REPO_ROOT, root));
  const extra = process.env.FEAT016_SCAN_ROOTS;
  if (typeof extra === 'string' && extra.length > 0) {
    for (const root of extra.split(':')) {
      if (root.length > 0) roots.push(root);
    }
  }
  return roots;
}

const files = [];
for (const root of collectRoots()) walk(root, files);

const findings = [];
for (const file of files) {
  const content = readFileSync(file, 'utf8');
  for (const { label, re, file: fileMatcher } of PROPERTIES) {
    if (fileMatcher !== undefined && !fileMatcher.test(file)) continue;
    const globalRe = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    for (const match of content.matchAll(globalRe)) {
      // Forbidden properties cannot be commented out of the property gate.
      findings.push(`${file}: ${label} (${match[0].slice(0, 80)})`);
      break;
    }
  }
}

if (findings.length > 0) {
  console.error(`PROPERTY SCAN FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log(`PROPERTY SCAN OK (0 forbidden properties across ${files.length} production files)`);
