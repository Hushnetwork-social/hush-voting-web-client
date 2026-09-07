#!/usr/bin/env node
/**
 * FEAT-017 source-property scan (Phase 6 task 6.5).
 *
 * Machine-checked source-level guards over FEAT-017 production surfaces.
 * Each forbidden property, if present in a NON-TEST production source file,
 * fails the gate (warnings are RED). Patterns reflect the FeatureTasks
 * "Patterns to Avoid" and the FEAT-017 authority boundaries:
 *   - no second entitlement store / projection persistence / remembered
 *     current plan;
 *   - no client catalogue/rank table and no client-authored plan defaults;
 *   - no page-owned polling loop, no page-owned signer, no generic signing
 *     request, and no second pending journal;
 *   - no raw transaction/template/UUID bytes in React/UI state;
 *   - no new UUID/timestamp/payload/signature on Retry;
 *   - no licence/plan/identity/transaction values in URL/history;
 *   - no actionable Enterprise / payment / renewal / downgrade / cancel UI;
 *   - no native Browser fallback inside native vault modules;
 *   - no FEAT-018 client-side authorization import into FEAT-017 surfaces.
 *
 * Test files, conformance fixtures and generated artifacts are excluded
 * (covered by secret/artifact scans and their own tests). Roots can be
 * extended with FEAT017_SCAN_ROOTS (colon-separated absolute paths) so the
 * seeded-defect self-test can prove red-effectiveness.
 *
 * Usage: node scripts/licence-upgrade/property-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const DEFAULT_ROOTS = [
  'src/lib/licensing',
  'src/lib/browser-vault/production',
  'src/lib/auth/web',
  'src/app/auth/licence',
  'src-tauri/src',
];

/** FEAT-017-affected files outside the narrow licence module. */
const EXTRA_FILES = [
  'src/app/auth/AuthRoot.tsx',
  'src/app/auth/AuthenticatedUserMenu.tsx',
  'src/app/auth/AuthenticatedLicenceRoot.tsx',
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
    label: 'second entitlement store / localStorage licence state',
    re: /(?:localStorage|sessionStorage)\.(?:setItem|getItem)?\s*\(?[^)]*(?:licence|entitlement|plan)/i,
  },
  {
    label: 'general IndexedDB licence state store (non-journal)',
    re: /indexedDB\.open\s*\([^)]*(?:licence|entitlement|plan)/i,
  },
  {
    label: 'client-authored licence catalogue / plan table',
    re: /(?:catalogue|planTable|planRank|rankTable)\s*[:=]\s*(?:\[|\{)/,
  },
  {
    label: 'page-owned polling loop (setInterval/setTimeout cadence) in UI',
    re: /set(?:Interval|Timeout)\s*\(\s*(?:[^,]*,\s*)?3000\s*\)/,
  },
  {
    label: 'page-owned generic signer / arbitrary signing request (page/UI)',
    file: /src\/app\/auth/,
    re: /(?:requestSign|signArbitrary|signMessage|signingRequest)\s*\(|import\s+[^;]*\b(?:signMessage|Signer)\b/i,
  },
  {
    label: 'page code imports raw signing capability (lib/auth web/react only)',
    file: /src\/lib\/auth/,
    re: /import\s+[^;]*\b(?:signMessage|SigningKey|privateKey)\b/i,
  },
  {
    label: 'raw signed transaction/template bytes in UI state',
    re: /setState\s*\([^)]*(?:transaction|signed|template)/i,
  },
  {
    label: 'retry mints a new transaction identity (new UUID/timestamp)',
    file: /src\/lib\/licensing\/(?:coordinator|upgrade|pending-transaction)\.ts$/,
    re: /retry[\s\S]{0,200}(?:createUuidV4|new\s+Date\(\)\.toISOString)/i,
  },
  {
    label: 'licence values written to URL/history state',
    re: /(?:pushState|replaceState|history\.(?:push|replace))\s*\([^)]*(?:licence|plan|reference|target)/i,
  },
  {
    label: 'actionable Enterprise / payment / renewal / downgrade path in FEAT-017 licence UI',
    file: /src\/app\/auth\/licence\//,
    re: /(?:payment|renew(?:al)?|downgrade|contactProvider|requestPlan)\b/i,
  },
  {
    label: 'native module browser/IndexedDB/BFF fallback',
    file: /src-tauri\//,
    re: /(?:import\s+[^'"]*from\s+['"])(?:\.\.\/)+.*(?:browser-vault|indexeddb|bff)/,
  },
  {
    label: 'FEAT-018 client authorization imported into FEAT-017 surfaces',
    re: /(?:import\s+.+from\s+['"][^'"]*(?:enforce|authorization|entitlement-enforcement)[^'"]*['"])/i,
  },
];

/** Production file predicate: TS/TSX source, never a test or sample. */
function isProductionSource(path, name) {
  if (!/\.(ts|tsx|rs)$/.test(name)) return false;
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
  const extra = process.env.FEAT017_SCAN_ROOTS;
  if (typeof extra === 'string' && extra.length > 0) {
    for (const root of extra.split(':')) {
      if (root.length > 0) roots.push(root);
    }
  }
  return roots;
}

const files = [];
for (const root of collectRoots()) walk(root, files);
for (const extra of EXTRA_FILES) {
  const p = join(REPO_ROOT, extra);
  if (statSync(p, { throwIfNoEntry: false }) && isProductionSource(p, extra)) {
    files.push(p);
  }
}

const findings = [];
for (const file of files) {
  const content = readFileSync(file, 'utf8');
  for (const { label, re, file: fileMatcher } of PROPERTIES) {
    if (fileMatcher !== undefined && !fileMatcher.test(file)) continue;
    const globalRe = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    for (const match of content.matchAll(globalRe)) {
      findings.push(`${file}: ${label} (${match[0].slice(0, 80)})`);
      break;
    }
  }
}

if (findings.length > 0) {
  console.error(`FEAT-017 PROPERTY SCAN FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log(`FEAT-017 PROPERTY SCAN OK (0 forbidden properties across ${files.length} production files)`);
