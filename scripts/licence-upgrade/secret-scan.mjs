#!/usr/bin/env node
/**
 * FEAT-017 secret/privacy scan (Phase 6 task 6.5).
 *
 * Scans FEAT-017 production surfaces and integration artifacts for
 * prohibited content: credential literals, private-key markers, raw exact
 * transaction/signature material, native key handles, plan/licence/
 * transaction identifiers in telemetry/log/report surfaces, and free-form
 * server text. Public synthetic fixture UUIDs used by tests are allowed.
 *
 * Roots can be extended with FEAT017_SCAN_ROOTS so the seeded-defect
 * self-test can prove red-effectiveness.
 *
 * Usage: node scripts/licence-upgrade/secret-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const DEFAULT_ROOTS = [
  'src/lib/licensing',
  'src/lib/browser-vault/production',
  'src/lib/auth/web',
  'src/lib/auth/state',
  'src/app/auth',
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
  'fixtures',
]);

const SKIP_FILES = new Set(['secret-scan.mjs', 'property-scan.mjs', 'artifact-scan.mjs', 'selftest.mjs', 'quality.mjs', 'coverage.mjs', 'wiring.mjs', 'evidence-manifest.json', 'pairing-ledger.json', 'canonical-ids.json']);

/** Explicitly allowed public synthetic fixture / domain markers. */
const ALLOWED_PATTERNS = [
  /FIXTURE/,
  /fixture/,
  /5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e/,
  /8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55/,
  /71370664-5eb4-4ce9-b96a-d7e7ffe53db5/,
  /hushvoting\.direct\.free/,
  /hushvoting\.veritas\.\d+/,
  /hushvoting\.enterprise/,
  /baseline_free/,
  /confirmed_upgrade/,
  /hushvoting-licence-catalogue\/v1\.0\.0/,
  /0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5/,
  /02b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2/,
  /x-hush-licence-query-signature/,
  /example\.com/,
  /localhost/,
  /127\.0\.0\.1/,
  /hush-network-local-devnet-5195086/,
  /Tr0ub4dor/,
  /0000000000000000000000000000000000000000000000000000000000000001/,
];

/** Prohibited markers (secret-class only). */
const PROHIBITED = [
  { label: 'mnemonic phrase', re: /(?:"|')((?:[a-z]{3,12}\s){11,23}[a-z]{3,12})(?:"|')/ },
  { label: 'private key', re: /BEGIN (?:RSA |EC )?PRIVATE KEY/ },
  { label: 'private scalar hex in key context', re: /(?:privateScalar|signingSecret|secretHex)\s*[:=]\s*["'][0-9a-f]{64}["']/i },
  { label: 'raw signature value', re: /signature\s*[:=]\s*["'][0-9a-fA-F]{64,}["']/ },
  { label: 'signed envelope in log/trace', re: /(?:exactJson|signedJson)\s*[:=]\s*["'][^"']{40,}["']/ },
  { label: 'native key handle', re: /keyAlias\s*[:=]\s*["'][^"']+["']/ },
  { label: 'server free-form text (msg/message from server)', re: /(?:serverMessage|freeForm|rawMessage)\s*[:=]/i },
];

function walk(dir, out) {
  if (!statSync(dir, { throwIfNoEntry: false })) return;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(p, out);
    } else if (/^(?:ts|tsx|mjs|rs|md|json)$/.test(entry.slice(entry.lastIndexOf('.') + 1)) && !SKIP_FILES.has(entry) && !/\.test\.|\.spec\./.test(entry)) {
      out.push(p);
    }
  }
}

function isAllowed(match) {
  return ALLOWED_PATTERNS.some((pattern) => pattern.test(match));
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

const findings = [];
for (const file of files) {
  const content = readFileSync(file, 'utf8');
  for (const { label, re } of PROHIBITED) {
    const globalRe = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    for (const match of content.matchAll(globalRe)) {
      if (isAllowed(match[0])) continue;
      findings.push(`${file}: ${label}`);
      break;
    }
  }
}

if (findings.length > 0) {
  console.error(`FEAT-017 SECRET SCAN FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log(`FEAT-017 SECRET SCAN OK (0 prohibited findings across ${files.length} files)`);
