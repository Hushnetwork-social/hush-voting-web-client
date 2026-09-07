#!/usr/bin/env node
/**
 * FEAT-016 secret/privacy scan (Phase 7 tasks 7.2/7.5).
 *
 * Scans FEAT-016 journey surface and evidence material for prohibited
 * content: credential/password/mnemonic/seed literals, private-key markers,
 * full signing/encryption addresses, endpoint URLs, exact licence
 * transaction material, native key handles, raw signed envelopes, plan/
 * licence identifiers, and stable device/user identifiers. Public synthetic
 * fixture values used by the BDD journeys are explicitly allowed (never real
 * credential material). A finding fails the gate.
 *
 * Roots can be extended with FEAT016_SCAN_ROOTS (colon-separated absolute
 * paths) so the seeded-defect self-test can prove red-effectiveness.
 *
 * Usage: node scripts/entitlement-bootstrap/secret-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const DEFAULT_ROOTS = [
  'features/licence-entitlements',
  'browser/licence-entitlements',
  'scripts/entitlement-bootstrap',
  'src/lib/licensing',
  'src/lib/browser-vault/production',
  'src/lib/auth/presentation',
  'src/lib/auth/web',
  'src/lib/auth/state',
  'src/app/auth',
  'src/app/api',
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

/** Explicitly allowed public synthetic journey/fixture markers. */
const ALLOWED_PATTERNS = [
  /BDD Entitlement Alice/,
  /Entitlement-fixture-password-42/,
  /wrong-password-value-123/,
  /abandon abandon/,
  /fixture-alias/,
  /FIXTURE/,
  /hunter2/,
  /'A'\.repeat\(44\)/,
  /repeat\(44\)/,
  /secret-material/,
  /not-the-digest/,
  /evil\.example/,
  /example\.com/,
  /127\.0\.0\.1/,
  /localhost/,
  /https:\/\/x/,
  /HUSHSERVER_NODE_ENDPOINT/,
  /ApplicationSettings/,
  /x-hush-licence-query-signature/,
  /71370664-5eb4-4ce9-b96a-d7e7ffe53db5/,
  /Direct Free/,
  /Veritas/,
  /baseline_free/,
  /confirmed_upgrade/,
];

/** Prohibited markers. */
const PROHIBITED = [
  { label: 'mnemonic phrase', re: /(?:"|')((?:[a-z]{3,12}\s){11,23}[a-z]{3,12})(?:"|')/ },
  { label: 'private key', re: /BEGIN (?:RSA |EC )?PRIVATE KEY/ },
  { label: 'private scalar hex', re: /(?:privateScalar|scalarHex|signingKey|privateKey)\s*[:=]\s*["'][0-9a-f]{64}["']/i },
  { label: 'full address dump', re: /\b(?![a-f0-9]{44,64}\b)[0-9A-Za-z]{44,64}\b/ },
  { label: 'endpoint url', re: /https?:\/\/[^\s"']+/ },
  { label: 'transaction material', re: /signedJson\s*[:=]\s*["'][^"']{20,}["']/ },
  { label: 'raw signature', re: /signature\s*[:=]\s*["'][0-9a-fA-F]{64,}["']/ },
  { label: 'native key handle', re: /keyAlias\s*[:=]\s*["'][^"']+["']/ },
  { label: 'device identifier', re: /deviceId\s*[:=]\s*["'][^"']+["']/ },
  { label: 'signed envelope', re: /(?:envelope|signedAt|actorAddress)\s*[:=]\s*["'][^"']{40,}["']/ },
  { label: 'support-code seed', re: /supportCode\s*[:=]\s*["'][A-Z0-9]{4}-[A-Z0-9]{4}["']/ },
];

function walk(dir, out) {
  if (!statSync(dir, { throwIfNoEntry: false })) return;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(p, out);
    } else if (/^(?:ts|tsx|mjs|js|md|feature|json)$/.test(entry.slice(entry.lastIndexOf('.') + 1)) && !SKIP_FILES.has(entry) && !/\.test\.|\.spec\./.test(entry)) {
      out.push(p);
    }
  }
}

function isAllowed(match) {
  return ALLOWED_PATTERNS.some((pattern) => pattern.test(match));
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
  console.error(`SECRET SCAN FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log(`SECRET SCAN OK (0 prohibited findings across ${files.length} files)`);
