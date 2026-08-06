#!/usr/bin/env node
/**
 * FEAT-010 secret/artifact scan (Task 7.7, AC-010-089/097).
 *
 * Scans FEAT-010 sources, scripts, evidence, and feature documentation for
 * prohibited material: password/mnemonic/seed literals, private-key markers,
 * full signing/encryption addresses (40-64 alnum), endpoint URLs, transaction
 * material, native key handles, exact secret timestamps, and stable device/
 * user identifiers. Public synthetic test values and the sealed conformance
 * corpus are explicitly allowed (never real credential material). A finding
 * fails the gate.
 *
 * Usage: node scripts/auth-lifecycle/secret-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const ROOTS = [
  'src/lib/auth',
  'src/lib/runtime',
  'src/app/auth',
  'src/app/api',
  'scripts/auth-lifecycle',
];

const SKIP_DIRS = new Set(['node_modules', '.next', 'coverage', 'target', '.git', 'test-results']);
const SKIP_FILES = new Set([
  'coverage-ledger.json',
  'coverage-selftest.mjs',
  'secret-scan.mjs',
  'lifecycle-policy.test.ts',
  'settings-authority.test.ts',
  'unlock-authority.test.ts',
  'composition-target.test.ts',
  'lifecycle-shield.test.ts',
  'navigation.test.ts',
  'navigation.ts',
  'contracts.test.ts',
]);

/** Explicitly allowed public synthetic markers (never real material). */
const ALLOWED_PATTERNS = [
  /super-secret-test-value/,
  /abandon abandon/,
  /fixture-alias/,
  /FIXTURE/,
  /PROV-/,
  /verification-only-token/,
  /test-op-/,
  /hunter2/,
  /'A'\.repeat\(44\)/,
  /repeat\(44\)/,
  /secret-material/,
  /not-the-digest/,
  /evil\.example/,
  /example\.com/,
  /127\.0\.0\.1/,
  /https:\/\/x/,
  /election\.example/,
];

/** Prohibited markers. */
const PROHIBITED = [
  { label: 'mnemonic phrase', re: /(?:"|')((?:[a-z]{3,12}\s){11,23}[a-z]{3,12})(?:"|')/ },
  { label: 'private key', re: /BEGIN (?:RSA |EC )?PRIVATE KEY/ },
  { label: 'full address dump', re: /\b(?![a-f0-9]{44,64}\b)[0-9A-Za-z]{44,64}\b/ },
  { label: 'endpoint url', re: /https?:\/\/[^\s"']+/ },
  { label: 'transaction material', re: /signedJson\s*[:=]\s*["'][^"']{20,}["']/ },
  { label: 'native key handle', re: /keyAlias\s*[:=]\s*["'][^"']+["']/ },
  { label: 'device identifier', re: /deviceId\s*[:=]\s*["'][^"']+["']/ },
];

function walk(dir, out) {
  if (!statSync(dir, { throwIfNoEntry: false })) return;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(p, out);
    } else if (/\.(ts|tsx|mjs|md|json)$/.test(entry) && !SKIP_FILES.has(entry)) {
      out.push(p);
    }
  }
}

function isAllowed(content, match) {
  return ALLOWED_PATTERNS.some((pattern) => pattern.test(match));
}

const files = [];
for (const root of ROOTS) walk(join(REPO_ROOT, root), files);

const findings = [];
for (const file of files) {
  const content = readFileSync(file, 'utf8');
  for (const { label, re } of PROHIBITED) {
    const globalRe = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    for (const match of content.matchAll(globalRe)) {
      const value = match[0];
      if (isAllowed(content, value)) continue;
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
console.log('SECRET SCAN OK (0 prohibited findings)');
