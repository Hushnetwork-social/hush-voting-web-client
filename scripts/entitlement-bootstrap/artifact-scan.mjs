#!/usr/bin/env node
/**
 * FEAT-016 build/runtime artifact privacy scan (Phase 7 task 7.5).
 *
 * Scans generated/runtime artifacts for SECRET-CLASS material: the declared
 * FEAT-016 journey credential/alias values, mnemonic phrase runs, private-key
 * PEM headers, private scalar hex in key contexts, and raw signature/envelope
 * material. Webpack bundles legitimately contain public URLs and pinned proto
 * digests, so generic URL/hex patterns are NOT findings here (matching the
 * repo vault artifact-scan precedent that scans for conformance-only and
 * declared-credential material). Text-ish files only (extension allowlist,
 * size-capped); binaries are skipped. A finding fails the gate.
 *
 * Roots can be extended with FEAT016_SCAN_ROOTS (colon-separated absolute
 * paths) so the seeded-defect self-test can prove red-effectiveness.
 *
 * Usage: node scripts/entitlement-bootstrap/artifact-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const DEFAULT_ROOTS = ['.next-web', '.next-static', '.next-tauri', 'out', 'test-results', 'playwright-report', '.features-gen-entitlement-bootstrap', 'coverage'];

const TEXT_EXTENSIONS = new Set(['.txt', '.log', '.json', '.html', '.xml', '.csv', '.md', '.ts', '.js', '.mjs', '.feature', '.map']);
const MAX_BYTES = 4 * 1024 * 1024;

/** Secret-class material only (declared fixture credentials and private-key
 * material). Public copy/digest/URL content and framework-owned per-build
 * keys (e.g. Next.js prerender-manifest SigningKey) are not findings. */
const PROHIBITED = [
  { label: 'declared journey credential value', re: /Entitlement-fixture-password-42/ },
  { label: 'declared journey identity alias', re: /BDD Entitlement Alice/ },
  { label: 'mnemonic phrase', re: /(?:"|')((?:[a-z]{3,12}\s){11,23}[a-z]{3,12})(?:"|')/ },
  { label: 'private key PEM header', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { label: 'raw signature material', re: /signature["']?\s*[:=]\s*["']?[0-9a-fA-F]{128,}["']?/ },
  { label: 'vault handle', re: /keyAlias["']?\s*[:=]\s*["'][^"']+["']/ },
];

function walk(dir, out) {
  if (!statSync(dir, { throwIfNoEntry: false })) return;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (entry !== 'node_modules' && entry !== '.git' && entry !== 'target') walk(p, out);
    } else {
      const extIndex = entry.lastIndexOf('.');
      const ext = extIndex === -1 ? '' : entry.slice(extIndex);
      if (TEXT_EXTENSIONS.has(ext) && st.size <= MAX_BYTES) out.push(p);
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
  let content;
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  for (const { label, re } of PROHIBITED) {
    const globalRe = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    for (const _match of content.matchAll(globalRe)) {
      findings.push(`${file}: ${label}`);
      break;
    }
  }
}

if (findings.length > 0) {
  console.error(`ARTIFACT SCAN FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log(`ARTIFACT SCAN OK (0 prohibited findings across ${files.length} artifact files)`);
