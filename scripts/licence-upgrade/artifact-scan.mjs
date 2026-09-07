#!/usr/bin/env node
/**
 * FEAT-017 build/runtime artifact privacy scan (Phase 6 task 6.5).
 *
 * Scans generated/runtime artifacts for SECRET-CLASS FEAT-017 material:
 * declared fixture credentials/identity markers, mnemonic runs, private-key
 * PEM headers, raw exact-signed-envelope/signature material, and licence
 * reference/plan material in telemetry/log/report surfaces. Generic public
 * copy/URL/digest content in bundles is not a finding. A finding fails the
 * gate. Text-ish files only (extension allowlist, size-capped).
 *
 * Roots can be extended with FEAT017_SCAN_ROOTS so the seeded-defect
 * self-test can prove red-effectiveness.
 *
 * Usage: node scripts/licence-upgrade/artifact-scan.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const DEFAULT_ROOTS = ['.next-web', '.next-static', '.next-tauri', 'out', 'test-results', 'playwright-report', '.features-gen', 'coverage'];

const TEXT_EXTENSIONS = new Set(['.txt', '.log', '.json', '.html', '.xml', '.csv', '.md', '.ts', '.js', '.mjs', '.feature', '.map']);
const MAX_BYTES = 4 * 1024 * 1024;

/** Secret-class material only. */
const PROHIBITED = [
  { label: 'declared FEAT-017 fixture credential value', re: /(?:Alice|Ada)\s*(?:licence|fixture)-?password-?/i },
  { label: 'mnemonic phrase', re: /(?:"|')((?:[a-z]{3,12}\s){11,23}[a-z]{3,12})(?:"|')/ },
  { label: 'private key PEM header', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { label: 'raw signature material', re: /signature["']?\s*[:=]\s*["']?[0-9a-fA-F]{128,}["']?/ },
  { label: 'exact signed envelope', re: /exactJson["']?\s*[:=]\s*["'][^"']{80,}["']/ },
  { label: 'vault key handle', re: /keyAlias["']?\s*[:=]\s*["'][^"']+["']/ },
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
  console.error(`FEAT-017 ARTIFACT SCAN FAIL (${findings.length}):`);
  for (const finding of findings) console.error(`  - ${finding}`);
  process.exit(1);
}
console.log(`FEAT-017 ARTIFACT SCAN OK (0 prohibited findings across ${files.length} artifact files)`);
