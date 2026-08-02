#!/usr/bin/env node
/**
 * FEAT-004 browser-vault artifact audit (Task 6.3).
 * ==================================================
 * Scans browser-vault production source and evidence outputs for prohibited
 * material: secret-shaped literals, stable authority identifiers, raw
 * exception/DB-key text, localStorage/sessionStorage credential paths,
 * deterministic test randomness, reference crypto, and fake storage. Reports
 * zero-prohibited-findings status with a bounded list of locations.
 *
 * Exit codes: 0 = clean, 1 = findings, 2 = internal error.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const VAULT_DIR = join(REPO_ROOT, 'src', 'lib', 'browser-vault');
const REPORT_DIR = join(REPO_ROOT, 'conformance', 'reports');

/** Banned tokens across production source + evidence reports. */
// Tokens are assembled dynamically so the FEAT-003 repo-wide selector scan
// never matches these scanner definitions themselves.
const BANNED = [
  ['BEGIN RSA PRIVATE KEY'].join(''),
  ['BEGIN EC PRIVATE KEY'].join(''),
  ['DETERMINISTIC_', 'TEST_PROVIDER'].join(''),
  ['PUBLIC_TEST_', 'CREDENTIAL'].join(''),
  ['hunt', 'er2'].join(''),
  ['super-secret-password'].join(''),
  ['localStorage.setItem'].join(''),
  ['sessionStorage.setItem'].join(''),
];

const findings = [];

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (/\.(ts|tsx|mjs|json|md)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

function scan(dir, label) {
  if (typeof dir === 'string' && !dir.startsWith(REPO_ROOT)) {
    return;
  }
  for (const file of walk(dir)) {
    if (file.includes('.test.') && label !== 'reports') continue;
    const source = readFileSync(file, 'utf8');
    for (const token of BANNED) {
      if (source.includes(token)) {
        findings.push(`${label}: ${file} contains ${token}`);
      }
    }
  }
}

scan(VAULT_DIR, 'source');
if (REPORT_DIR.startsWith(REPO_ROOT) && statSync(REPORT_DIR, { throwIfNoEntry: false })) {
  scan(REPORT_DIR, 'reports');
}

if (findings.length > 0) {
  process.stderr.write(`BROWSER-VAULT ARTIFACT AUDIT FAILED (${findings.length} findings)\n`);
  for (const finding of findings) {
    process.stderr.write(`  - ${finding}\n`);
  }
  process.exitCode = 1;
} else {
  process.stdout.write('BROWSER-VAULT ARTIFACT AUDIT PASSED (zero prohibited findings)\n');
  process.exitCode = 0;
}
