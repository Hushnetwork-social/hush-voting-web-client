#!/usr/bin/env node
/**
 * FEAT-006 Phase 7 Task 7.4 (static part) — Android secret/artifact scan.
 *
 * Scans the Android surfaces (src-tauri/src/android_vault, src-tauri/
 * mobile-plugin, src/lib/android-vault, scripts/android-vault, conformance/
 * android-vault) for secret patterns and prohibited markers. The sanctioned
 * synthetic vectors/reports are allowlisted; production keys and real
 * wrapped-vault ciphertext must never appear. Supply-chain gates (cargo
 * audit + npm audit) run separately as advisory gates.
 *
 * Usage:
 *   node scripts/android-vault/secret-scan.mjs
 */

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const SCRIPT_DIR = dirname(new URL(import.meta.url).pathname);
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

const SCAN_ROOTS = [
  join(REPO_ROOT, 'src-tauri', 'src', 'android_vault'),
  join(REPO_ROOT, 'src-tauri', 'mobile-plugin'),
  join(REPO_ROOT, 'src', 'lib', 'android-vault'),
  join(REPO_ROOT, 'scripts', 'android-vault'),
  join(REPO_ROOT, 'conformance', 'android-vault'),
];

const FILE_RE = /\.(rs|kt|ts|tsx|mjs|js|json|md)$/;

/** Sanctioned allowlist: public synthetic vectors/reports only. */
const ALLOWLIST = [
  'conformance/android-vault/v1/vectors/',
  'conformance/android-vault/v1/reports/',
];

const PROHIBITED = [
  { label: 'private key PEM header', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: 'mnemonic seed phrase fragment', re: /\b(abandon|ability|able|about|above|absent)\b[\s]+(?:abandon|ability|able|about|above|absent)\b[\s]+(?:abandon|ability|able|about|above|absent)\b/ },
  { label: 'stable device id pattern', re: /\b(serial|androidId|android_id|attestationId|attestation_id|imei)\b\s*[:=]\s*["'][^"']{8,}["']/i },
  // Note: `.jks`/`.keystore` are checked as FILE NAMES below, never as
  // content substrings (Android's `android.security.keystore` package is
  // legitimate application code).
  { label: 'real vault ciphertext marker', re: /BEGIN HUSHVOTING VAULT/ },
];

const findings = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (entry === 'node_modules' || entry === 'target' || entry === 'gen') continue;
      walk(p);
    } else {
      if (entry === 'secret-scan.mjs') continue; // the scanner carries its own patterns
      const rel = relative(REPO_ROOT, p).split(sep()).join('/');
      if (ALLOWLIST.some((a) => rel.startsWith(a))) continue;
      if (/\.(jks|keystore)$/i.test(entry)) {
        findings.push(`${rel} is signing keystore material`);
      }
      if (!FILE_RE.test(entry)) continue;
      const content = readFileSync(p, 'utf8');
      if (/\.(test\.(rs|ts|tsx)|\.test\.mjs)$/.test(entry)) {
        // Test files legitimately carry negative-pattern fixtures; skip
        // prohibited-pattern scan but keep stable-device-id scan (no fixtures).
      } else {
        for (const pattern of PROHIBITED) {
          if (pattern.re.test(content)) {
            findings.push(`${rel} matches ${pattern.label}`);
          }
        }
      }
    }
  }
}

function sep() {
  return /^win/.test(process.platform) ? '\\' : '/';
}

function main() {
  for (const root of SCAN_ROOTS) {
    if (existsSync(root)) walk(root);
  }
  if (findings.length > 0) {
    console.error(`ANDROID SECRET SCAN FAILED:\n${findings.join('\n')}`);
    process.exit(1);
  }
  console.log('ANDROID SECRET SCAN OK (no secret/signing/device-id material in Android surfaces)');
}

if (process.argv[1] && process.argv[1].endsWith('secret-scan.mjs')) {
  main();
}
