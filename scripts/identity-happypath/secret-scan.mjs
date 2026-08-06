#!/usr/bin/env node
/**
 * FEAT-011 Tasks 7.1/7.5 — secret/provenance/export scan for the FEAT-011
 * production surface.
 *
 * Scans the convergence modules, BFF binary transport, and evidence manifest
 * for never-recorded values, export/generic-signer capabilities, full
 * identifiers, and capture-policy violations. Zero findings required.
 */

import { readFileSync } from 'node:fs';
import { globSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_ROOT = path.resolve(__dirname, '..', '..');

/** Never-recorded value patterns (evidence-admission §1). */
const NEVER_RECORDED = [
  /(?:password|passwd)\s*[:=]\s*["'][^"']{4,}/i,
  /\b(mnemonic|recovery ?words?|seed ?phrase)\b.{0,40}["'][A-Za-z ]{8,}["']/i,
  /private ?key\s*[:=]\s*["'][0-9a-fA-F]{32,}["']/i,
  /BEGIN [A-Z ]*PRIVATE KEY/,
  /\.dat\b.{0,30}["'][^"']{8,}["']/i,
  /transaction ?(?:json|bytes|signature)\s*[:=]\s*["'][^"']{32,}["']/i,
  /device ?id\s*[:=]\s*["'][^"']{8,}["']/i,
];

/** Forbidden capability surface (export / generic signer). */
const FORBIDDEN_CAPABILITY = [
  /\bexport(?:Encrypted)?File\b/i,
  /\bcreateDat\b|\bsaveDat\b|\bdownloadDat\b/i,
  /\bsign\(bytes\)\b|\bgenericSign\b|\bsignAnything\b/i,
  /\bprivateKeyExport\b/i,
];

/** Full-identifier pattern (66/130-char hex addresses in source constants). */
const FULL_IDENTIFIER = /\b[0-9a-fA-F]{64,130}\b/;

/** Known non-identifier 64-hex constants (pinned proto digests). */
const ALLOWED_64HEX = new Set([
  'df3a2d9b128335dc3c92f0ef2b246655ed4c95f53f7ce058d438d945724f8ffa',
  'e0625d52e4227ed77b6eb0e7d74b2990b7a8d3e8ecd77bd308371797275dc04b',
]);

const SCAN_PATHS = [
  'src/lib/identity-convergence/**/*.ts',
  'src/lib/runtime/native-dispatch.ts',
  'src/lib/runtime/target-transports.ts',
  'src/app/api/binary-grpc-transport.ts',
  'src/app/api/server-transport.ts',
];

export function scanSurface(roots = SCAN_PATHS, baseDir = CLIENT_ROOT) {
  const findings = [];
  // Production surface only: test files deliberately carry seeded-defect
  // fixtures (hunter2, BEGIN PRIVATE KEY, createDat) as negative test data.
  const files = roots
    .flatMap((pattern) => globSync(pattern, { cwd: baseDir }))
    .filter((file) => !/\.test\.ts$/.test(file) && !/\.test\.mjs$/.test(file));

  for (const file of files) {
    const lines = readFileSync(path.join(baseDir, file), 'utf8').split('\n');
    const content = lines.join('\n');
    for (const re of NEVER_RECORDED) {
      for (const line of lines) {
        // The forbidden-surface guard types/asserts deliberately name the
        // forbidden fields; they are the boundary declaration, not a leak.
        if (/Forbidden\w*Surface|assertNoSecret|includes\(key\)|violations/.test(line)) {
          continue;
        }
        const match = line.match(re);
        if (match !== null) {
          findings.push({ file, pattern: re.source, snippet: match[0].slice(0, 80) });
        }
      }
    }
    for (const re of FORBIDDEN_CAPABILITY) {
      const match = content.match(re);
      if (match !== null) {
        findings.push({ file, pattern: re.source, snippet: match[0].slice(0, 80) });
      }
    }
    // Full identifiers allowed ONLY in test files (FEAT-001 public vectors)
    // and the pinned proto digest constants.
    if (!/\.test\.ts$/.test(file)) {
      const match = content.match(FULL_IDENTIFIER);
      if (match !== null && !ALLOWED_64HEX.has(match[0].toLowerCase())) {
        findings.push({ file, pattern: 'FULL_IDENTIFIER', snippet: match[0].slice(0, 40) });
      }
    }
  }

  return findings;
}

export function main() {
  const findings = scanSurface();
  if (findings.length === 0) {
    console.log('FEAT-011 secret/provenance scan OK: 0 findings.');
    return 0;
  }
  console.error(`FEAT-011 secret/provenance scan FAILED: ${findings.length} finding(s)`);
  for (const finding of findings) {
    console.error(`  - ${finding.file}: ${finding.pattern} -> ${finding.snippet}`);
  }
  return 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main());
}
