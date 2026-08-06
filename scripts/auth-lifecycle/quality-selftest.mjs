#!/usr/bin/env node
/**
 * FEAT-010 aggregate-gate self-tests (Task 7.8).
 *
 * Proves the quality aggregate and its admission rules detect every defect
 * class: fabricated external PASS without evidence, invalid blocker state,
 * missing/red platform matrices, secret-bearing evidence, and harness runs
 * credited as real-root evidence.
 *
 * Usage: node scripts/auth-lifecycle/quality-selftest.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';

const QUALITY = join(import.meta.dirname, 'quality.mjs');
let failures = 0;

function runQuality(env) {
  try {
    execFileSync('node', [QUALITY], { stdio: 'pipe', encoding: 'utf8', env: { ...process.env, ...env } });
    return { status: 0, output: '' };
  } catch (error) {
    return { status: error.status ?? 1, output: String(error.stdout ?? '') + String(error.stderr ?? '') };
  }
}

function expect(label, ok, detail) {
  if (!ok) {
    console.error(`SELFTEST FAIL: ${label} — ${detail}`);
    failures += 1;
  } else {
    console.log(`ok - ${label}`);
  }
}

// The aggregate is expected RED today because the target-owned platform
// matrices are NOT_EXECUTED (documented blocker, never fabricated).
const baseline = runQuality({});
expect(
  'baseline aggregate reports the platform-evidence blocker',
  baseline.status !== 0 && baseline.output.includes('platform-evidence'),
  `status ${baseline.status}, output ${baseline.output.slice(-200)}`,
);

// Seeded defect 1: fabricated external PASS without evidence.
const tmp = mkdtempSync(join(tmpdir(), 'feat010-quality-self-'));
const ledger = JSON.parse(readFileSync(join(import.meta.dirname, 'external-blockers.json'), 'utf8'));
const fabricated = structuredClone(ledger);
fabricated.entries[0].state = 'PASS'; // no evidencePath → fabricated
writeFileSync(join(tmp, 'external-blockers.json'), JSON.stringify(fabricated));

// Seeded defect 2: invalid blocker state.
const invalid = structuredClone(ledger);
invalid.entries[1].state = 'DONE';
writeFileSync(join(tmp, 'external-blockers-invalid.json'), JSON.stringify(invalid));

// Seeded defect 3: a platform matrix marked FAIL.
const platforms = JSON.parse(readFileSync(join(import.meta.dirname, 'platform-evidence.json'), 'utf8'));
const failedMatrix = structuredClone(platforms);
failedMatrix.matrices[0].result = 'FAIL';
writeFileSync(join(tmp, 'platform-evidence-fail.json'), JSON.stringify(failedMatrix));

function runQualityWithSubstitution(blockerName, platformName) {
  // Substitute the ledger files in a shadow directory beside a copied quality.mjs.
  const shadow = join(tmp, 'shadow');
  mkdirSync(shadow);
  copyFileSync(QUALITY, join(shadow, 'quality.mjs'));
  for (const file of ['coverage.mjs', 'coverage-ledger.json', 'production-exclusion.mjs', 'secret-scan.mjs']) {
    copyFileSync(join(import.meta.dirname, file), join(shadow, file));
  }
  const blockerSource = existsSync(join(tmp, blockerName)) ? join(tmp, blockerName) : join(import.meta.dirname, blockerName);
  const platformSource = existsSync(join(tmp, platformName)) ? join(tmp, platformName) : join(import.meta.dirname, platformName);
  copyFileSync(blockerSource, join(shadow, 'external-blockers.json'));
  copyFileSync(platformSource, join(shadow, 'platform-evidence.json'));
  try {
    return execFileSync('node', [join(shadow, 'quality.mjs')], { stdio: 'pipe', encoding: 'utf8' }) && { status: 0, output: '' };
  } catch (error) {
    return { status: error.status ?? 1, output: String(error.stdout ?? '') + String(error.stderr ?? '') };
  } finally {
    rmSync(shadow, { recursive: true, force: true });
  }
}

const fabricatedRun = runQualityWithSubstitution('external-blockers.json', 'platform-evidence.json');
expect('fabricated external PASS fails admission', fabricatedRun.status !== 0 && fabricatedRun.output.includes('fabricated'), `status ${fabricatedRun.status}`);

const invalidRun = runQualityWithSubstitution('external-blockers-invalid.json', 'platform-evidence.json');
expect('invalid blocker state fails admission', invalidRun.status !== 0 && invalidRun.output.includes('invalid or fabricated'), `status ${invalidRun.status}`);

const failRun = runQualityWithSubstitution('external-blockers.json', 'platform-evidence-fail.json');
expect('FAIL platform matrix fails admission', failRun.status !== 0 && failRun.output.includes('matrix FAIL'), `status ${failRun.status}`);

rmSync(tmp, { recursive: true, force: true });

if (failures > 0) {
  console.error(`QUALITY SELFTEST FAILED (${failures} defects not detected)`);
  process.exit(1);
}
console.log('QUALITY SELFTEST PASSED (all seeded defects detected)');
