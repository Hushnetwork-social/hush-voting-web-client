#!/usr/bin/env node
/**
 * FEAT-010 aggregate-gate self-tests (Task 7.8).
 *
 * Proves the quality aggregate and its admission rules detect malformed or
 * fabricated evidence while preserving the independent release-readiness
 * result for valid FAIL/NOT_EXECUTED physical qualification evidence.
 *
 * Usage: node scripts/auth-lifecycle/quality-selftest.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const QUALITY = join(import.meta.dirname, 'quality.mjs');
let failures = 0;

function runQuality(env) {
  try {
    const output = execFileSync('node', [QUALITY], { stdio: 'pipe', encoding: 'utf8', env: { ...process.env, ...env } });
    return { status: 0, output };
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

// The implementation aggregate is green when the platform ledger truthfully
// records NOT_EXECUTED. Release readiness remains independently blocked.
const baseline = runQuality({});
expect(
  'baseline implementation aggregate accepts truthful pending manual qualification',
  baseline.status === 0 && baseline.output.includes('RELEASE READINESS: BLOCKED_BY_MANUAL_QUALIFICATION'),
  `status ${baseline.status}, output ${baseline.output.slice(-300)}`,
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
  return runQuality({
    FEAT010_EXTERNAL_BLOCKER_LEDGER: join(tmp, blockerName),
    FEAT010_PLATFORM_EVIDENCE_LEDGER: join(tmp, platformName),
  });
}

writeFileSync(join(tmp, 'external-blockers-valid.json'), JSON.stringify(ledger));
writeFileSync(join(tmp, 'platform-evidence-valid.json'), JSON.stringify(platforms));

const fabricatedRun = runQualityWithSubstitution('external-blockers.json', 'platform-evidence-valid.json');
expect('fabricated external PASS fails admission', fabricatedRun.status !== 0 && fabricatedRun.output.includes('fabricated'), `status ${fabricatedRun.status}`);

const invalidRun = runQualityWithSubstitution('external-blockers-invalid.json', 'platform-evidence-valid.json');
expect('invalid blocker state fails admission', invalidRun.status !== 0 && invalidRun.output.includes('invalid or fabricated'), `status ${invalidRun.status}`);

const failRun = runQualityWithSubstitution('external-blockers-valid.json', 'platform-evidence-fail.json');
expect(
  'truthful FAIL platform matrix blocks release readiness without failing implementation admission',
  failRun.status === 0 && failRun.output.includes('RELEASE READINESS: BLOCKED_BY_MANUAL_QUALIFICATION'),
  `status ${failRun.status}, output ${failRun.output.slice(-300)}`,
);

rmSync(tmp, { recursive: true, force: true });

if (failures > 0) {
  console.error(`QUALITY SELFTEST FAILED (${failures} defects not detected)`);
  process.exit(1);
}
console.log('QUALITY SELFTEST PASSED (all seeded defects detected)');
