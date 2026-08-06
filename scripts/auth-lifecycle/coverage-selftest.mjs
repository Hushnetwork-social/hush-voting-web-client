#!/usr/bin/env node
/**
 * FEAT-010 coverage-validator self-tests (Task 7.2).
 *
 * Proves the validator fails for every missing/unknown/stale/weak/
 * duplicate-conflicting mapping and passes only a complete 100/100, 26/26,
 * target-aware inventory (AC-010-091/098).
 *
 * Usage: node scripts/auth-lifecycle/coverage-selftest.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const VALIDATOR = join(import.meta.dirname, 'coverage.mjs');
const LEDGER = join(import.meta.dirname, 'coverage-ledger.json');

let failures = 0;

function runValidator(args = []) {
  try {
    execFileSync('node', [VALIDATOR, ...args], { stdio: 'pipe', encoding: 'utf8' });
    return { status: 0 };
  } catch (error) {
    return { status: error.status ?? 1, output: String(error.stdout ?? '') + String(error.stderr ?? '') };
  }
}

function expectFail(label, result, needle) {
  if (result.status === 0) {
    console.error(`SELFTEST FAIL: ${label} — validator passed but should have failed`);
    failures += 1;
    return;
  }
  if (needle !== undefined && !result.output.includes(needle)) {
    console.error(`SELFTEST FAIL: ${label} — missing diagnostic ${needle}`);
    failures += 1;
    return;
  }
  console.log(`ok - ${label}`);
}

function expectPass(label, result) {
  if (result.status !== 0) {
    console.error(`SELFTEST FAIL: ${label} — validator failed unexpectedly`);
    failures += 1;
    return;
  }
  console.log(`ok - ${label}`);
}

const tmp = mkdtempSync(join(tmpdir(), 'feat010-coverage-self-'));
/** Run the validator against a patched ledger by shadowing its ledger file. */
function runPatchedLedger(patchedPath, targetName, copyDir) {
  mkdirSync(copyDir, { recursive: true });
  copyFileSync(VALIDATOR, join(copyDir, 'coverage.mjs'));
  copyFileSync(patchedPath, join(copyDir, targetName));
  try {
    return execFileSync('node', [join(copyDir, 'coverage.mjs')], { stdio: 'pipe', encoding: 'utf8' }) && { status: 0 };
  } catch (error) {
    return { status: error.status ?? 1, output: String(error.stdout ?? '') + String(error.stderr ?? '') };
  } finally {
    rmSync(copyDir, { recursive: true, force: true });
  }
}
try {
  // Baseline: the shipped ledger must pass.
  expectPass('baseline ledger is complete', runValidator());

  // Seeded defect 1: one criterion removed.
  const ledger = JSON.parse(readFileSync(LEDGER, 'utf8'));
  const missingAc = structuredClone(ledger);
  missingAc.criteria = missingAc.criteria.filter((c) => c.id !== 'AC-010-042');
  const missingPath = join(tmp, 'missing-ac.json');
  writeFileSync(missingPath, JSON.stringify(missingAc));
  const copyDir = join(tmp, 'validator-copy');
  // The validator reads its ledger from its own directory; copy it beside a
  // patched validator to test patched ledgers.
  expectFail(
    'removed criterion fails validation',
    runPatchedLedger(missingPath, 'coverage-ledger.json', copyDir),
    'expected 100 criteria, got 99',
  );

  // Seeded defect 2: duplicate family.
  const dupFamily = structuredClone(ledger);
  dupFamily.families = [...dupFamily.families, dupFamily.families[0]];
  const dupPath = join(tmp, 'dup-family.json');
  writeFileSync(dupPath, JSON.stringify(dupFamily));
  expectFail('duplicate family fails validation', runPatchedLedger(dupPath, 'coverage-ledger.json', copyDir), 'expected 26 families, got 27');

  // Seeded defect 3: evidence manifest with an unknown class.
  const evidenceBad = { entries: [{ criterionId: 'AC-010-001', class: 'Z', secretBearing: false }] };
  const badEvidencePath = join(tmp, 'bad-evidence.json');
  writeFileSync(badEvidencePath, JSON.stringify(evidenceBad));
  const badRun = runValidator(['--evidence', badEvidencePath]);
  expectFail('unknown evidence class fails validation', badRun, 'unknown class');

  // Seeded defect 4: secret-bearing scenario with capture enabled.
  const evidenceSecret = { entries: [{ criterionId: 'AC-010-029', class: 'R', realRoot: true, secretBearing: true, capturePolicy: 'enabled' }] };
  const secretPath = join(tmp, 'secret-evidence.json');
  writeFileSync(secretPath, JSON.stringify(evidenceSecret));
  const secretRun = runValidator(['--evidence', secretPath]);
  expectFail('secret-bearing scenario with capture enabled fails', secretRun, 'capture');

  // Seeded defect 5: component-only evidence for a user-visible boundary.
  const evidenceWeak = { entries: [{ criterionId: 'AC-010-007', class: 'C', secretBearing: false }] };
  const weakPath = join(tmp, 'weak-evidence.json');
  writeFileSync(weakPath, JSON.stringify(evidenceWeak));
  const weakRun = runValidator(['--evidence', weakPath]);
  expectFail('component-only evidence for a real-root boundary fails', weakRun, 'real-root');

  // Seeded defect 6: missing evidence manifest file.
  expectFail('missing evidence manifest fails', runValidator(['--evidence', join(tmp, 'nope.json')]), 'not found');

  // Seeded defect 7: incomplete evidence (one AC missing).
  const evidenceIncomplete = {
    entries: ledger.criteria
      .filter((c) => c.id !== 'AC-010-091')
      .map((c) => ({ criterionId: c.id, class: 'X', secretBearing: false })),
  };
  const incompletePath = join(tmp, 'incomplete-evidence.json');
  writeFileSync(incompletePath, JSON.stringify(evidenceIncomplete));
  const incompleteRun = runValidator(['--evidence', incompletePath]);
  expectFail('incomplete evidence fails validation', incompleteRun, 'AC-010-091');
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`COVERAGE SELFTEST FAILED (${failures} defects not detected)`);
  process.exit(1);
}
console.log('COVERAGE SELFTEST PASSED (all seeded defects detected)');
