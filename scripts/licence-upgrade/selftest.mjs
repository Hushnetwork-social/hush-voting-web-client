#!/usr/bin/env node
/**
 * FEAT-017 seeded-defect self-tests (Phase 6 task 6.6).
 *
 * Proves each focused gate is RED-effective: a seeded defect in the gate's
 * own input surface MUST fail the gate with a non-zero exit. Cases:
 *  1. secret-scan finds a private-key marker in a seeded file;
 *  2. property-scan finds a forbidden FEAT-017 property (page polling);
 *  3. artifact-scan finds a raw secret in a seeded artifact log;
 *  4. coverage validator fails on a required suite (zero discovery);
 *  5. wiring validator fails on a missing integration anchor.
 * All seeded material lives in a temporary directory created and removed by
 * this script; production source is never modified.
 *
 * Usage: node scripts/licence-upgrade/selftest.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

function expectRed(label, command, args, env) {
  let exit = null;
  try {
    execFileSync(command, args, {
      cwd: REPO_ROOT,
      stdio: 'pipe',
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, ...env },
    });
  } catch (error) {
    exit = error.status ?? 1;
  }
  if (exit === null) {
    console.error(`SELF-TEST FAIL: ${label} did not fail (gate passed on a seeded defect)`);
    return false;
  }
  console.log(`  \u2713 ${label}: gate failed non-zero as required (exit ${exit})`);
  return true;
}

const root = mkdtempSync(join(tmpdir(), 'feat017-seed-'));
const results = [];
try {
  // 1. secret-scan red-effectiveness.
  const secretRoot = join(root, 'secret-seed');
  mkdirSync(secretRoot, { recursive: true });
  const pemHeader = '-----BEGIN ' + 'EC PRIVATE KEY' + '-----';
  writeFileSync(join(secretRoot, 'seeded-secret.ts'), `const material = "${pemHeader}\\nseeded";\n`);
  results.push(
    expectRed('secret-scan', process.execPath, [join(SCRIPT_DIR, 'secret-scan.mjs')], {
      FEAT017_SCAN_ROOTS: secretRoot,
    }),
  );

  // 2. property-scan red-effectiveness (page polling loop).
  const propertyRoot = join(root, 'property-seed');
  mkdirSync(propertyRoot, { recursive: true });
  writeFileSync(
    join(propertyRoot, 'seeded-prop.ts'),
    'export function poll(): void { setInterval(() => undefined, 3000); }\n',
  );
  results.push(
    expectRed('property-scan', process.execPath, [join(SCRIPT_DIR, 'property-scan.mjs')], {
      FEAT017_SCAN_ROOTS: propertyRoot,
    }),
  );

  // 3. artifact-scan red-effectiveness.
  const artifactRoot = join(root, 'artifact-seed');
  mkdirSync(artifactRoot, { recursive: true });
  const pemMarker = '-----BEGIN ' + 'RSA PRIVATE KEY' + '-----';
  writeFileSync(join(artifactRoot, 'seeded.log'), `trace: ${pemMarker} leaked-into-artifact\n`);
  results.push(
    expectRed('artifact-scan', process.execPath, [join(SCRIPT_DIR, 'artifact-scan.mjs')], {
      FEAT017_SCAN_ROOTS: artifactRoot,
    }),
  );

  // 4. coverage red-effectiveness: force a required suite that does not exist.
  results.push(
    expectRed('coverage', process.execPath, [join(SCRIPT_DIR, 'coverage.mjs')], {
      FEAT017_COVERAGE_REQUIRED_JSON: JSON.stringify([
        { file: 'src/app/auth/licence/does-not-exist.test.tsx', note: 'seeded missing suite' },
      ]),
      FEAT017_COVERAGE_SEARCH_JSON: JSON.stringify([]),
    }),
  );

  // 5. wiring red-effectiveness (missing anchor seam).
  results.push(
    expectRed('wiring', process.execPath, [join(SCRIPT_DIR, 'wiring.mjs')], {
      FEAT017_WIRING_ANCHORS_JSON: JSON.stringify([
        { file: 'src/app/auth/licence/does-not-exist.tsx', anchor: 'never-present' },
      ]),
    }),
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}

const red = results.filter((ok) => !ok).length;
if (red > 0) {
  console.error(`SELF-TEST FAILED (${red}/${results.length} seeded defects not detected)`);
  process.exit(1);
}
console.log(`SELF-TEST OK (${results.length}/${results.length} gates proven red-effective)`);
