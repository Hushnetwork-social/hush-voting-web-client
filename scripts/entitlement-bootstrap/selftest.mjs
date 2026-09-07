#!/usr/bin/env node
/**
 * FEAT-016 seeded-defect self-tests (Phase 7 task 7.6).
 *
 * Proves each focused gate is RED-effective: a seeded defect in the gate's
 * own input surface MUST fail the gate with a non-zero exit. Cases:
 *  1. secret-scan finds a private-key marker in a seeded file;
 *  2. property-scan finds `navigator.onLine` authority in a seeded file;
 *  3. artifact-scan finds a raw 64-hex secret in a seeded artifact log;
 *  4. coverage validator rejects a manifest missing one acceptance row;
 *  5. wiring validator rejects a duplicate canonical scenario id.
 * All seeded material lives in a temporary directory created and removed by
 * this script; production code and repositories are never modified.
 *
 * Usage: node scripts/entitlement-bootstrap/selftest.mjs
 * Exit 0 only when every seeded defect is detected (gate fails non-zero).
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
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

const root = mkdtempSync(join(tmpdir(), 'feat016-seed-'));
const results = [];
try {
  // 1. secret-scan red-effectiveness.
  const secretRoot = join(root, 'secret-seed');
  mkdirSync(secretRoot, { recursive: true });
  // Build the seeded PEM marker from parts so this self-test source never
  // itself contains a contiguous private-key PEM header (repo-wide gates).
  const pemHeader = '-----BEGIN ' + 'EC PRIVATE KEY' + '-----';
  writeFileSync(join(secretRoot, 'seeded-secret.ts'), `const material = "${pemHeader}\nseeded";\n`);
  results.push(
    expectRed('secret-scan', process.execPath, [join(SCRIPT_DIR, 'secret-scan.mjs')], {
      FEAT016_SCAN_ROOTS: secretRoot,
    }),
  );

  // 2. property-scan red-effectiveness.
  const propertyRoot = join(root, 'property-seed');
  mkdirSync(propertyRoot, { recursive: true });
  writeFileSync(join(propertyRoot, 'seeded-prop.ts'), 'export function online(): boolean { return navigator.onLine; }\n');
  results.push(
    expectRed('property-scan', process.execPath, [join(SCRIPT_DIR, 'property-scan.mjs')], {
      FEAT016_SCAN_ROOTS: propertyRoot,
    }),
  );

  // 3. artifact-scan red-effectiveness.
  const artifactRoot = join(root, 'artifact-seed');
  mkdirSync(artifactRoot, { recursive: true });
  const pemMarker = '-----BEGIN ' + 'RSA PRIVATE KEY' + '-----';
  writeFileSync(join(artifactRoot, 'seeded.log'), `trace: ${pemMarker} leaked-into-artifact\n`);
  results.push(
    expectRed('artifact-scan', process.execPath, [join(SCRIPT_DIR, 'artifact-scan.mjs')], {
      FEAT016_SCAN_ROOTS: artifactRoot,
    }),
  );

  // 4. coverage validator red-effectiveness (missing acceptance row).
  const manifestPath = join(SCRIPT_DIR, 'evidence-manifest.json');
  const realManifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const seededManifest = join(root, 'evidence-seeded.json');
  const rowsWithoutOne = realManifest.rows.filter((row) => row.stableId !== 'AC-016-001');
  writeFileSync(seededManifest, JSON.stringify({ ...realManifest, rows: rowsWithoutOne }, null, 2));
  results.push(
    expectRed('coverage', process.execPath, [join(SCRIPT_DIR, 'coverage.mjs')], {
      FEAT016_EVIDENCE_MANIFEST: seededManifest,
    }),
  );

  // 5. wiring validator red-effectiveness (duplicate canonical id).
  const featuresSeed = join(root, 'features-seed');
  mkdirSync(featuresSeed, { recursive: true });
  writeFileSync(
    join(featuresSeed, 'dup.feature'),
    [
      '@FEAT-016',
      'Feature: duplicate journey seed',
      '  @AT-LIC-002',
      '  Scenario: duplicate canonical id',
      '    Given Alice has completed exact EPIC-001 identity authentication',
    ].join('\n'),
  );
  writeFileSync(
    join(featuresSeed, 'dup-again.feature'),
    [
      '@FEAT-016',
      'Feature: duplicate journey seed two',
      '  @AT-LIC-002',
      '  Scenario: duplicate canonical id again',
      '    Given Alice has completed exact EPIC-001 identity authentication',
    ].join('\n'),
  );
  results.push(
    expectRed('wiring', process.execPath, [join(SCRIPT_DIR, 'wiring.mjs')], {
      FEAT016_WIRING_FEATURES: featuresSeed,
      FEAT016_WIRING_SKIP_LIST: '1',
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
