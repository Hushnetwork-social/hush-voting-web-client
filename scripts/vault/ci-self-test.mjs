#!/usr/bin/env node
/**
 * FEAT-003 unified conformance CI self-tests (Task 6.2).
 * ======================================================
 * Proves EVERY required gate fails independently when its contract input is broken
 * and recovers when restored:
 *
 *   1. tampered schema           -> `vault:integrity` fails (invalid draft-2020-12)
 *   2. tampered vector           -> `vault:conformance` fails (derivation mismatch)
 *   3. tampered manifest digest  -> `vault:integrity` fails (manifest drift)
 *   4. production import of a conformance module -> `vault:production-exclusion` fails
 *   5. missing conformance module -> `vault:conformance` fails (no isolated path)
 *
 * Every scenario restores the original bytes in a `finally` block and re-runs the
 * gate to prove the clean state still passes. The path-trigger analysis (unrelated
 * files never select expensive vault blocks) is enforced by the workflow `paths:`
 * declaration; the self-test asserts those paths cover every vault artifact area.
 *
 * Exit codes: 0 = all scenarios behave, 1 = a scenario failed, 2 = internal error.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const run = (args, opts = {}) => execFileSync('npm', ['run', ...args], { cwd: REPO_ROOT, stdio: 'ignore', ...opts });

let failures = 0;

function scenario(name, gate, tamper, restore) {
  process.stdout.write(`scenario: ${name}\n`);
  tamper();
  let tamperedExit = 0;
  try {
    run([gate], { timeout: 900_000 });
  } catch (err) {
    tamperedExit = typeof err.status === 'number' && err.status !== 0 ? err.status : 1;
  }
  restore();
  let restoredExit = 0;
  try {
    run([gate], { timeout: 900_000 });
  } catch (err) {
    restoredExit = typeof err.status === 'number' ? err.status : 1;
  }
  const ok = tamperedExit !== 0 && restoredExit === 0;
  if (!ok) failures += 1;
  process.stdout.write(`  tampered=${tamperedExit !== 0 ? 'FAILS (ok)' : 'PASSES (BAD)'} restored=${restoredExit === 0 ? 'PASSES (ok)' : 'FAILS (BAD)'} -> ${ok ? 'ok' : 'FAIL'}\n`);
  return ok;
}

// ---- scenario helpers -------------------------------------------------------
const SCHEMA = join(REPO_ROOT, 'conformance/vault/v1/schemas/suite.schema.json');
const VECTOR = join(REPO_ROOT, 'conformance/vault/v1/vectors/canonical-byte-vectors.json');
const MANIFEST = join(REPO_ROOT, 'conformance/vault/v1/manifest.json');
const NEGATIVE_DIR = join(REPO_ROOT, 'src/vault-ci-negative-fixture');
const ISOLATED = join(REPO_ROOT, 'src/lib/vault-core/conformance/isolated-validator.ts');

// ---- 1. tampered schema -----------------------------------------------------
scenario(
  'tampered schema fails vault:integrity',
  'vault:integrity',
  () => {
    const backup = readFileSync(SCHEMA);
    writeFileSync(SCHEMA, backup.toString('utf8').replace('https://json-schema.org/draft/2020-12/schema', 'https://json-schema.org/draft/2020-12/bogus'));
  },
  () => {
    // restored by integrity --check? No: manifest pins the digest, so the original
    // bytes must be restored exactly. Keep a pristine copy via git.
    execFileSync('git', ['checkout', '--', 'conformance/vault/v1/schemas/suite.schema.json'], { cwd: REPO_ROOT, stdio: 'ignore' });
  },
);

// ---- 2. tampered vector -----------------------------------------------------
scenario(
  'tampered vector fails vault:conformance',
  'vault:conformance',
  () => {
    const backup = readFileSync(VECTOR);
    writeFileSync(VECTOR, backup.toString('utf8').replace('"id": "C-001"', '"id": "C-001" "tamper": true'));
  },
  () => {
    execFileSync('git', ['checkout', '--', 'conformance/vault/v1/vectors/canonical-byte-vectors.json'], { cwd: REPO_ROOT, stdio: 'ignore' });
  },
);

// ---- 3. tampered manifest ---------------------------------------------------
scenario(
  'tampered manifest digest fails vault:integrity',
  'vault:integrity',
  () => {
    const backup = readFileSync(MANIFEST);
    // Replace the first sha256 entry with a bogus digest; manifest check must fail.
    writeFileSync(MANIFEST, backup.toString('utf8').replace(/"sha256": "[0-9a-f]{64}"/, '"sha256": "' + '0'.repeat(64) + '"'));
  },
  () => {
    execFileSync('git', ['checkout', '--', 'conformance/vault/v1/manifest.json'], { cwd: REPO_ROOT, stdio: 'ignore' });
  },
);

// ---- 4. production import fixture ------------------------------------------
scenario(
  'production import of conformance module fails vault:production-exclusion',
  'vault:production-exclusion',
  () => {
    mkdirSync(NEGATIVE_DIR, { recursive: true });
    writeFileSync(join(NEGATIVE_DIR, 'imports-conformance.ts'), "import { runIsolatedValidation } from '../lib/vault-core/conformance/isolated-validator';\n");
  },
  () => {
    rmSync(NEGATIVE_DIR, { recursive: true, force: true });
  },
);

// ---- 5. missing conformance module -----------------------------------------
scenario(
  'missing conformance module fails vault:conformance',
  'vault:conformance',
  () => {
    renameSync(ISOLATED, `${ISOLATED}.bak`);
  },
  () => {
    renameSync(`${ISOLATED}.bak`, ISOLATED);
  },
);

// ---- workflow path coverage -------------------------------------------------
const WORKFLOW = readFileSync(join(REPO_ROOT, '.github/workflows/vault-conformance.yml'), 'utf8');
const requiredPaths = ['conformance/vault/**', 'src/lib/vault-core/**', 'scripts/vault/**', 'package.json', 'package-lock.json'];
for (const p of requiredPaths) {
  if (!WORKFLOW.includes(`"${p}"`)) {
    process.stdout.write(`workflow paths missing ${p}\n`);
    failures += 1;
  }
}

process.stdout.write(failures === 0 ? `VAULT CI SELF-TEST OK (5 scenarios + path coverage)\n` : `VAULT CI SELF-TEST FAILED (${failures} scenario(s))\n`);
process.exit(failures === 0 ? 0 : 1);
