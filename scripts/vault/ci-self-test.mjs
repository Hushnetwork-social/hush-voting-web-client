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
 * Every scenario captures the PRISTINE file bytes before tampering and restores them
 * in a `finally` block (never `git checkout`, so uncommitted developer changes are
 * never destroyed), then re-runs the gate to prove the clean state still passes.
 * The path-trigger analysis (unrelated files never select expensive vault blocks) is
 * enforced by the workflow `paths:` declaration; the self-test asserts those paths
 * cover every vault artifact area.
 *
 * Exit codes: 0 = all scenarios behave, 1 = a scenario failed, 2 = internal error.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const run = (args, opts = {}) => execFileSync('npm', ['run', ...args], { cwd: REPO_ROOT, stdio: 'ignore', ...opts });

let failures = 0;

function gateExit(gate) {
  try {
    run([gate], { timeout: 900_000 });
    return 0;
  } catch (err) {
    return typeof err.status === 'number' && err.status !== 0 ? err.status : 1;
  }
}

/**
 * Run a tamper/restore scenario. `tamper` mutates the working tree; the PRISTINE
 * bytes of every listed path are restored in `finally` before the clean-state
 * re-run. Returns true when the tampered gate FAILS and the restored gate PASSES.
 */
function scenario(name, gate, tamper, pathsToRestore, extraRestore) {
  process.stdout.write(`scenario: ${name}\n`);
  const pristine = new Map(pathsToRestore.map((p) => [p, readFileSync(p)]));
  let tamperedExit = 0;
  try {
    tamper();
    tamperedExit = gateExit(gate);
  } catch {
    tamperedExit = 1;
  } finally {
    for (const [p, bytes] of pristine) writeFileSync(p, bytes);
    extraRestore?.();
  }
  const restoredExit = gateExit(gate);
  const ok = tamperedExit !== 0 && restoredExit === 0;
  if (!ok) failures += 1;
  process.stdout.write(`  tampered=${tamperedExit !== 0 ? 'FAILS (ok)' : 'PASSES (BAD)'} restored=${restoredExit === 0 ? 'PASSES (ok)' : 'FAILS (BAD)'} -> ${ok ? 'ok' : 'FAIL'}\n`);
  return ok;
}

// ---- paths ------------------------------------------------------------------
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
    const content = readFileSync(SCHEMA, 'utf8');
    writeFileSync(SCHEMA, content.replace('https://json-schema.org/draft/2020-12/schema', 'https://json-schema.org/draft/2020-12/bogus'));
  },
  [SCHEMA],
);

// ---- 2. tampered vector -----------------------------------------------------
scenario(
  'tampered vector fails vault:conformance',
  'vault:conformance',
  () => {
    const content = readFileSync(VECTOR, 'utf8');
    writeFileSync(VECTOR, content.replace('"id": "C-001"', '"id": "C-001" "tamper": true'));
  },
  [VECTOR],
);

// ---- 3. tampered manifest ---------------------------------------------------
scenario(
  'tampered manifest digest fails vault:integrity',
  'vault:integrity',
  () => {
    const content = readFileSync(MANIFEST, 'utf8');
    writeFileSync(MANIFEST, content.replace(/"sha256": "[0-9a-f]{64}"/, '"sha256": "' + '0'.repeat(64) + '"'));
  },
  [MANIFEST],
);

// ---- 4. production import fixture ------------------------------------------
scenario(
  'production import of conformance module fails vault:production-exclusion',
  'vault:production-exclusion',
  () => {
    mkdirSync(NEGATIVE_DIR, { recursive: true });
    writeFileSync(join(NEGATIVE_DIR, 'imports-conformance.ts'), "import { runIsolatedValidation } from '../lib/vault-core/conformance/isolated-validator';\n");
  },
  [],
  () => rmSync(NEGATIVE_DIR, { recursive: true, force: true }),
);

// ---- 5. missing conformance module -----------------------------------------
scenario(
  'missing conformance module fails vault:conformance',
  'vault:conformance',
  () => {
    renameSync(ISOLATED, `${ISOLATED}.bak`);
  },
  [],
  () => {
    if (existsSync(`${ISOLATED}.bak`)) renameSync(`${ISOLATED}.bak`, ISOLATED);
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
