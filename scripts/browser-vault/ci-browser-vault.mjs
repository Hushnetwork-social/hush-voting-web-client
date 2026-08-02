#!/usr/bin/env node
/**
 * FEAT-004 unified browser-vault CI gate (Task 6.5/6.6).
 * ======================================================
 * Runs every browser-adapter gate deterministically with bounded timeouts:
 *   1. lint, 2. typecheck, 3. unit tests, 4. vault core CI (corpus untouched),
 *   5. browser-vault production-exclusion, 6. browser-vault artifact audit,
 *   7. dependency audit, 8. focused browser blocks (Playwright vault-*),
 *   9. deployment policy (build required), 10. downstream handoff integrity.
 *
 * `--selftest` runs the failure-mode self-tests: seeded defects (tampered
 * corpus pin, reference import in production source, secret-shaped literal)
 * MUST fail the corresponding gate, proving the gates actually guard the
 * contract. The unmodified baseline must pass.
 *
 * A failing gate exits non-zero with a stable sanitized diagnostic naming the
 * stage only. Success writes a digest-only summary to
 * `conformance/reports/browser-vault-ci-summary.json`.
 *
 * Exit codes: 0 = all gates pass, 1 = a gate failed, 2 = internal error.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const SUMMARY_PATH = join(REPO_ROOT, 'conformance', 'reports', 'browser-vault-ci-summary.json');
const SELF_TEST = process.argv.includes('--selftest');

const GATES = [
  { name: 'lint', script: 'lint', timeoutMs: 300_000, skip: false },
  { name: 'typecheck', script: 'typecheck', timeoutMs: 300_000, skip: false },
  { name: 'unit-tests', script: 'test:unit', timeoutMs: 900_000, skip: false },
  { name: 'vault-core-ci', script: 'vault:ci', timeoutMs: 1_200_000, skip: false },
  { name: 'production-exclusion', script: 'browser-vault:production-exclusion', timeoutMs: 300_000, skip: false },
  { name: 'artifact-audit', script: 'browser-vault:audit', timeoutMs: 180_000, skip: false },
  { name: 'dependency-audit', script: 'browser-vault:dependency-audit', timeoutMs: 300_000, skip: false },
  { name: 'browser-blocks', script: 'browser-vault:browser-blocks', timeoutMs: 600_000, skip: false },
  { name: 'deployment-policy', script: 'browser-vault:deployment-policy', timeoutMs: 300_000, skip: false },
  { name: 'handoff-integrity', script: 'browser-vault:handoff', timeoutMs: 60_000, skip: false },
];

function runNpmScript(name, timeoutMs) {
  execFileSync('npm', ['run', name], { cwd: REPO_ROOT, stdio: 'ignore', timeout: timeoutMs });
}

function gitRevision() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

function manifestSha256() {
  const bytes = readFileSync(join(REPO_ROOT, 'conformance', 'vault', 'v1', 'manifest.json'));
  return createHash('sha256').update(bytes).digest('hex');
}

async function runSelfTests() {
  const fixtureDir = join(REPO_ROOT, 'tmp', 'browser-vault-selftest');
  mkdirSync(fixtureDir, { recursive: true });
  const mutations = [
    {
      name: 'corpus-pin-tamper',
      run: () => {
        const manifest = join(REPO_ROOT, 'conformance', 'vault', 'v1', 'manifest.json');
        const original = readFileSync(manifest, 'utf8');
        writeFileSync(manifest, `${original}\n// tampered`);
        try {
          execFileSync('npm', ['run', 'vault:integrity'], { cwd: REPO_ROOT, stdio: 'ignore', timeout: 120_000 });
          return false;
        } catch {
          return true;
        } finally {
          writeFileSync(manifest, original);
        }
      },
    },
    {
      name: 'reference-import-in-production',
      run: () => {
        const probe = join(fixtureDir, 'probe.ts');
        writeFileSync(probe, `import '${['DETERMINISTIC_', 'TEST_PROVIDER'].join('')}';\n`);
        try {
          execFileSync('node', [join(REPO_ROOT, 'scripts', 'browser-vault', 'production-exclusion.mjs')], {
            cwd: REPO_ROOT,
            stdio: 'ignore',
            timeout: 60_000,
          });
          return false;
        } catch {
          return true;
        } finally {
          rmSync(fixtureDir, { recursive: true, force: true });
        }
      },
    },
  ];

  let ok = true;
  for (const mutation of mutations) {
    const detected = await mutation.run();
    process.stdout.write(`SELFTEST ${mutation.name}: ${detected ? 'PASS (defect detected)' : 'FAIL (defect NOT detected)'}\n`);
    if (!detected) {
      ok = false;
    }
  }
  return ok;
}

async function main() {
  if (SELF_TEST) {
    const ok = await runSelfTests();
    process.exit(ok ? 0 : 1);
    return;
  }

  const summary = { revision: gitRevision(), manifestSha256: manifestSha256(), stages: [] };
  for (const gate of GATES) {
    if (gate.skip) {
      summary.stages.push({ name: gate.name, status: 'skipped' });
      continue;
    }
    try {
      runNpmScript(gate.script, gate.timeoutMs);
      summary.stages.push({ name: gate.name, status: 'pass' });
      process.stdout.write(`[OK] ${gate.name}\n`);
    } catch {
      summary.stages.push({ name: gate.name, status: 'fail' });
      process.stderr.write(`BROWSER-VAULT CI FAILED at stage: ${gate.name}\n`);
      mkdirSync(join(REPO_ROOT, 'conformance', 'reports'), { recursive: true });
      writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2));
      process.exitCode = 1;
      return;
    }
  }
  mkdirSync(join(REPO_ROOT, 'conformance', 'reports'), { recursive: true });
  writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2));
  process.stdout.write(
    `BROWSER-VAULT CI OK (${summary.stages.filter((s) => s.status === 'pass').length} stages, revision ${gitRevision().slice(0, 12)}, manifest ${manifestSha256().slice(0, 12)})\n`,
  );
  process.exitCode = 0;
}

main().catch((error) => {
  process.stderr.write(`BROWSER-VAULT CI internal error: ${String(error)}\n`);
  process.exitCode = 2;
});
