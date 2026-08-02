#!/usr/bin/env node
/**
 * FEAT-003 unified vault CI orchestration (Task 6.1).
 * =====================================================
 * Runs every vault contract gate in a deterministic order with bounded timeouts:
 *   1. lint, 2. typecheck, 3. unit tests, 4. corpus integrity,
 *   5. corpus node:test suites, 6. primary + isolated conformance,
 *   7. identity (FEAT-001) regression, 8. web + static builds (skippable),
 *   9. auth artifact audit, 10. vault production-exclusion scan.
 *
 * A gate that exits non-zero fails the run with a stable sanitized diagnostic naming
 * the stage only (no command output is echoed). On success the script writes a
 * deterministic digest-only summary to `conformance/reports/vault-ci-summary.json`
 * (revision + manifest digest + per-stage pass/duration; no credential values).
 *
 * Exit codes: 0 = all gates pass, 1 = a gate failed, 2 = internal error.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const SUMMARY_PATH = join(REPO_ROOT, 'conformance', 'reports', 'vault-ci-summary.json');

const GATES = [
  { name: 'lint', script: 'lint', timeoutMs: 300_000, skip: false },
  { name: 'typecheck', script: 'typecheck', timeoutMs: 300_000, skip: false },
  { name: 'unit-tests', script: 'test:unit', timeoutMs: 900_000, skip: false },
  { name: 'corpus-integrity', script: 'vault:integrity', timeoutMs: 180_000, skip: false },
  { name: 'corpus-node-tests', script: 'vault:integrity:tests', timeoutMs: 180_000, skip: false },
  { name: 'vault-conformance', script: 'vault:conformance', timeoutMs: 900_000, skip: false },
  { name: 'identity-conformance', script: 'identity:conformance', timeoutMs: 300_000, skip: false },
  { name: 'build-web', script: 'build:web', timeoutMs: 1_200_000, skip: false },
  { name: 'build-static', script: 'build:static', timeoutMs: 1_200_000, skip: false },
  { name: 'auth-audit', script: 'auth:audit', timeoutMs: 180_000, skip: false },
  { name: 'production-exclusion', script: 'vault:production-exclusion', timeoutMs: 300_000, skip: false },
  { name: 'adversarial', script: 'vault:test:adversarial', timeoutMs: 900_000, skip: false },
  { name: 'security-gates', script: 'vault:security-gates', timeoutMs: 300_000, skip: false },
  { name: 'archive', script: 'vault:archive', timeoutMs: 180_000, skip: false },
  { name: 'archive-check', script: 'vault:archive:check', timeoutMs: 180_000, skip: false },
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

function main() {
  const args = new Set(process.argv.slice(2));
  const skipBuilds = args.has('--skip-builds');
  const gateList = GATES.filter((g) => !(skipBuilds && (g.name === 'build-web' || g.name === 'build-static')));
  const results = [];
  const failures = [];
  for (const gate of gateList) {
    const started = Date.now();
    let ok = true;
    try {
      runNpmScript(gate.script, gate.timeoutMs);
    } catch {
      ok = false;
      failures.push(gate.name);
    }
    results.push({ name: gate.name, ok, durationMs: Date.now() - started });
    // Fail fast after the first failure to keep CI cycles bounded.
    if (!ok) break;
  }
  const passed = failures.length === 0;
  const summary = {
    contract: 'FEAT-003 vault CI contract v1',
    revision: gitRevision(),
    manifestSha256: manifestSha256(),
    corpusVersion: '1.0.0',
    passed,
    stages: results,
    failures,
  };
  mkdirSync(join(REPO_ROOT, 'conformance', 'reports'), { recursive: true });
  writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2) + '\n');
  process.stdout.write(
    passed
      ? `VAULT CI OK (${results.length} stages, revision ${summary.revision.slice(0, 12)}, manifest ${summary.manifestSha256.slice(0, 12)})\n`
      : `VAULT CI FAILED at stage: ${failures[0]}\n`,
  );
  process.exit(passed ? 0 : 1);
}

try {
  main();
} catch (err) {
  process.stderr.write(`VAULT CI INTERNAL ERROR: ${err.message}\n`);
  process.exit(2);
}
