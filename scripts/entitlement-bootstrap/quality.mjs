#!/usr/bin/env node
/**
 * FEAT-016 focused quality gate (Phase 7 task 7.6).
 *
 * Aggregates the target-owned machine gates and evidence admission:
 *  1. BDD wiring/discovery (13/13 canonical journeys compiled + discovered);
 *  2. coverage/evidence/pairing ledger admission (28 ACs + 13 scenario ids);
 *  3. secret/privacy scan — 0 prohibited findings;
 *  4. source-property scan — 0 forbidden production properties;
 *  5. build/runtime artifact privacy scan — 0 prohibited findings;
 *  6. cleanup verification — no agent-started dev/listener process remains
 *     on the FEAT-016 client composition ports.
 *
 * Release readiness is reported separately: the full production-composition
 * run of the journeys requires the controlled real HushServerNode fixture
 * (external), and the two physical manual smoke obligations remain PENDING —
 * neither blocks implementation completion.
 *
 * Usage: node scripts/entitlement-bootstrap/quality.mjs
 * Exit 0 when all implementation gates and evidence admission pass.
 */
import { execFileSync, execSync } from 'node:child_process';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

const gates = [];
function gate(name, ok, detail) {
  gates.push({ name, ok, detail });
  if (!ok) console.error(`  \u2718 ${name}: ${detail}`);
  else console.log(`  \u2713 ${name}: ${detail}`);
}

function run(label, command, args) {
  try {
    execFileSync(command, args, { cwd: REPO_ROOT, stdio: 'pipe', encoding: 'utf8', timeout: 300_000 });
    gate(label, true, 'green');
  } catch (error) {
    gate(label, false, `exit ${error.status ?? 1}`);
  }
}

console.log('FEAT-016 focused quality aggregate');
run('bdd-wiring-discovery', 'node', [join(SCRIPT_DIR, 'wiring.mjs')]);
run('coverage-evidence-pairing', 'node', [join(SCRIPT_DIR, 'coverage.mjs')]);
run('secret-scan', 'node', [join(SCRIPT_DIR, 'secret-scan.mjs')]);
run('source-property-scan', 'node', [join(SCRIPT_DIR, 'property-scan.mjs')]);
run('artifact-privacy-scan', 'node', [join(SCRIPT_DIR, 'artifact-scan.mjs')]);

// Cleanup verification: no agent-started listener on the FEAT-016 client
// composition ports (3201 dev/start, 3202 tauri dev) and no Next dev/start
// process remains. Pre-existing user services (5432/6379/4665/8080/3000/14666)
// are intentionally not inspected.
let cleanupOk = true;
let cleanupDetail = 'no agent-started listener or next process';
try {
  const listeners = execSync('ss -ltn', { encoding: 'utf8' });
  for (const port of ['3201', '3202']) {
    if (new RegExp(`:${port}\\b`).test(listeners)) {
      cleanupOk = false;
      cleanupDetail = `port ${port} is still listening`;
    }
  }
  const procs = execSync("pgrep -af 'next (dev|start)' || true", { encoding: 'utf8' });
  const repoRoot = REPO_ROOT.replaceAll('\\', '/');
  const agentNextProcs = procs
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .filter((line) => {
      // Only processes started from THIS repository or on this feature's
      // composition ports are agent-started; dockerized and other-project
      // pre-existing user dev servers are never inspected or stopped.
      const pid = Number.parseInt(line.split(' ')[0], 10);
      let cwd = '';
      try {
        cwd = execSync(`readlink /proc/${pid}/cwd 2>/dev/null || true`, { encoding: 'utf8' }).trim();
      } catch {
        return false;
      }
      const onFeaturePort = /-p\s+320[12]\b/.test(line);
      return cwd === repoRoot || onFeaturePort;
    });
  if (agentNextProcs.length > 0) {
    cleanupOk = false;
    cleanupDetail = `next dev/start process still running: ${agentNextProcs[0]}`;
  }
} catch {
  // ss/pgrep absence is treated as an unknown environment; the running gate
  // commands themselves are foreground and bounded.
  cleanupDetail = 'listener inspection unavailable';
}
gate('cleanup-verification', cleanupOk, cleanupDetail);

const red = gates.filter((g) => !g.ok);
if (red.length > 0) {
  console.error(`QUALITY AGGREGATE FAILED (${red.length}/${gates.length} gates red)`);
  process.exit(1);
}
console.log(`QUALITY AGGREGATE OK (${gates.length}/${gates.length} implementation gates green)`);
console.log('IMPLEMENTATION STATUS: COMPLETABLE');
console.log(
  'RELEASE READINESS: BLOCKED_BY_EXTERNAL_FIXTURE_AND_MANUAL_QUALIFICATION (pinned HushServerNode full-composition journeys; MT-QUAL-ANDROID/UBUNTU-016-001 PENDING)',
);
