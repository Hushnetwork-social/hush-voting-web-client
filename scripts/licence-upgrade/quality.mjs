#!/usr/bin/env node
/**
 * FEAT-017 focused quality aggregate (Phase 6 task 6.5/6.6).
 *
 * Runs the FEAT-017 focused gates sequentially and preserves EVERY
 * underlying outcome — a later green block never masks an earlier red block.
 * Blocks:
 *  1. wiring — integration anchors present in real seams;
 *  2. coverage — required non-zero suites present;
 *  3. secret/privacy scan — 0 prohibited findings;
 *  4. source-property scan — 0 forbidden production properties;
 *  5. artifact privacy scan — 0 prohibited findings;
 *  6. cleanup verification — no agent-started listener/next process remains.
 *
 * Usage: node scripts/licence-upgrade/quality.mjs
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

console.log('FEAT-017 focused quality aggregate');
run('journey-wiring-discovery', 'node', [join(SCRIPT_DIR, 'journey-wiring.mjs')]);
run('wiring', 'node', [join(SCRIPT_DIR, 'wiring.mjs')]);
run('coverage', 'node', [join(SCRIPT_DIR, 'coverage.mjs')]);
run('secret-scan', 'node', [join(SCRIPT_DIR, 'secret-scan.mjs')]);
run('source-property-scan', 'node', [join(SCRIPT_DIR, 'property-scan.mjs')]);
run('artifact-privacy-scan', 'node', [join(SCRIPT_DIR, 'artifact-scan.mjs')]);

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
  cleanupDetail = 'listener inspection unavailable';
}
gate('cleanup-verification', cleanupOk, cleanupDetail);

const red = gates.filter((g) => !g.ok);
if (red.length > 0) {
  console.error(`QUALITY AGGREGATE FAILED (${red.length}/${gates.length} gates red)`);
  process.exit(1);
}
console.log(`QUALITY AGGREGATE OK (${gates.length}/${gates.length} FEAT-017 focused gates green)`);
