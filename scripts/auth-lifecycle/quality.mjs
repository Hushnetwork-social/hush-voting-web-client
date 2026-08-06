#!/usr/bin/env node
/**
 * FEAT-010 quality aggregate gate (Task 7.7, AC-010-091…100).
 *
 * Aggregates the target-owned gates and evidence admission:
 *  1. coverage ledger (100/100 ACs, 26/26 families) — machine-checked;
 *  2. production exclusion (placeholder/null/mock/unavailable/synthetic/
 *     fallback) — CI fail gate;
 *  3. secret/artifact scan — 0 prohibited findings;
 *  4. external EPIC blocker ledger admission — truthful PASS/FAIL/
 *     NOT_SUPPLIED only, never fabricated;
 *  5. real-platform procedure evidence (Web/Ubuntu/physical Android) —
 *     aggregate PASS/FAIL/NOT_EXECUTED; physical matrices are target-owned
 *     (AC-010-100) and unavailability is recorded, never substituted.
 *
 * Usage: node scripts/auth-lifecycle/quality.mjs
 * Exit 0 only when every owned gate is green and evidence admission passes.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');
const BLOCKER_LEDGER = join(SCRIPT_DIR, 'external-blockers.json');

const gates = [];
function gate(name, ok, detail) {
  gates.push({ name, ok, detail });
  if (!ok) console.error(`  ✘ ${name}: ${detail}`);
  else console.log(`  ✓ ${name}: ${detail}`);
}

function run(label, command, args, cwd = REPO_ROOT) {
  try {
    execFileSync(command, args, { cwd, stdio: 'pipe', encoding: 'utf8' });
    gate(label, true, 'green');
  } catch (error) {
    gate(label, false, `exit ${error.status ?? 1}`);
  }
}

console.log('FEAT-010 quality aggregate');
run('coverage-ledger', 'node', [join(SCRIPT_DIR, 'coverage.mjs')]);
run('production-exclusion', 'node', [join(SCRIPT_DIR, 'production-exclusion.mjs')]);
run('secret-scan', 'node', [join(SCRIPT_DIR, 'secret-scan.mjs')]);

// External EPIC blocker ledger admission (truthful states only).
if (!existsSync(BLOCKER_LEDGER)) {
  gate('external-blocker-ledger', false, 'missing external-blockers.json');
} else {
  try {
    const ledger = JSON.parse(readFileSync(BLOCKER_LEDGER, 'utf8'));
    const entries = ledger.entries ?? [];
    const valid = entries.every(
      (entry) =>
        /^EXT-\d{3}-\d{3}$/.test(entry.id) &&
        typeof entry.owner === 'string' &&
        entry.owner.length > 0 &&
        ['PASS', 'FAIL', 'NOT_SUPPLIED'].includes(entry.state) &&
        typeof entry.releaseImpact === 'string' &&
        entry.releaseImpact.length > 0,
    );
    const fabricated = entries.some((entry) => entry.state === 'PASS' && entry.evidencePath === undefined);
    if (!valid || fabricated) {
      gate('external-blocker-ledger', false, 'invalid or fabricated entry');
    } else {
      gate('external-blocker-ledger', true, `${entries.length} entries truthful`);
    }
  } catch (error) {
    gate('external-blocker-ledger', false, `parse error: ${error.message}`);
  }
}

// Real-platform procedure evidence admission (target-owned).
const platformLedger = join(SCRIPT_DIR, 'platform-evidence.json');
if (!existsSync(platformLedger)) {
  gate('platform-evidence', false, 'missing platform-evidence.json (AC-010-100 target-owned matrices)');
} else {
  try {
    const ledger = JSON.parse(readFileSync(platformLedger, 'utf8'));
    const matrices = ledger.matrices ?? [];
    const valid = matrices.every((m) =>
      ['web', 'ubuntu', 'android-physical'].includes(m.target) &&
      ['PASS', 'FAIL', 'NOT_EXECUTED'].includes(m.result) &&
      typeof m.digests === 'string' &&
      m.digests.length > 0,
    );
    if (!valid) {
      gate('platform-evidence', false, 'invalid matrix entry');
    } else {
      const red = matrices.filter((m) => m.result === 'FAIL').length;
      const notExecuted = matrices.filter((m) => m.result === 'NOT_EXECUTED').length;
      if (red > 0) {
        gate('platform-evidence', false, `${red} matrix FAIL`);
      } else {
        gate('platform-evidence', notExecuted === 0, `web/ubuntu/android recorded (${notExecuted} NOT_EXECUTED)`);
      }
    }
  } catch (error) {
    gate('platform-evidence', false, `parse error: ${error.message}`);
  }
}

const red = gates.filter((g) => !g.ok);
if (red.length > 0) {
  console.error(`QUALITY AGGREGATE FAILED (${red.length}/${gates.length} gates red)`);
  process.exit(1);
}
console.log(`QUALITY AGGREGATE OK (${gates.length}/${gates.length} gates green)`);
