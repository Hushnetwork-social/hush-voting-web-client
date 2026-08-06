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
 *     schema and truthfulness admission for PASS/FAIL/NOT_EXECUTED. Physical
 *     execution is mandatory Manual TestPack release-qualification evidence,
 *     but its absence does not block implementation completion.
 *
 * Usage: node scripts/auth-lifecycle/quality.mjs
 * Exit 0 when implementation gates and evidence admission pass. Release
 * readiness is reported independently and may remain blocked.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');
const BLOCKER_LEDGER = process.env.FEAT010_EXTERNAL_BLOCKER_LEDGER ?? join(SCRIPT_DIR, 'external-blockers.json');

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

// Real-platform Manual TestPack evidence admission. The implementation gate
// validates that the ledger is complete and truthful; it does not turn an
// unavailable physical target into implementation failure authority.
const platformLedger = process.env.FEAT010_PLATFORM_EVIDENCE_LEDGER ?? join(SCRIPT_DIR, 'platform-evidence.json');
let releaseReadiness = 'BLOCKED_BY_MANUAL_QUALIFICATION';
if (!existsSync(platformLedger)) {
  gate('platform-evidence-admission', false, 'missing platform-evidence.json');
} else {
  try {
    const ledger = JSON.parse(readFileSync(platformLedger, 'utf8'));
    const matrices = ledger.matrices ?? [];
    const expectedTargets = ['web', 'ubuntu', 'android-physical'];
    const targets = new Set(matrices.map((m) => m.target));
    const valid = matrices.length === expectedTargets.length &&
      expectedTargets.every((target) => targets.has(target)) &&
      matrices.every((m) =>
        expectedTargets.includes(m.target) &&
        ['PASS', 'FAIL', 'NOT_EXECUTED'].includes(m.result) &&
        typeof m.digests === 'string' &&
        m.digests.length > 0 &&
        typeof m.note === 'string' &&
        m.note.length > 0,
      );
    if (!valid) {
      gate('platform-evidence-admission', false, 'invalid, incomplete, or duplicate matrix entry');
    } else {
      const failed = matrices.filter((m) => m.result === 'FAIL').length;
      const notExecuted = matrices.filter((m) => m.result === 'NOT_EXECUTED').length;
      releaseReadiness = failed === 0 && notExecuted === 0
        ? 'READY'
        : 'BLOCKED_BY_MANUAL_QUALIFICATION';
      gate(
        'platform-evidence-admission',
        true,
        `truthful (${failed} FAIL, ${notExecuted} NOT_EXECUTED); Release Readiness: ${releaseReadiness}`,
      );
    }
  } catch (error) {
    gate('platform-evidence-admission', false, `parse error: ${error.message}`);
  }
}

const red = gates.filter((g) => !g.ok);
if (red.length > 0) {
  console.error(`QUALITY AGGREGATE FAILED (${red.length}/${gates.length} gates red)`);
  process.exit(1);
}
console.log(`QUALITY AGGREGATE OK (${gates.length}/${gates.length} implementation gates green)`);
console.log(`IMPLEMENTATION STATUS: COMPLETABLE`);
console.log(`RELEASE READINESS: ${releaseReadiness}`);
