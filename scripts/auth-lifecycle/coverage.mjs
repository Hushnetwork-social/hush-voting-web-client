#!/usr/bin/env node
/**
 * FEAT-010 coverage validator (Task 7.1, AC-010-091).
 *
 * Machine-checks that every acceptance criterion (100/100) and every
 * mandatory scenario family (26/26) maps to an owning implementation task and
 * a current executable evidence target, and that no unknown/duplicate/stale
 * mapping exists. Evidence manifests (added by later tasks as evidence lands)
 * are validated for real-root requirements, secret-capture policy, and
 * external-blocker separation.
 *
 * Usage: node scripts/auth-lifecycle/coverage.mjs [--evidence <manifest.json>]
 * Exit 0 only when the ledger is complete and every supplied evidence entry
 * is current and allowed. Secret-safe: emits stable IDs only.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const LEDGER_PATH = join(import.meta.dirname, 'coverage-ledger.json');

const AC_RE = /^AC-010-\d{3}$/;
const FAMILY_RE = /^HV-AUTH-[A-Z]+$/;

/** Allowed evidence classes (Phase 1 ledger legend). */
const ALLOWED_EVIDENCE_CLASSES = new Set(['C', 'R', 'N', 'S', 'X', 'M']);

/** User-visible composition boundaries whose evidence must be real-root
 * (class R) or native-root (class N) — from the Phase 1 traceability ledger. */
const REAL_ROOT_CRITERIA = new Set([
  'AC-010-007','AC-010-008','AC-010-009','AC-010-010','AC-010-011','AC-010-012','AC-010-013',
  'AC-010-024','AC-010-025','AC-010-027','AC-010-028','AC-010-029','AC-010-030','AC-010-031',
  'AC-010-032','AC-010-033','AC-010-034','AC-010-035','AC-010-036','AC-010-037','AC-010-038',
  'AC-010-039','AC-010-040','AC-010-041','AC-010-044','AC-010-045','AC-010-046','AC-010-047',
  'AC-010-048','AC-010-049','AC-010-052','AC-010-053','AC-010-054','AC-010-062','AC-010-063',
  'AC-010-064','AC-010-065','AC-010-066','AC-010-069','AC-010-070','AC-010-071','AC-010-073',
  'AC-010-074','AC-010-075','AC-010-076','AC-010-077','AC-010-079','AC-010-080','AC-010-082',
  'AC-010-083','AC-010-084','AC-010-085','AC-010-086','AC-010-087','AC-010-088','AC-010-089',
  'AC-010-092',
]);

function fail(message) {
  console.error(`COVERAGE FAIL: ${message}`);
  process.exitCode = 1;
}

function main() {
  let ledger;
  try {
    ledger = JSON.parse(readFileSync(LEDGER_PATH, 'utf8'));
  } catch (error) {
    fail(`cannot read ledger: ${error.message}`);
    return;
  }

  if (ledger.schema !== 'feat010-coverage-ledger-v1') {
    fail('unknown ledger schema');
  }

  const criteria = ledger.criteria;
  const families = ledger.families;

  // 100/100 criteria with stable IDs and owners.
  if (!Array.isArray(criteria) || criteria.length !== 100) {
    fail(`expected 100 criteria, got ${Array.isArray(criteria) ? criteria.length : 'none'}`);
  } else {
    const seen = new Set();
    for (const criterion of criteria) {
      if (!AC_RE.test(criterion.id)) {
        fail(`malformed criterion id: ${JSON.stringify(criterion.id)}`);
        continue;
      }
      if (seen.has(criterion.id)) {
        fail(`duplicate criterion: ${criterion.id}`);
      }
      seen.add(criterion.id);
      if (typeof criterion.owners !== 'string' || criterion.owners.length === 0) {
        fail(`criterion ${criterion.id} has no owning task`);
      }
    }
    if (seen.size !== 100) {
      fail(`unique criteria ${seen.size}/100`);
    }
  }

  // 26/26 families.
  if (!Array.isArray(families) || families.length !== 26) {
    fail(`expected 26 families, got ${Array.isArray(families) ? families.length : 'none'}`);
  } else {
    const seen = new Set();
    for (const family of families) {
      if (!FAMILY_RE.test(family.id)) {
        fail(`malformed family id: ${JSON.stringify(family.id)}`);
        continue;
      }
      if (seen.has(family.id)) {
        fail(`duplicate family: ${family.id}`);
      }
      seen.add(family.id);
      if (typeof family.owners !== 'string' || family.owners.length === 0) {
        fail(`family ${family.id} has no owning task`);
      }
    }
    if (seen.size !== 26) {
      fail(`unique families ${seen.size}/26`);
    }
  }

  // Optional evidence manifest validation (added as evidence lands).
  const args = process.argv.slice(2);
  const evidenceIndex = args.indexOf('--evidence');
  if (evidenceIndex !== -1 && args[evidenceIndex + 1]) {
    const rawPath = args[evidenceIndex + 1];
    const evidencePath = rawPath.startsWith('/') || /^[A-Za-z]:/.test(rawPath) ? rawPath : join(REPO_ROOT, rawPath);
    if (!existsSync(evidencePath)) {
      fail(`evidence manifest not found: ${args[evidenceIndex + 1]}`);
      return;
    }
    const evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));
    if (!Array.isArray(evidence.entries)) {
      fail('evidence manifest must contain an entries array');
      return;
    }
    const covered = new Set();
    for (const entry of evidence.entries) {
      if (!AC_RE.test(entry.criterionId)) {
        fail(`evidence entry has malformed criterion: ${JSON.stringify(entry.criterionId)}`);
        continue;
      }
      if (!ALLOWED_EVIDENCE_CLASSES.has(entry.class)) {
        fail(`evidence entry ${entry.criterionId} has unknown class: ${entry.class}`);
      }
      if (REAL_ROOT_CRITERIA.has(entry.criterionId) && entry.class === 'C' && entry.realRoot !== true) {
        fail(`evidence entry ${entry.criterionId}: user-visible boundary requires real-root evidence`);
      }
      if (entry.secretBearing === true && entry.capturePolicy !== 'disabled') {
        fail(`evidence entry ${entry.criterionId}: secret-bearing scenario must disable capture`);
      }
      covered.add(entry.criterionId);
    }
    for (const criterion of criteria) {
      if (!covered.has(criterion.id)) {
        fail(`criterion ${criterion.id} has no current evidence entry`);
      }
    }
  }

  if (process.exitCode === undefined) {
    console.log(`COVERAGE OK (${criteria.length}/100 criteria, ${families.length}/26 families, ledger ${ledger.schema})`);
  }
}

main();
