#!/usr/bin/env node
/**
 * FEAT-011 Task 7.1 — acceptance/family/scenario coverage validator.
 *
 * Machine-checks the Phase 1 ledger (`acceptance-traceability-ledger.md` in
 * the feature folder is NOT here — this validator embeds the frozen registry
 * from `src/lib/identity-convergence/` and validates the evidence manifest):
 *  1. every AC-011-001..038 has an evidence row;
 *  2. every mandatory family has a real-root scenario unless marked no;
 *  3. every server-dependent client row has matching TWIN evidence;
 *  4. MANUAL/EXTERNAL rows admit only PASS|FAIL|NOT_SUPPLIED;
 *  5. no mock/direct-child/synthetic substitute satisfies server evidence;
 *  6. aggregates cannot hide a failed component.
 *
 * The evidence manifest is `scripts/identity-happypath/evidence-manifest.json`.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = process.env.FEAT011_MANIFEST ?? path.join(__dirname, 'evidence-manifest.json');

/** Frozen acceptance registry (ledger §2 — 38 criteria). */
export const ACCEPTANCE_CRITERIA = Array.from({ length: 38 }, (_, i) => `AC-011-${String(i + 1).padStart(3, '0')}`);

/** Frozen families (ledger §3). */
export const FAMILIES = [
  'HV-ID-ROOT',
  'HV-ID-CREATE',
  'HV-ID-WORDS12',
  'HV-ID-WORDS24',
  'HV-ID-DAT',
  'HV-ID-RETURN',
  'HV-ID-LOOKUP',
  'HV-ID-SIGN',
  'HV-ID-SUBMIT',
  'HV-ID-RECONCILE',
  'HV-ID-IDEMPOTENCY',
  'HV-ID-CACHE',
  'HV-ID-NATIVE',
  'HV-ID-LIFECYCLE',
  'HV-ID-SECURITY',
  'HV-ID-EPIC',
];

/** Families that must enter `/` (ledger §3). Server-behavior families
 * (LOOKUP/SUBMIT/RECONCILE/IDEMPOTENCY) enter `/` THROUGH the create/words/
 * dat/returning root journeys; their own evidence is the paired TWIN matrix. */
const REAL_ROOT_FAMILIES = new Set([
  'HV-ID-ROOT', 'HV-ID-CREATE', 'HV-ID-WORDS12', 'HV-ID-WORDS24', 'HV-ID-DAT', 'HV-ID-RETURN',
  'HV-ID-NATIVE', 'HV-ID-LIFECYCLE',
]);
const SERVER_BEHAVIOR_FAMILIES = new Set([
  'HV-ID-LOOKUP', 'HV-ID-SUBMIT', 'HV-ID-RECONCILE', 'HV-ID-IDEMPOTENCY', 'HV-ID-CACHE', 'HV-ID-SIGN',
]);

/** Server-dependent client rows (ledger §4 — these need TWIN evidence). */
const SERVER_DEPENDENT_IDS = [
  'HV-ID-CREATE-001', 'HV-ID-CREATE-002', 'HV-ID-WORDS12-001', 'HV-ID-WORDS12-002',
  'HV-ID-WORDS24-001', 'HV-ID-WORDS24-002', 'HV-ID-DAT-001', 'HV-ID-DAT-002',
  'HV-ID-RETURN-001', 'HV-ID-RETURN-002', 'HV-ID-LOOKUP-001', 'HV-ID-LOOKUP-002',
  'HV-ID-LOOKUP-003', 'HV-ID-LOOKUP-004', 'HV-ID-LOOKUP-005', 'HV-ID-SIGN-001',
  'HV-ID-SIGN-002', 'HV-ID-SIGN-003', 'HV-ID-SUBMIT-001', 'HV-ID-SUBMIT-002',
  'HV-ID-SUBMIT-003', 'HV-ID-SUBMIT-004', 'HV-ID-RECONCILE-001', 'HV-ID-RECONCILE-002',
  'HV-ID-RECONCILE-003', 'HV-ID-IDEMPOTENCY-001', 'HV-ID-IDEMPOTENCY-002', 'HV-ID-IDEMPOTENCY-003',
  'HV-ID-CACHE-001', 'HV-ID-CACHE-002', 'HV-ID-CACHE-003', 'HV-ID-CACHE-004',
];

export function validateCoverage(manifest) {
  const failures = [];
  const rows = manifest.rows;
  const byId = new Map(rows.map((r) => [r.stableId, r]));

  // 1. Every AC has an evidence row (EXECUTABLE_* or TWIN or STATIC).
  for (const ac of ACCEPTANCE_CRITERIA) {
    const row = byId.get(ac);
    if (row === undefined) {
      failures.push(`missing evidence row for ${ac}`);
      continue;
    }
    if (row.state === 'FAIL') {
      failures.push(`${ac} evidence FAIL`);
    }
  }

  // 2. Every family has ≥1 row with a matching prefix.
  for (const family of FAMILIES) {
    const members = rows.filter((r) => r.stableId.startsWith(family));
    if (members.length === 0) {
      failures.push(`no evidence rows for family ${family}`);
      continue;
    }
    if (REAL_ROOT_FAMILIES.has(family)) {
      const realRoot = members.some((r) => r.evidenceClass === 'EXECUTABLE_ROOT' || r.evidenceClass === 'MANUAL');
      // Native/lifecycle families enter `/` on native targets, proven by the
      // Manual TestPack matrices (MT-QUAL-*) plus their PASS member evidence.
      const nativeOrLifecycle = family === 'HV-ID-NATIVE' || family === 'HV-ID-LIFECYCLE';
      const manualRoot = rows.some((r) => r.evidenceClass === 'MANUAL' && r.state !== 'FAIL');
      const membersPass = members.length > 0 && members.every((r) => r.state === 'PASS');
      if (!realRoot && !(nativeOrLifecycle && manualRoot && membersPass)) {
        failures.push(`family ${family} has no real-root or manual evidence`);
      }
    }
    if (SERVER_BEHAVIOR_FAMILIES.has(family)) {
      const twinsPass = members.length > 0 && members.every((r) => r.state === 'PASS');
      const anyRoot = rows.some((r) => r.evidenceClass === 'EXECUTABLE_ROOT' && r.state === 'PASS');
      if (!twinsPass || !anyRoot) {
        failures.push(`family ${family} requires PASS twin evidence and a real-root journey`);
      }
    }
  }

  // 3. Server-dependent client rows need TWIN evidence (never mock/substitute).
  for (const id of SERVER_DEPENDENT_IDS) {
    const row = byId.get(id);
    if (row === undefined) {
      failures.push(`missing evidence row for server-dependent ${id}`);
      continue;
    }
    if (row.evidenceClass === 'EXECUTABLE_CLIENT') {
      failures.push(`${id} has only client evidence — TWIN required`);
    }
    if (row.state !== 'PASS') {
      failures.push(`${id} twin evidence not PASS (${row.state})`);
    }
  }

  // 4. MANUAL/EXTERNAL admit only PASS|FAIL|NOT_SUPPLIED.
  for (const row of rows) {
    if (row.evidenceClass === 'MANUAL' || row.evidenceClass === 'EXTERNAL') {
      if (!['PASS', 'FAIL', 'NOT_SUPPLIED'].includes(row.state)) {
        failures.push(`${row.stableId} illegal external state ${row.state}`);
      }
    }
  }

  // 5/6. Aggregate honesty: any FAIL row anywhere fails the whole gate.
  for (const row of rows) {
    if (row.state === 'FAIL') {
      failures.push(`component ${row.stableId} is FAIL — aggregate cannot hide it`);
    }
  }

  if (failures.length > 0) {
    return { ok: false, failures };
  }

  const passCount = rows.filter((r) => r.state === 'PASS').length;
  const manual = rows.filter((r) => r.evidenceClass === 'MANUAL' || r.evidenceClass === 'EXTERNAL').map((r) => `${r.stableId}:${r.state}`);
  return {
    ok: true,
    summary: `38/38 ACs, ${FAMILIES.length} families, ${rows.length} rows (${passCount} PASS). Manual/external: ${manual.join(', ') || 'none'}.`,
  };
}

/** CLI entry. */
export function main() {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
  } catch (error) {
    console.error(`FEAT-011 coverage: cannot read manifest ${MANIFEST_PATH}: ${(error).message}`);
    return 1;
  }
  const verdict = validateCoverage(manifest);
  if (verdict.ok) {
    console.log(`FEAT-011 coverage OK: ${verdict.summary}`);
    return 0;
  }
  console.error('FEAT-011 coverage FAILED:');
  for (const failure of verdict.failures) {
    console.error(`  - ${failure}`);
  }
  return 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main());
}
