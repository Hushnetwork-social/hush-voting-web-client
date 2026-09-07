#!/usr/bin/env node
/**
 * FEAT-017 evidence + pairing + obligations admission validator (Phase 7
 * tasks 7.3/7.9).
 *
 * Machine-checks that:
 *  1. the canonical freeze (owned ids + regression ids + manual obligations)
 *     in `canonical-ids.json` is well-formed and unique;
 *  2. every FEAT-017-owned backend-dependent id (AT-LIC-001/004/005/006/008/
 *     009) has a 1:1 PASS TWIN pairing row in `pairing-ledger.json`;
 *  3. every canonical owned id has an evidence row (TWIN PASS for paired ids,
 *     EXECUTABLE_CLIENT PASS for client-only ids) and an EXECUTABLE_ROOT
 *     row recording the honest browser-journey state;
 *  4. every manual obligation is PENDING and linked to its exact phase-7 task;
 *  5. no unknown/duplicate id, no secret-bearing field, no manual obligation
 *     treated as implementation completion.
 *
 * Full live browser runs remain release readiness (EXT-017-001).
 *
 * Usage: node scripts/licence-upgrade/evidence.mjs
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const CANONICAL_PATH = process.env.FEAT017_CANONICAL_PATH ?? join(SCRIPT_DIR, 'canonical-ids.json');
const EVIDENCE_PATH = process.env.FEAT017_EVIDENCE_MANIFEST ?? join(SCRIPT_DIR, 'evidence-manifest.json');
const PAIRING_PATH = process.env.FEAT017_PAIRING_LEDGER ?? join(SCRIPT_DIR, 'pairing-ledger.json');

const SCENARIO_RE = /^AT-LIC-\d{3}$/;
const MANUAL_RE = /^MT-QUAL-(ANDROID|UBUNTU)-017-001$/;
const ALLOWED_CLASSES = new Set(['EXECUTABLE_CLIENT', 'EXECUTABLE_ROOT', 'TWIN', 'EXECUTABLE_STATIC', 'EXECUTABLE_NATIVE', 'MANUAL', 'EXTERNAL']);
const LEGAL_STATES = new Set(['PASS', 'FAIL', 'NOT_EXECUTED', 'NOT_SUPPLIED', 'PENDING']);
const SECRET_RE = /password|mnemonic|private ?key|BEGIN .*PRIVATE|transaction.?json|\.dat|signature["']?\s*[:=]\s*["']?[0-9a-fA-F]{32,}/i;

function fail(message) {
  console.error(`EVIDENCE FAIL: ${message}`);
  process.exitCode = 1;
}

const canonical = JSON.parse(readFileSync(CANONICAL_PATH, 'utf8'));
if (canonical.schema !== 'feat017-canonical-ids-v1') {
  fail(`unknown canonical schema ${canonical.schema}`);
}

// 1. Canonical freeze shape/uniqueness.
const owned = canonical.ownedScenarioIds;
const regressions = canonical.regressionScenarioIds;
const obligations = canonical.manualObligations;
if (!Array.isArray(owned) || owned.length !== 8) fail(`expected 8 owned scenario ids, got ${owned?.length}`);
if (!Array.isArray(regressions) || regressions.length !== 5) fail(`expected 5 regression ids, got ${regressions?.length}`);
if (!Array.isArray(obligations) || obligations.length !== 2) fail('expected exactly 2 manual obligations');

const ownedIds = new Set();
for (const entry of owned) {
  if (!SCENARIO_RE.test(entry.id) || ownedIds.has(entry.id)) fail(`bad/duplicate owned id ${entry.id}`);
  ownedIds.add(entry.id);
  if (!['twintest-paired', 'client-only'].includes(entry.kind)) fail(`${entry.id}: unknown kind`);
}
const pairedIds = new Set(owned.filter((e) => e.kind === 'twintest-paired').map((e) => e.id));
const clientOnlyIds = new Set(owned.filter((e) => e.kind === 'client-only').map((e) => e.id));
if (pairedIds.size !== 6 || clientOnlyIds.size !== 2) {
  fail(`expected 6 twin-paired + 2 client-only owned ids (got ${pairedIds.size}/${clientOnlyIds.size})`);
}
for (const entry of regressions) {
  if (!SCENARIO_RE.test(entry.id) || ownedIds.has(entry.id)) fail(`bad/overlapping regression id ${entry.id}`);
  if (entry.kind !== 'regression-twintest') fail(`${entry.id}: regression must be regression-twintest`);
}
for (const obligation of obligations) {
  if (!MANUAL_RE.test(obligation.id)) fail(`malformed manual obligation id ${obligation.id}`);
  if (typeof obligation.taskId !== 'string' || !/^phase-7-task-7-[78]$/.test(obligation.taskId)) {
    fail(`obligation ${obligation.id} must link to phase-7 task 7.7 or 7.8`);
  }
}

// 2. Pairing ledger 1:1 for twin-paired ids.
if (!existsSync(PAIRING_PATH)) {
  fail(`pairing ledger not found: ${PAIRING_PATH}`);
  process.exit(1);
}
const pairing = JSON.parse(readFileSync(PAIRING_PATH, 'utf8'));
const pairedRows = new Map();
for (const row of pairing.entries ?? []) {
  if (!pairedIds.has(row.scenarioId)) fail(`pairing ledger has non-paired/unknown scenario ${row.scenarioId}`);
  if (pairedRows.has(row.scenarioId)) fail(`pairing ledger duplicates ${row.scenarioId}`);
  pairedRows.set(row.scenarioId, row);
  if (!row.browserFeature || !row.serverClass || !row.serverMethod || !row.filter) {
    fail(`${row.scenarioId}: incomplete pairing row`);
  }
  if (row.twinRunState !== 'PASS' || !row.twinRunCounts) fail(`${row.scenarioId}: TwinTest run must be PASS with counts`);
}
for (const id of pairedIds) {
  if (!pairedRows.has(id)) fail(`twin-paired id ${id} has no pairing row`);
}

// 3. Evidence manifest rows.
if (!existsSync(EVIDENCE_PATH)) {
  fail(`evidence manifest not found: ${EVIDENCE_PATH}`);
  process.exit(1);
}
const evidence = JSON.parse(readFileSync(EVIDENCE_PATH, 'utf8'));
if (!Array.isArray(evidence.rows)) {
  fail('evidence manifest must contain a rows array');
  process.exit(1);
}
const evidenceBy = new Map();
for (const row of evidence.rows) {
  if (typeof row.stableId !== 'string') fail('evidence row without stableId');
  if (!ALLOWED_CLASSES.has(row.evidenceClass)) fail(`${row.stableId}: illegal evidenceClass ${row.evidenceClass}`);
  if (!LEGAL_STATES.has(row.state)) fail(`${row.stableId}: illegal state ${String(row.state)}`);
  if (row.state === 'PASS' && (row.counts === undefined || row.command === undefined || row.revision === undefined)) {
    fail(`${row.stableId}: PASS without counts/command/revision`);
  }
  if (row.captureRequired === true && row.captureDisabled !== true) {
    fail(`${row.stableId}: secret-bearing browser evidence must disable capture`);
  }
  if (SECRET_RE.test(JSON.stringify(row))) fail(`${row.stableId}: secret-bearing evidence field`);
  const rows = evidenceBy.get(row.stableId) ?? [];
  rows.push(row);
  evidenceBy.set(row.stableId, rows);
}
for (const id of ownedIds) {
  const rows = evidenceBy.get(id);
  if (rows === undefined || rows.length === 0) {
    fail(`owned id ${id} has no evidence row`);
    continue;
  }
  if (pairedIds.has(id) && !rows.some((r) => r.evidenceClass === 'TWIN' && r.state === 'PASS')) {
    fail(`twin-paired id ${id} requires a PASS TWIN evidence row`);
  }
  if (clientOnlyIds.has(id) && !rows.some((r) => r.evidenceClass === 'EXECUTABLE_CLIENT' && r.state === 'PASS')) {
    fail(`client-only id ${id} requires a PASS EXECUTABLE_CLIENT evidence row`);
  }
  if (!rows.some((r) => r.evidenceClass === 'EXECUTABLE_ROOT')) {
    fail(`id ${id} has no browser-journey (EXECUTABLE_ROOT) evidence row`);
  }
}

// 4. Manual obligations PENDING admission.
for (const obligation of obligations) {
  const rows = evidenceBy.get(obligation.id) ?? [];
  if (!rows.some((r) => r.evidenceClass === 'MANUAL')) fail(`obligation ${obligation.id} must have a MANUAL evidence row`);
  if (!rows.some((r) => r.state === 'PENDING')) fail(`obligation ${obligation.id} must be PENDING (release readiness only)`);
}

if (process.exitCode === undefined) {
  console.log(
    `EVIDENCE OK (8/8 owned ids with evidence, ${pairedRows.size}/6 pairing rows PASS, 2 obligations PENDING)`,
  );
}
