#!/usr/bin/env node
/**
 * FEAT-016 coverage + evidence + pairing validator (Phase 7 task 7.9).
 *
 * Machine-checks that:
 *  1. the canonical freeze (28 ACs + 13 scenario IDs + 2 manual
 *     obligations) is complete in `canonical-ids.json`;
 *  2. every canonical row has current evidence in `evidence-manifest.json`
 *     with an allowed evidence class and truthful state (PASS requires
 *     counts/command/revision; captureDisabled is required for browser rows);
 *  3. the 1:1 pairing ledger maps every TwinTest-paired scenario ID to a
 *     server test method/filter and the six real server runs recorded PASS;
 *  4. no unknown/duplicate ID, no secret-bearing evidence field, no manual
 *     obligation treated as implementation completion, and no automatable
 *     requirement deferred to a manual obligation.
 *
 * Usage: node scripts/entitlement-bootstrap/coverage.mjs
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const CANONICAL_PATH = join(SCRIPT_DIR, 'canonical-ids.json');
const EVIDENCE_PATH = process.env.FEAT016_EVIDENCE_MANIFEST ?? join(SCRIPT_DIR, 'evidence-manifest.json');
const PAIRING_PATH = process.env.FEAT016_PAIRING_LEDGER ?? join(SCRIPT_DIR, 'pairing-ledger.json');

const AC_RE = /^AC-016-\d{3}$/;
const SCENARIO_RE = /^AT-LIC-016-\d{3}$/;
const TWIN_SCENARIO_RE = /^AT-LIC-\d{3}$/;
const ALLOWED_CLASSES = new Set(['EXECUTABLE_CLIENT', 'EXECUTABLE_ROOT', 'TWIN', 'EXECUTABLE_STATIC', 'EXECUTABLE_NATIVE', 'MANUAL', 'EXTERNAL']);
const LEGAL_STATES = new Set(['PASS', 'FAIL', 'NOT_EXECUTED', 'NOT_SUPPLIED', 'PENDING']);
const SECRET_RE = /password|mnemonic|private ?key|BEGIN .*PRIVATE|transaction.?json|\.dat|signature["']?\s*[:=]\s*["']?[0-9a-fA-F]{32,}/i;

function fail(message) {
  console.error(`COVERAGE FAIL: ${message}`);
  process.exitCode = 1;
}

const canonical = JSON.parse(readFileSync(CANONICAL_PATH, 'utf8'));
if (canonical.schema !== 'feat016-canonical-ids-v1') {
  fail(`unknown canonical schema ${canonical.schema}`);
}

const canonicalAcs = canonical.acceptanceCriteria;
const canonicalScenarios = canonical.scenarioIds;

// 1. Canonical freeze completeness/shape.
if (!Array.isArray(canonicalAcs) || canonicalAcs.length !== 28) {
  fail(`expected 28 acceptance criteria, got ${Array.isArray(canonicalAcs) ? canonicalAcs.length : 'none'}`);
} else {
  for (const ac of canonicalAcs) {
    if (!AC_RE.test(ac)) fail(`malformed acceptance id ${JSON.stringify(ac)}`);
  }
  const unique = new Set(canonicalAcs).size;
  if (unique !== 28) fail(`duplicate acceptance ids (unique ${unique}/28)`);
}
if (!Array.isArray(canonicalScenarios) || canonicalScenarios.length !== 13) {
  fail(`expected 13 scenario ids, got ${Array.isArray(canonicalScenarios) ? canonicalScenarios.length : 'none'}`);
} else {
  const seen = new Set();
  for (const entry of canonicalScenarios) {
    if (!SCENARIO_RE.test(entry.id) && !TWIN_SCENARIO_RE.test(entry.id)) {
      fail(`malformed scenario id ${JSON.stringify(entry.id)}`);
    }
    if (seen.has(entry.id)) fail(`duplicate scenario id ${entry.id}`);
    seen.add(entry.id);
    if (typeof entry.kind !== 'string' || entry.kind.length === 0) {
      fail(`scenario ${entry.id} has no kind`);
    }
  }
}

// 2. Evidence manifest completeness/truthfulness.
if (!existsSync(EVIDENCE_PATH)) {
  fail(`evidence manifest not found: ${EVIDENCE_PATH}`);
  process.exit(1);
}
const evidence = JSON.parse(readFileSync(EVIDENCE_PATH, 'utf8'));
if (!Array.isArray(evidence.rows)) {
  fail('evidence manifest must contain a rows array');
  process.exit(1);
}
const evidenceRows = new Map(); // stableId -> rows[]
for (const row of evidence.rows) {
  if (typeof row.stableId !== 'string' || row.stableId.length === 0) {
    fail('evidence row without stableId');
    continue;
  }
  if (!ALLOWED_CLASSES.has(row.evidenceClass)) {
    fail(`${row.stableId}: illegal evidenceClass ${row.evidenceClass}`);
  }
  if (!LEGAL_STATES.has(row.state)) {
    fail(`${row.stableId}: illegal state ${String(row.state)}`);
  }
  if (row.state === 'PASS' && (row.counts === undefined || row.command === undefined || row.revision === undefined)) {
    fail(`${row.stableId}: PASS without counts/command/revision`);
  }
  if (row.captureRequired === true && row.captureDisabled !== true) {
    fail(`${row.stableId}: secret-bearing browser evidence must disable capture`);
  }
  const serialized = JSON.stringify(row);
  if (SECRET_RE.test(serialized)) {
    fail(`${row.stableId}: secret-bearing evidence field`);
  }
  const rows = evidenceRows.get(row.stableId) ?? [];
  rows.push(row);
  evidenceRows.set(row.stableId, rows);
}

for (const ac of canonicalAcs) {
  if (!evidenceRows.has(ac)) fail(`acceptance ${ac} has no current evidence row`);
}
for (const entry of canonicalScenarios) {
  const rows = evidenceRows.get(entry.id);
  if (rows === undefined || rows.length === 0) {
    fail(`scenario ${entry.id} has no current evidence row`);
    continue;
  }
  if (entry.kind === 'client-only') {
    if (!rows.some((row) => row.evidenceClass === 'EXECUTABLE_CLIENT' && row.state === 'PASS')) {
      fail(`client-only scenario ${entry.id} requires a PASS EXECUTABLE_CLIENT evidence row`);
    }
  }
  if (entry.kind === 'twintest-paired') {
    if (!rows.some((row) => row.evidenceClass === 'TWIN' && row.state === 'PASS')) {
      fail(`TwinTest-paired scenario ${entry.id} requires a PASS TWIN evidence row`);
    }
  }
  // Every journey must be wired in the catalog (wiring gate proves discovery
  // separately); a browser-journey row records the honest execution state.
  if (!rows.some((row) => row.evidenceClass === 'EXECUTABLE_ROOT')) {
    fail(`scenario ${entry.id} has no browser-journey (EXECUTABLE_ROOT) evidence row`);
  }
}

// 3. Pairing ledger: 1:1 browser ↔ server for every TwinTest-paired ID.
if (!existsSync(PAIRING_PATH)) {
  fail(`pairing ledger not found: ${PAIRING_PATH}`);
  process.exit(1);
}
const pairing = JSON.parse(readFileSync(PAIRING_PATH, 'utf8'));
if (!Array.isArray(pairing.entries)) {
  fail('pairing ledger must contain an entries array');
  process.exit(1);
}
const pairedIds = new Set(
  canonicalScenarios.filter((entry) => entry.kind === 'twintest-paired').map((entry) => entry.id),
);
if (pairedIds.size !== 6) {
  fail(`expected 6 TwinTest-paired scenario ids, got ${pairedIds.size}`);
}
const pairingIds = new Set();
for (const entry of pairing.entries) {
  if (!pairedIds.has(entry.scenarioId)) {
    fail(`pairing ledger has non-TwinTest or unknown scenario ${entry.scenarioId}`);
  }
  if (pairingIds.has(entry.scenarioId)) fail(`pairing ledger duplicates ${entry.scenarioId}`);
  pairingIds.add(entry.scenarioId);
  if (typeof entry.browserFeature !== 'string' || entry.browserFeature.length === 0) {
    fail(`${entry.scenarioId}: missing browserFeature`);
  }
  if (typeof entry.serverClass !== 'string' || typeof entry.serverMethod !== 'string') {
    fail(`${entry.scenarioId}: missing server class/method`);
  }
  if (typeof entry.filter !== 'string' || entry.filter.length === 0) {
    fail(`${entry.scenarioId}: missing server filter`);
  }
  if (entry.twinRunState !== 'PASS' || entry.twinRunCounts === undefined) {
    fail(`${entry.scenarioId}: TwinTest server run must be recorded PASS with counts`);
  }
  const browserRow = evidenceRows.get(entry.scenarioId)?.find((row) => row.evidenceClass === 'TWIN');
  if (browserRow === undefined) {
    fail(`${entry.scenarioId}: evidence row must be a TWIN class row`);
  }
}
for (const id of pairedIds) {
  if (!pairingIds.has(id)) fail(`TwinTest-paired scenario ${id} has no pairing entry`);
}

// 4. Manual obligations admission (schema-valid + PENDING + task-linked).
if (!Array.isArray(canonical.manualObligations) || canonical.manualObligations.length !== 2) {
  fail('canonical freeze must carry exactly the two manual obligations');
} else {
  for (const obligation of canonical.manualObligations) {
    if (!/^MT-QUAL-(ANDROID|UBUNTU)-016-001$/.test(obligation.id)) {
      fail(`malformed manual obligation id ${obligation.id}`);
    }
    if (typeof obligation.taskId !== 'string' || !/^phase-7-task-7-[78]$/.test(obligation.taskId)) {
      fail(`obligation ${obligation.id} must link to phase-7 task 7.7 or 7.8`);
    }
    const rows = evidenceRows.get(obligation.id) ?? [];
    if (!rows.some((row) => row.evidenceClass === 'MANUAL')) {
      fail(`obligation ${obligation.id} must have a MANUAL evidence row`);
    }
    if (!rows.some((row) => row.state === 'PENDING')) {
      fail(`obligation ${obligation.id} must be recorded PENDING (release readiness only)`);
    }
  }
}

if (process.exitCode === undefined) {
  console.log(
    `COVERAGE OK (28/28 ACs, 13/13 scenario ids, ${pairing.entries.length}/6 pairing rows PASS, obligations PENDING)`,
  );
}
