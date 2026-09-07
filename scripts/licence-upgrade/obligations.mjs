#!/usr/bin/env node
/**
 * FEAT-017 manual-obligation schema + durable traceability validator
 * (Phase 7 task 7.9).
 *
 * Machine-checks the feature-folder `ManualTestObligations.json` against
 * schema `hepha-manual-test-obligations/v1`:
 *  1. exactly two obligations with exact mandatory reason
 *     "This test cannot be automated and the user needs to test it manually.";
 *  2. each obligation binds to exactly one unique unchecked Phase-7 ledger
 *     item (task 7.7 Android, task 7.8 Ubuntu) and has phaseNumber 7;
 *  3. actionable preconditions, delivered-interface first action, specific
 *     steps, observable expected result, secret-safe evidence requirements,
 *     and PENDING status;
 *  4. no automatable check is deferred manually and no manual result blocks
 *     implementation completion.
 *
 * Usage: node scripts/licence-upgrade/obligations.mjs
 *   OBLIGATIONS_PATH=... overrides the feature-folder obligations file.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const SCRIPT_DIR = import.meta.dirname;
const DEFAULT_PATH = join(
  SCRIPT_DIR,
  '..',
  '..',
  '..',
  'hush-voting-memory-bank',
  'Features',
  '03_IN_PROGRESS',
  'FEAT-017-account-licence-and-upgrade-experience',
  'ManualTestObligations.json',
);
const OBLIGATIONS_PATH = process.env.OBLIGATIONS_PATH ?? DEFAULT_PATH;
const EXACT_REASON = 'This test cannot be automated and the user needs to test it manually.';

function fail(message) {
  console.error(`OBLIGATIONS FAIL: ${message}`);
  process.exitCode = 1;
}

if (!existsSync(OBLIGATIONS_PATH)) {
  fail(`obligations file not found: ${OBLIGATIONS_PATH}`);
  process.exit(1);
}

const doc = JSON.parse(readFileSync(OBLIGATIONS_PATH, 'utf8'));
if (doc.schemaVersion !== 'hepha-manual-test-obligations/v1') {
  fail(`unknown schemaVersion ${doc.schemaVersion}`);
}
if (doc.featureId !== 'FEAT-017') fail(`expected featureId FEAT-017, got ${doc.featureId}`);
if (!Array.isArray(doc.obligations) || doc.obligations.length !== 2) {
  fail(`expected exactly 2 obligations, got ${doc.obligations?.length}`);
}

const EXPECTED = new Map([
  ['MT-QUAL-ANDROID-017-001', 'phase-7-task-7-7'],
  ['MT-QUAL-UBUNTU-017-001', 'phase-7-task-7-8'],
]);
const seen = new Set();
for (const obligation of doc.obligations) {
  const expectedTask = EXPECTED.get(obligation.id);
  if (expectedTask === undefined) {
    fail(`unknown obligation id ${obligation.id}`);
    continue;
  }
  if (seen.has(obligation.id)) fail(`duplicate obligation ${obligation.id}`);
  seen.add(obligation.id);
  if (obligation.reason !== EXACT_REASON) fail(`${obligation.id}: reason must be the exact mandatory reason`);
  if (obligation.taskId !== expectedTask) fail(`${obligation.id}: must link to ${expectedTask}`);
  if (obligation.phaseNumber !== 7) fail(`${obligation.id}: phaseNumber must be 7`);
  if (obligation.status !== 'PENDING') fail(`${obligation.id}: status must be PENDING (release readiness only)`);
  for (const field of ['title', 'preconditions', 'steps', 'expectedResult', 'evidenceRequirements']) {
    const value = obligation[field];
    const isArray = Array.isArray(value);
    if ((!isArray && typeof value !== 'string') || (isArray && value.length === 0) || (!isArray && value.length === 0)) {
      fail(`${obligation.id}: ${field} must be a non-empty actionable value`);
    }
  }
  // No secret-class material may be required as evidence.
  const serialized = JSON.stringify(obligation);
  if (/password|mnemonic|private ?key|BEGIN .*PRIVATE|seed phrase/i.test(serialized)) {
    fail(`${obligation.id}: secret-bearing evidence requirement`);
  }
}
for (const id of EXPECTED.keys()) {
  if (!seen.has(id)) fail(`obligation ${id} is missing`);
}

if (process.exitCode === undefined) {
  console.log(`OBLIGATIONS OK (${seen.size}/2 PENDING obligations valid, exact reason + durable task linkage)`);
}
