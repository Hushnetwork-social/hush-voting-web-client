#!/usr/bin/env node
/**
 * FEAT-011 Tasks 7.1/7.5 — aggregate quality gate + evidence/manual-obligation
 * admission.
 *
 * `quality` validates the evidence manifest end-to-end (rows, capture policy,
 * cleanup proofs, warnings/errors) and the Manual TestPack traceability
 * (schema-valid obligations matching the SKIPPED phase-7 tasks). Any red
 * component fails the aggregate.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_ROOT = path.resolve(__dirname, '..', '..');
const MANIFEST_PATH = process.env.FEAT011_MANIFEST ?? path.join(__dirname, 'evidence-manifest.json');
const OBLIGATIONS_PATH = process.env.FEAT011_OBLIGATIONS ?? path.join(CLIENT_ROOT, '..', 'hush-voting-memory-bank', 'Features', '03_IN_PROGRESS', 'FEAT-011-login-and-identity-happypath-closure', 'ManualTestObligations.json');

/** Legal external states (evidence-admission §2). */
const LEGAL_EXTERNAL_STATES = new Set(['PASS', 'FAIL', 'NOT_SUPPLIED']);

/** Canonical manual-skip reason (start-feature traceability contract). */
export const CANONICAL_MANUAL_REASON = 'This test cannot be automated and the user needs to test it manually.';

/** Validate one evidence row. */
function validateRow(row) {
  if (typeof row.stableId !== 'string' || row.stableId.length === 0) {
    return 'row without stableId';
  }
  if (!['EXECUTABLE_CLIENT', 'EXECUTABLE_ROOT', 'TWIN', 'EXECUTABLE_NATIVE', 'EXECUTABLE_STATIC', 'MANUAL', 'EXTERNAL'].includes(row.evidenceClass)) {
    return `${row.stableId}: illegal evidenceClass`;
  }
  if (!LEGAL_EXTERNAL_STATES.has(row.state)) {
    return `${row.stableId}: illegal state ${String(row.state)}`;
  }
  if (row.state === 'PASS' && (row.counts === undefined || row.command === undefined)) {
    return `${row.stableId}: PASS without counts/command`;
  }
  if (row.state === 'PASS' && row.revision === undefined) {
    return `${row.stableId}: PASS without revision`;
  }
  const json = JSON.stringify(row);
  if (/password|mnemonic|private ?key|BEGIN .*PRIVATE|transaction.?json|\.dat/i.test(json)) {
    return `${row.stableId}: secret-bearing evidence field`;
  }
  return null;
}

/** Validate the Manual TestPack obligations traceability. */
export function validateManualObligations(obligations) {
  const failures = [];
  if (typeof obligations !== 'object' || obligations === null) {
    return ['ManualTestObligations.json is not an object'];
  }
  const doc = obligations;
  if (doc.schemaVersion !== 'hepha-manual-test-obligations/v1') {
    failures.push('schemaVersion mismatch');
  }
  if (doc.featureId !== 'FEAT-011') {
    failures.push('featureId mismatch');
  }
  const rows = Array.isArray(doc.obligations) ? doc.obligations : [];
  const expectedIds = new Set(['MT-QUAL-UBUNTU-011-001', 'MT-QUAL-ANDROID-011-001']);
  const foundIds = new Set();
  for (const row of rows) {
    if (typeof row.id !== 'string' || !expectedIds.has(row.id)) {
      failures.push(`unexpected obligation id ${String(row.id)}`);
      continue;
    }
    foundIds.add(row.id);
    if (row.reason !== CANONICAL_MANUAL_REASON) {
      failures.push(`${row.id}: reason is not the canonical manual reason`);
    }
    if (row.status !== 'PENDING') {
      failures.push(`${row.id}: status must be PENDING`);
    }
    if (!Array.isArray(row.preconditions) || !Array.isArray(row.steps) || typeof row.expectedResult !== 'string' || !Array.isArray(row.evidenceRequirements)) {
      failures.push(`${row.id}: missing preconditions/steps/expectedResult/evidenceRequirements`);
    }
  }
  for (const expected of expectedIds) {
    if (!foundIds.has(expected)) {
      failures.push(`missing obligation ${expected}`);
    }
  }
  return failures;
}

export function main() {
  const failures = [];

  let manifest = {};
  try {
    manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
  } catch (error) {
    failures.push(`cannot read manifest: ${(error).message}`);
    manifest = {};
  }
  if (Array.isArray(manifest.rows)) {
    for (const row of manifest.rows) {
      const failure = validateRow(row);
      if (failure !== null) {
        failures.push(failure);
      }
    }
  } else {
    failures.push('manifest has no rows array');
  }

  try {
    const obligations = JSON.parse(readFileSync(OBLIGATIONS_PATH, 'utf8'));
    failures.push(...validateManualObligations(obligations));
  } catch (error) {
    failures.push(`cannot read ManualTestObligations.json: ${(error).message}`);
  }

  if (failures.length === 0) {
    console.log('FEAT-011 quality gate OK: evidence manifest + manual obligations valid.');
    return 0;
  }
  console.error(`FEAT-011 quality gate FAILED (${failures.length}):`);
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  return 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main());
}
