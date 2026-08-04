#!/usr/bin/env node
/**
 * FEAT-007 coverage-manifest validator (Task 7.1).
 *
 * Machine-checks the acceptance-coverage manifest produced in Phase 1
 * (memory bank): every AC-007-NNN has at least one executable scenario ID,
 * every scenario ID is unique, every scenario references a known criterion,
 * and every criterion references one of the 17 mandatory families. Unknown or
 * missing mappings fail CI before acceptance execution.
 *
 * Usage:
 *   node scripts/identity-create/validate-coverage-manifest.mjs <manifest.json>
 */
import { readFileSync } from 'node:fs';

const FAMILIES = new Set([
  'HV-ID-CREATE-ENTRY', 'HV-ID-CREATE-PROFILE', 'HV-ID-CREATE-GENERATE',
  'HV-ID-CREATE-RECOVERY', 'HV-ID-CREATE-PROTECT', 'HV-ID-CREATE-REVIEW',
  'HV-ID-CREATE-STAGE', 'HV-ID-CREATE-SUBMIT', 'HV-ID-CREATE-CONFIRM',
  'HV-ID-CREATE-DELAY', 'HV-ID-CREATE-CORRECT', 'HV-ID-CREATE-RESET',
  'HV-ID-CREATE-NAV', 'HV-ID-CREATE-MULTI', 'HV-ID-CREATE-CANCEL',
  'HV-ID-CREATE-SECURITY', 'HV-ID-CREATE-NATIVE',
]);

const TARGETS = new Set(['web', 'ubuntu', 'android', 'server', 'cross-adapter']);

function main() {
  const manifestPath = process.argv[2];
  if (!manifestPath) {
    console.error('usage: node scripts/identity-create/validate-coverage-manifest.mjs <manifest.json>');
    process.exit(2);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const errors = [];
  const criteria = manifest.criteria;
  if (!criteria || typeof criteria !== 'object') {
    console.error('COVERAGE MANIFEST INVALID: missing criteria object');
    process.exit(1);
  }

  const seenScenarioIds = new Set();
  const knownCriteria = Object.keys(criteria);

  for (const ac of knownCriteria) {
    if (!/^AC-007-\d{3}$/.test(ac)) {
      errors.push(`${ac}: malformed criterion id`);
      continue;
    }
    const entry = criteria[ac];
    if (!entry || !Array.isArray(entry.scenarioIds) || entry.scenarioIds.length === 0) {
      errors.push(`${ac}: has no executable scenario`);
      continue;
    }
    if (!FAMILIES.has(entry.family)) {
      errors.push(`${ac}: unknown family ${entry.family}`);
    }
    for (const target of entry.targets ?? []) {
      if (!TARGETS.has(target)) {
        errors.push(`${ac}: unknown target ${target}`);
      }
    }
    for (const sid of entry.scenarioIds) {
      if (seenScenarioIds.has(sid)) {
        errors.push(`${ac}: duplicate scenario id ${sid}`);
      }
      seenScenarioIds.add(sid);
      if (!sid.startsWith(entry.family)) {
        errors.push(`${ac}: scenario ${sid} does not belong to family ${entry.family}`);
      }
    }
  }

  if (knownCriteria.length !== 76) {
    errors.push(`expected 76 criteria, found ${knownCriteria.length}`);
  }

  if (errors.length > 0) {
    console.error('COVERAGE MANIFEST FAILED:');
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`COVERAGE MANIFEST OK (${knownCriteria.length}/76 criteria, ${seenScenarioIds.size} scenario ids, ${FAMILIES.size} families)`);
}

main();
