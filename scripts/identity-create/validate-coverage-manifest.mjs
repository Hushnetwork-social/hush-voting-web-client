#!/usr/bin/env node
/**
 * FEAT-007 coverage-manifest validator (Task 7.1).
 *
 * Machine-checks the acceptance-coverage manifest produced in Phase 1
 * (memory bank) AND the executable Gherkin catalog
 * (`features/identity-create/*.feature`): every AC-007-NNN has exactly the
 * manifest scenario ID in the catalog, every scenario ID is unique, every
 * scenario references a known criterion, and every criterion references one
 * of the 17 mandatory families. Unknown or missing mappings fail CI before
 * acceptance execution.
 *
 * Usage:
 *   node scripts/identity-create/validate-coverage-manifest.mjs <manifest.json>
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');
const FEATURES_DIR = join(REPO_ROOT, 'features', 'identity-create');

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

  // Cross-check the executable Gherkin catalog against the manifest.
  const catalog = readCatalog();
  for (const ac of knownCriteria) {
    const expectedIds = new Set(criteria[ac].scenarioIds);
    const actualIds = catalog.get(ac) ?? [];
    const missing = [...expectedIds].filter((id) => !actualIds.includes(id));
    const extra = actualIds.filter((id) => !expectedIds.has(id));
    if (missing.length > 0) errors.push(`${ac}: catalog missing scenario(s) ${missing.join(', ')}`);
    if (extra.length > 0) errors.push(`${ac}: catalog has unexpected scenario(s) ${extra.join(', ')}`);
  }
  for (const [ac, ids] of catalog) {
    if (!knownCriteria.includes(ac)) {
      errors.push(`${ac}: catalog references an unknown criterion`);
    }
    void ids;
  }

  if (errors.length > 0) {
    console.error('COVERAGE MANIFEST FAILED:');
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`COVERAGE MANIFEST OK (${knownCriteria.length}/76 criteria, ${seenScenarioIds.size} scenario ids, ${FAMILIES.size} families, ${catalog.size} catalog scenarios)`);
}

/** Parse .feature files into AC -> scenario IDs. */
function readCatalog() {
  const catalog = new Map();
  for (const name of readdirSync(FEATURES_DIR)) {
    const file = join(FEATURES_DIR, name);
    if (!statSync(file).isFile() || !name.endsWith('.feature')) continue;
    const content = readFileSync(file, 'utf8');
    // Each scenario tag line carries: @FEAT-007 @AC-007-NNN @HV-ID-CREATE-XXX-NNN
    const tagRe = /@(AC-007-\d{3})\s+@(HV-ID-CREATE-[A-Z]+-\d{3})/g;
    let match;
    while ((match = tagRe.exec(content)) !== null) {
      const ac = match[1];
      const id = match[2];
      catalog.set(ac, [...(catalog.get(ac) ?? []), id]);
    }
  }
  return catalog;
}

main();
