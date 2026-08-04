#!/usr/bin/env node
/**
 * FEAT-008 coverage-manifest validator (Task 7.1).
 *
 * Machine-checks the acceptance-coverage manifest (memory bank) AND the
 * executable Gherkin catalog (`features/recovery-words/*.feature`): every
 * AC-008-NNN has exactly the manifest scenario ID in the catalog, every
 * scenario ID is unique, every scenario references a known criterion, and
 * every criterion references one of the 22 mandatory families. Unknown or
 * missing mappings fail CI before acceptance execution.
 *
 * Usage:
 *   node scripts/recovery-words/validate-coverage-manifest.mjs <manifest.json>
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');
const FEATURES_DIR = join(REPO_ROOT, 'features', 'recovery-words');

const FAMILIES = new Set([
  'HV-RW-ENTRY-GUARD', 'HV-RW-INPUT', 'HV-RW-PASTE', 'HV-RW-VALIDATE', 'HV-RW-CUSTODY', 'HV-RW-CANDIDATES',
  'HV-RW-LOOKUP', 'HV-RW-SELECT', 'HV-RW-CONTROL', 'HV-RW-PROFILE', 'HV-RW-RECREATE', 'HV-RW-PASSWORD',
  'HV-RW-PASSKEY', 'HV-RW-NATIVE-PASSWORDLESS', 'HV-RW-SESSION', 'HV-RW-STAGE', 'HV-RW-RESUME', 'HV-RW-NAV',
  'HV-RW-OWNER', 'HV-RW-CLEANUP', 'HV-RW-MIGRATION', 'HV-RW-SECURITY',
]);

const TARGETS = new Set(['web', 'ubuntu', 'android', 'server', 'cross-adapter', 'all']);

function main() {
  const manifestPath = process.argv[2];
  if (!manifestPath) {
    console.error('usage: node scripts/recovery-words/validate-coverage-manifest.mjs <manifest.json>');
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
  const criteriaToScenario = new Map();

  for (const ac of knownCriteria) {
    if (!/^AC-008-\d{3}$/.test(ac)) {
      errors.push(`${ac}: malformed criterion id`);
      continue;
    }
    const entry = criteria[ac];
    if (!entry || !Array.isArray(entry.scenarioIds) || entry.scenarioIds.length === 0) {
      errors.push(`${ac}: has no executable scenario`);
      continue;
    }
    if (entry.scenarioIds.length !== 1) {
      errors.push(`${ac}: must map to exactly one scenario id`);
    }
    if (!FAMILIES.has(entry.family)) {
      errors.push(`${ac}: unknown family ${entry.family}`);
    }
    const targets = entry.targets ?? [];
    if (targets.length === 0 || targets.some((target) => !TARGETS.has(target))) {
      errors.push(`${ac}: unknown or empty target list`);
    }
    for (const sid of entry.scenarioIds) {
      if (seenScenarioIds.has(sid)) {
        errors.push(`${ac}: duplicate scenario id ${sid}`);
      }
      seenScenarioIds.add(sid);
      criteriaToScenario.set(sid, ac);
    }
  }

  // Parse the feature catalog: collect @AC-008-NNN and @HV-RW-* tags per scenario.
  const featureFiles = readdirSync(FEATURES_DIR).filter((name) => name.endsWith('.feature'));
  if (featureFiles.length === 0) {
    errors.push('no feature files found under features/recovery-words');
  }
  const catalogScenarioTags = new Set();
  const catalogCriterionTags = new Set();
  for (const name of featureFiles) {
    const path = join(FEATURES_DIR, name);
    if (!statSync(path).isFile()) continue;
    const content = readFileSync(path, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('@')) continue;
      for (const tag of trimmed.split(/\s+/)) {
        if (/^@AC-008-\d{3}$/.test(tag)) catalogCriterionTags.add(tag.slice(1));
        if (/^@HV-RW-[A-Z-]+-\d{3}$/.test(tag)) catalogScenarioTags.add(tag.slice(1));
      }
    }
  }

  // Every manifest scenario must exist in the catalog with its criterion tag.
  for (const [sid, ac] of criteriaToScenario) {
    if (!catalogScenarioTags.has(sid)) {
      errors.push(`${ac}: scenario ${sid} missing from the Gherkin catalog`);
    }
  }
  // Every catalog criterion must be a known manifest criterion.
  for (const ac of catalogCriterionTags) {
    if (!knownCriteria.includes(ac)) {
      errors.push(`catalog references unknown criterion ${ac}`);
    }
  }
  // Every manifest criterion must appear in the catalog.
  for (const ac of knownCriteria) {
    if (!catalogCriterionTags.has(ac)) {
      errors.push(`manifest criterion ${ac} missing from the Gherkin catalog`);
    }
  }

  if (errors.length > 0) {
    console.error(`COVERAGE MANIFEST INVALID (${errors.length}):`);
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
  }
  console.log(`COVERAGE MANIFEST OK: ${knownCriteria.length}/85 criteria, ${criteriaToScenario.size} scenarios, ${featureFiles.length} feature files`);
}

main();
