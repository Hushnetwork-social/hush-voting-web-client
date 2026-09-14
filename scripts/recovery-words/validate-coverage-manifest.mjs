#!/usr/bin/env node
/**
 * FEAT-008 coverage-manifest validator (Task 7.1).
 *
 * Machine-checks the acceptance-coverage manifest (memory bank) AND the
 * owned .NET Gherkin catalogue (including separate qualification gates): every
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
const FEATURES_DIR = process.env.FEAT008_COVERAGE_FEATURES ?? join(REPO_ROOT, '..', 'hush-server-node', 'Node', 'HushNode.IntegrationTests', 'HushVoting', 'Features', 'recovery-words');

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
  if (knownCriteria.length !== 85) errors.push('exactly 85 original criteria are required');
  for (let number = 1; number <= 85; number++) {
    const id = `AC-008-${String(number).padStart(3, '0')}`;
    if (!Object.hasOwn(criteria, id)) errors.push(`missing original criterion ${id}`);
  }
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

  // Validate each scenario's own AC/ID association, not independent global tag sets.
  const featureFiles = readdirSync(FEATURES_DIR).filter(name => name.endsWith('.feature'));
  if (featureFiles.length === 0) errors.push('no HushVoting .NET recovery feature files found');
  const catalog = new Map();
  for (const name of featureFiles) {
    const path = join(FEATURES_DIR, name);
    if (!statSync(path).isFile()) continue;
    let pendingTags = [];
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      const trimmed = line.trim();
      if (trimmed.startsWith('@')) { pendingTags.push(...trimmed.split(/\s+/)); continue; }
      if (trimmed.startsWith('Feature:')) { pendingTags = []; continue; }
      if (!/^Scenario(?: Outline)?:/.test(trimmed)) continue;
      const ids = pendingTags.filter(tag => /^@HV-RW-[A-Z-]+-\d{3}$/.test(tag)).map(tag => tag.slice(1));
      const acs = pendingTags.filter(tag => /^@AC-008-\d{3}$/.test(tag)).map(tag => tag.slice(1));
      pendingTags = [];
      if (ids.length !== 1 || acs.length !== 1) {
        errors.push(`${name}: each scenario requires exactly one original scenario ID and AC`);
        continue;
      }
      const [id] = ids, [ac] = acs;
      if (catalog.has(id)) errors.push(`duplicate scenario in .NET catalogue: ${id}`);
      catalog.set(id, ac);
      if (criteriaToScenario.get(id) !== ac) errors.push(`${id}: catalogue AC ${ac} does not match the acceptance manifest`);
    }
  }
  for (const [id, ac] of criteriaToScenario) {
    if (catalog.get(id) !== ac) errors.push(`${ac}: scenario ${id} missing or incorrectly mapped in .NET catalogue`);
  }

  if (errors.length > 0) {
    console.error(`COVERAGE MANIFEST INVALID (${errors.length}):`);
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
  }
  console.log(`COVERAGE MAPPINGS OK: ${knownCriteria.length}/85 criteria, ${catalog.size} .NET scenarios, ${featureFiles.length} feature files (mapping only; runtime, semantic acceptance and qualification are separate)`);
}

main();
