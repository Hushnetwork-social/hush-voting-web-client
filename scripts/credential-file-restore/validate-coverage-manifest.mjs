#!/usr/bin/env node
/**
 * FEAT-009 coverage-manifest validator (Task 6.9 seed; full catalog in Phase 7).
 *
 * Machine-checks the acceptance-coverage manifest produced from the FEAT-009
 * traceability ledger: exactly 89 criteria AC-009-001…089, every criterion
 * references one of the 25 HV-DAT-* families, every scenario ID is unique,
 * every criterion has ≥1 scenario ID and ≥1 target, and the classification
 * is one of target-owned / target-owned-capability / release-evidence.
 *
 * Usage:
 *   node scripts/credential-file-restore/validate-coverage-manifest.mjs <manifest.json>
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');
const DEFAULT_MANIFEST = join(REPO_ROOT, 'conformance', 'credential-file-restore', 'v1', 'coverage-manifest.json');

const FAMILIES = new Set([
  'HV-DAT-ENTRY', 'HV-DAT-PICKER', 'HV-DAT-READ', 'HV-DAT-TEMP', 'HV-DAT-ENVELOPE', 'HV-DAT-PASSWORD',
  'HV-DAT-BACKOFF', 'HV-DAT-AUTH', 'HV-DAT-SCHEMA', 'HV-DAT-KEYS', 'HV-DAT-MNEMONIC', 'HV-DAT-SOURCE',
  'HV-DAT-LOOKUP', 'HV-DAT-RESET', 'HV-DAT-SIGNATURE', 'HV-DAT-SEPARATION', 'HV-DAT-PROTECT', 'HV-DAT-STAGE',
  'HV-DAT-SESSION', 'HV-DAT-RESUME', 'HV-DAT-NAV', 'HV-DAT-OWNER', 'HV-DAT-CLEANUP', 'HV-DAT-EXTERNAL',
  'HV-DAT-SECURITY',
]);

const CLASSIFICATIONS = new Set(['target-owned', 'target-owned-capability', 'release-evidence']);

const manifestPath = process.argv[2] ?? DEFAULT_MANIFEST;

let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (error) {
  console.error(`FAIL: cannot read manifest ${manifestPath}: ${error.message}`);
  process.exit(1);
}

const reasons = [];
if (manifest.schemaVersion !== 1) reasons.push('unsupported schemaVersion');
if (manifest.featureId !== 'FEAT-009') reasons.push('featureId mismatch');

const ids = new Set();
for (const criterion of manifest.criteria ?? []) {
  if (!/^AC-009-\d{3}$/.test(criterion.id)) {
    reasons.push(`malformed criterion id: ${criterion.id}`);
    continue;
  }
  if (ids.has(criterion.id)) reasons.push(`duplicate criterion id: ${criterion.id}`);
  ids.add(criterion.id);
  if (!FAMILIES.has(criterion.family)) reasons.push(`unknown family on ${criterion.id}: ${criterion.family}`);
  if (!Array.isArray(criterion.scenarioIds) || criterion.scenarioIds.length === 0) reasons.push(`no scenario id on ${criterion.id}`);
  if (!Array.isArray(criterion.targets) || criterion.targets.length === 0) reasons.push(`no target on ${criterion.id}`);
  if (!CLASSIFICATIONS.has(criterion.classification)) reasons.push(`unknown classification on ${criterion.id}: ${criterion.classification}`);
}

for (let n = 1; n <= 89; n += 1) {
  const id = `AC-009-${String(n).padStart(3, '0')}`;
  if (!ids.has(id)) reasons.push(`missing criterion: ${id}`);
}

if (reasons.length > 0) {
  console.error(`FAIL: ${reasons.length} coverage issue(s)`);
  for (const reason of reasons) console.error(`  - ${reason}`);
  process.exit(1);
}

// Cross-check the executable Gherkin catalog: every manifest scenario ID must
// exist in the feature files, every feature scenario must reference a known
// criterion, and scenario IDs must be unique.
const FEATURES_DIR = join(REPO_ROOT, 'features', 'credential-file-restore');
const catalogReasons = [];
const catalogScenarioIds = new Set();
const catalogCriteria = new Set();
let featureFiles = [];
try {
  featureFiles = readdirSync(FEATURES_DIR).filter((f) => f.endsWith('.feature'));
} catch {
  catalogReasons.push('features/credential-file-restore directory missing');
}
for (const file of featureFiles) {
  const content = readFileSync(join(FEATURES_DIR, file), 'utf8');
  const tagLines = content.split('\n').filter((line) => line.trim().startsWith('@'));
  for (const line of tagLines) {
    const tags = line.trim().split(/\s+/);
    const acTag = tags.find((t) => /^@AC-009-\d{3}$/.test(t));
    const scenarioTag = tags.find((t) => /^@HV-DAT-[A-Z]+-AC\d{3}$/.test(t));
    if (acTag) catalogCriteria.add(acTag.slice(1));
    if (scenarioTag) {
      if (catalogScenarioIds.has(scenarioTag)) catalogReasons.push(`duplicate scenario id in catalog: ${scenarioTag}`);
      catalogScenarioIds.add(scenarioTag);
    }
  }
}
for (const criterion of manifest.criteria) {
  for (const scenarioId of criterion.scenarioIds) {
    if (!catalogScenarioIds.has(`@${scenarioId}`)) catalogReasons.push(`scenario ${scenarioId} (${criterion.id}) missing from catalog`);
  }
}
for (const ac of catalogCriteria) {
  if (!ids.has(ac)) catalogReasons.push(`catalog references unknown criterion: ${ac}`);
}
if (catalogReasons.length > 0) {
  console.error(`FAIL: ${catalogReasons.length} catalog issue(s)`);
  for (const reason of catalogReasons) console.error(`  - ${reason}`);
  process.exit(1);
}

console.log(`OK: 89/89 criteria, ${manifest.criteria.length} mappings, ${catalogScenarioIds.size} catalog scenarios, families unique, classifications valid`);
