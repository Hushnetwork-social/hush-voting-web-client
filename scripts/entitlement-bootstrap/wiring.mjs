#!/usr/bin/env node
/** FEAT-016 Phase 7 Tasks 7.2/7.6: all 13 originals are owned by .NET.
 * Retired source must stay absent; unresolved/unrecorded retirements are red.
 * Discovery never substitutes for runtime or full acceptance evidence.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const FEATURES_DIR = process.env.FEAT016_WIRING_FEATURES ?? join(REPO_ROOT, 'features', 'licence-entitlements');
const CANONICAL_PATH = process.env.FEAT016_CANONICAL_PATH ?? join(import.meta.dirname, 'canonical-ids.json');
const SERVER_ROOT = join(REPO_ROOT, '..', 'hush-server-node');
const DOTNET_AREA = join(SERVER_ROOT, 'Node', 'HushNode.IntegrationTests', 'HushVoting');

const canonical = JSON.parse(readFileSync(CANONICAL_PATH, 'utf8'));
const CANONICAL_IDS = new Set(canonical.scenarioIds.map((entry) => entry.id));

const ID_RE = /@(AT-LIC-016-\d{3}|AT-LIC-\d{3})\b/g;

function fail(message) {
  console.error(`WIRING FAIL: ${message}`);
  process.exitCode = 1;
}

const features = (existsSync(FEATURES_DIR) ? readdirSync(FEATURES_DIR) : [])
  .filter(name => name.endsWith('.feature')).map(name => join(FEATURES_DIR, name));
const dotnetFeatures = new Set();
if (!process.env.FEAT016_WIRING_FEATURES) {
  const manifest = JSON.parse(readFileSync(process.env.FEAT016_WIRING_MIGRATION_MANIFEST ?? join(DOTNET_AREA, 'migration-manifest.json'), 'utf8'));
  for (const entry of manifest.files.filter(file => file.group === 'licence-entitlements')) {
    if (entry.retirement?.state !== 'typescript-source-retired'
      || !entry.scenarios?.length || entry.scenarios.some(scenario => scenario.status !== 'passed')) {
      fail(`unresolved or unrecorded retirement: ${entry.source}`);
      continue;
    }
    if (existsSync(join(REPO_ROOT, entry.source))) fail(`retired TypeScript source still exists: ${entry.source}`);
    const path = join(DOTNET_AREA, entry.destination);
    if (!existsSync(path)) { fail(`missing .NET replacement: ${entry.destination}`); continue; }
    features.push(path); dotnetFeatures.add(path);
  }
}

const scenarioIdOwners = new Map();
const dotnetIds = new Set();
const featureLines = [];
for (const feature of features) {
  const lines = readFileSync(feature, 'utf8').split('\n');
  featureLines.push(...lines.map((line) => ({ feature, line })));
  let pendingTags = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('@')) {
      for (const match of line.matchAll(ID_RE)) pendingTags.push(match[1]);
      continue;
    }
    if (/^Scenario:/i.test(line)) {
      for (const id of pendingTags) {
        if (scenarioIdOwners.has(id)) {
          fail(`duplicate canonical scenario id ${id} (${scenarioIdOwners.get(id)} and ${feature})`);
          continue;
        }
        scenarioIdOwners.set(id, `${feature} -> ${line}`);
        if (dotnetFeatures.has(feature)) dotnetIds.add(id);
      }
      pendingTags = [];
      continue;
    }
    if (/^(Feature:|Background:|Scenario Outline:)/i.test(line)) {
      pendingTags = [];
    }
  }
}

// 1+2. Canonical inventory completeness and uniqueness.
for (const id of CANONICAL_IDS) {
  if (!scenarioIdOwners.has(id)) {
    fail(`canonical scenario id ${id} is missing from the journey catalog`);
  }
}
for (const id of scenarioIdOwners.keys()) {
  if (!CANONICAL_IDS.has(id)) {
    fail(`unknown scenario id ${id} in the journey catalog (not in the canonical freeze)`);
  }
}

// Discover the verified .NET assembly; no TypeScript runner remains.
if (process.env.FEAT016_WIRING_SKIP_LIST === '1') {
  if (process.exitCode === undefined) {
    console.log(
      `WIRING OK (${features.length} feature files, ${CANONICAL_IDS.size}/13 canonical scenario ids present and unique; discovery listing skipped by env)`,
    );
  } else {
    console.error('WIRING FAILED (catalog checks above)');
  }
  process.exit(process.exitCode ?? 0);
}

let dotnetTitles = [];
if (dotnetIds.size > 0) {
  try {
    dotnetTitles = execFileSync('bash', [join(SERVER_ROOT, 'scripts', 'run-hushvoting-e2e.sh'), '--list'],
      { cwd: SERVER_ROOT, encoding: 'utf8', stdio: 'pipe', timeout: 90_000 }).split('\n').map(line => line.trim());
  } catch {
    fail('.NET discovery/provenance failed; build the retired group with npm run test:licence-direct-free:bdd');
  }
}

const TITLE_BY_ID = {
  'AT-LIC-002': 'A no-active user enters only after signed Direct Free is indexed',
  'AT-LIC-003': 'Entitlement authority failure never fabricates a plan',
  'AT-LIC-007': 'Delayed confirmation retries the exact licence transaction',
  'AT-LIC-010': 'Expiry triggers authoritative Direct Free bootstrap',
  'AT-LIC-011': 'Lock prevents a late entitlement result from restoring access',
  'AT-LIC-012': 'Incompatible active projection cannot become Direct Free',
  'AT-LIC-016-001': 'Existing active entitlement opens without extra confirmation',
  'AT-LIC-016-002': 'One browser authority coordinates all tabs',
  'AT-LIC-016-003': 'Restart queries before resubmitting pending Direct Free',
  'AT-LIC-016-004': 'Paused chain exposes delayed recovery before 30 seconds',
  'AT-LIC-016-005': 'Temporary disconnection cannot use stale entitlement',
  'AT-LIC-016-006': 'Back cannot bypass or cancel the authenticated gate',
  'AT-LIC-016-007': 'Entitlement recovery is accessible',
};
for (const [id, title] of Object.entries(TITLE_BY_ID)) {
  const found = dotnetIds.has(id) && dotnetTitles.filter(line => line === title).length === 1;
  if (!found) {
    fail(`canonical scenario ${id} ("${title}") was not discovered by its owning runner`);
  }
}

if (process.exitCode === undefined) {
  console.log(
    `DISCOVERY OK (${CANONICAL_IDS.size}/13 unique canonical IDs: ${dotnetIds.size} .NET, ${CANONICAL_IDS.size - dotnetIds.size} remaining TypeScript; runtime and acceptance execution are separate)`,
  );
}
