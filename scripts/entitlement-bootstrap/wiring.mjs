#!/usr/bin/env node
/**
 * FEAT-016 BDD wiring / canonical-ID discovery validator (Phase 7 task 7.2).
 *
 * Machine-checks that the canonical production-composition journeys are
 * fully wired and non-zero discovered:
 *  1. every canonical scenario ID (13) appears as a scenario tag in exactly
 *     one `features/licence-entitlements/*.feature` scenario;
 *  2. no unknown or duplicated AT-LIC/AT-LIC-016 ID is introduced;
 *  3. every scenario step phrase used by the features has a matching step
 *     definition in `browser/licence-entitlements/steps/*.ts`;
 *  4. playwright-bdd compiles the catalog and DISCOVERS every canonical
 *     scenario (zero discovery or a missing/duplicate canonical ID is RED).
 *
 * Discovery runs `playwright test --list` against
 * `playwright.entitlement-bootstrap.config.ts`; the config only starts the
 * production web server when FEAT016_RUN_WEB=1, so listing never launches a
 * server.
 *
 * Usage: node scripts/entitlement-bootstrap/wiring.mjs
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const FEATURES_DIR = process.env.FEAT016_WIRING_FEATURES ?? join(REPO_ROOT, 'features', 'licence-entitlements');
const CANONICAL_PATH = process.env.FEAT016_CANONICAL_PATH ?? join(import.meta.dirname, 'canonical-ids.json');

const canonical = JSON.parse(readFileSync(CANONICAL_PATH, 'utf8'));
const CANONICAL_IDS = new Set(canonical.scenarioIds.map((entry) => entry.id));

const ID_RE = /@(AT-LIC-016-\d{3}|AT-LIC-\d{3})\b/g;

function fail(message) {
  console.error(`WIRING FAIL: ${message}`);
  process.exitCode = 1;
}

const features = readdirSync(FEATURES_DIR)
  .filter((name) => name.endsWith('.feature'))
  .map((name) => join(FEATURES_DIR, name));

const scenarioIdOwners = new Map();
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

// 3+4. bddgen compiles features+steps and fails non-zero on missing step
// definitions; then playwright-bdd discovery lists every generated scenario.
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

try {
  execFileSync('npx', ['bddgen', '--config', 'playwright.entitlement-bootstrap.config.ts'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: 'pipe',
    timeout: 120_000,
  });
} catch (error) {
  const output = typeof error.stdout === 'string' ? error.stdout : '';
  fail(`bddgen failed (missing step definitions or generation error): ${output.slice(0, 600) || error.message}`);
}

let listed = '';
try {
  listed = execFileSync(
    'npx',
    ['playwright', 'test', '--config', 'playwright.entitlement-bootstrap.config.ts', '--list'],
    { cwd: REPO_ROOT, encoding: 'utf8', stdio: 'pipe', timeout: 120_000 },
  );
} catch (error) {
  const output = typeof error.stdout === 'string' ? error.stdout : '';
  fail(`playwright --list failed: ${output.slice(0, 800) || error.message}`);
}

const discoveredTitles = listed
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => line.length > 0 && !line.startsWith('Using') && !line.startsWith('Running') && !line.startsWith('npx'));
if (discoveredTitles.length === 0) {
  fail('zero BDD discovery (playwright --list found no scenarios)');
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
  if (!discoveredTitles.some((line) => line.includes(title))) {
    fail(`canonical scenario ${id} ("${title}") was not discovered by playwright-bdd`);
  }
}

if (process.exitCode === undefined) {
  console.log(
    `WIRING OK (${features.length} feature files, ${CANONICAL_IDS.size}/13 canonical scenario ids discovered and unique, all step phrases defined)`,
  );
}
