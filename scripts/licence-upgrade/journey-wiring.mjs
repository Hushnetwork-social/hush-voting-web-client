#!/usr/bin/env node
/**
 * FEAT-017 BDD wiring / canonical-ID discovery validator (Phase 7 task 7.2).
 *
 * Machine-checks that the canonical production-composition journeys are
 * fully wired and non-zero discovered:
 *  1. every FEAT-017 owned canonical scenario ID (AT-LIC-001/004/005/006/
 *     008/009/015/016) appears as a scenario tag in exactly one
 *     `features/licence-upgrade/*.feature` scenario;
 *  2. no unknown or duplicated AT-LIC ID is introduced by the FEAT-017
 *     journey catalog;
 *  3. every scenario step phrase used by the FEAT-017 features has a matching
 *     step definition in `browser/licence-upgrade/steps/*.ts` or the shared
 *     `browser/licence-entitlements/steps/*.ts` module;
 *  4. playwright-bdd compiles the catalog and DISCOVERS every canonical
 *     scenario (zero discovery or a missing/duplicate canonical ID is RED);
 *  5. every regression scenario ID (AT-LIC-003/007/010/011/012) that
 *     FEAT-017 inherits from FEAT-016 remains wired in the entitlement
 *     journey catalog (`features/licence-entitlements/*.feature`) so the
 *     recovery journeys stay green.
 *
 * Discovery runs `playwright test --list` against
 * `playwright.licence-upgrade.config.ts`; the config only starts the
 * production web server when FEAT017_RUN_WEB=1, so listing never launches a
 * server. The full live run requires the controlled real HushServerNode
 * fixture (EXT-017-001) and is release-readiness evidence only.
 *
 * Usage: node scripts/licence-upgrade/journey-wiring.mjs
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const FEATURES_DIR = process.env.FEAT017_WIRING_FEATURES ?? join(REPO_ROOT, 'features', 'licence-upgrade');
const REGRESSION_FEATURES_DIR =
  process.env.FEAT017_WIRING_REGRESSION_FEATURES ?? join(REPO_ROOT, 'features', 'licence-entitlements');
const CANONICAL_PATH = process.env.FEAT017_CANONICAL_PATH ?? join(import.meta.dirname, 'canonical-ids.json');

const canonical = JSON.parse(readFileSync(CANONICAL_PATH, 'utf8'));
const OWNED_IDS = new Set(canonical.ownedScenarioIds.map((entry) => entry.id));
const REGRESSION_IDS = new Set(canonical.regressionScenarioIds.map((entry) => entry.id));

const ID_RE = /@(AT-LIC-016-\d{3}|AT-LIC-\d{3})\b/g;

function fail(message) {
  console.error(`WIRING FAIL: ${message}`);
  process.exitCode = 1;
}

function scanScenarioIds(dir, owners) {
  const features = readdirSync(dir)
    .filter((name) => name.endsWith('.feature'))
    .map((name) => join(dir, name));
  let pendingTags = [];
  for (const feature of features) {
    for (const raw of readFileSync(feature, 'utf8').split('\n')) {
      const line = raw.trim();
      if (line.startsWith('@')) {
        for (const match of line.matchAll(ID_RE)) pendingTags.push(match[1]);
        continue;
      }
      if (/^Scenario:/i.test(line)) {
        for (const id of pendingTags) {
          if (owners.has(id)) {
            fail(`duplicate canonical scenario id ${id} (${owners.get(id)} and ${feature})`);
            continue;
          }
          owners.set(id, `${feature} -> ${line}`);
        }
        pendingTags = [];
        continue;
      }
      if (/^(Feature:|Background:|Scenario Outline:)/i.test(line)) {
        pendingTags = [];
      }
    }
  }
}

// 1+2. Owned canonical inventory completeness and uniqueness.
const scenarioIdOwners = new Map();
scanScenarioIds(FEATURES_DIR, scenarioIdOwners);
for (const id of OWNED_IDS) {
  if (!scenarioIdOwners.has(id)) {
    fail(`owned canonical scenario id ${id} is missing from the FEAT-017 journey catalog`);
  }
}
for (const id of scenarioIdOwners.keys()) {
  if (!OWNED_IDS.has(id)) {
    fail(`unknown scenario id ${id} in the FEAT-017 journey catalog (not in the owned freeze)`);
  }
}

// 5. Regression scenarios remain wired in the FEAT-016 entitlement catalog.
const regressionOwners = new Map();
scanScenarioIds(REGRESSION_FEATURES_DIR, regressionOwners);
for (const id of REGRESSION_IDS) {
  if (!regressionOwners.has(id)) {
    fail(`regression scenario id ${id} is no longer wired in the entitlement journey catalog`);
  }
}

// 3+4. bddgen compiles features+steps and fails non-zero on missing step
// definitions; then playwright-bdd discovery lists every generated scenario.
if (process.env.FEAT017_WIRING_SKIP_LIST === '1') {
  if (process.exitCode === undefined) {
    console.log(
      `WIRING OK (${OWNED_IDS.size}/8 owned canonical scenario ids present and unique; ${REGRESSION_IDS.size} regression ids wired; discovery listing skipped by env)`,
    );
  } else {
    console.error('WIRING FAILED (catalog checks above)');
  }
  process.exit(process.exitCode ?? 0);
}

try {
  execFileSync('npx', ['bddgen', '--config', 'playwright.licence-upgrade.config.ts'], {
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
    ['playwright', 'test', '--config', 'playwright.licence-upgrade.config.ts', '--list'],
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
  'AT-LIC-001': 'Account popup shows the exact indexed plan, limits, and shortened public reference',
  'AT-LIC-004': 'The full-width licence page reflects the exact server catalogue in server order',
  'AT-LIC-005': 'Activation requires explicit informed confirmation and cancel commits nothing',
  'AT-LIC-006': 'A strictly higher Veritas plan activates only after indexed confirmation',
  'AT-LIC-008': 'Current lower and Enterprise actions cannot mutate the assignment',
  'AT-LIC-009': 'A stale current-plan or catalogue precondition refreshes and requires reselection',
  'AT-LIC-015': 'Back and in-app navigation preserve coherent licence state',
  'AT-LIC-016': 'Licence surfaces are accessible and responsive across supported Web viewports',
};
for (const [id, title] of Object.entries(TITLE_BY_ID)) {
  if (!discoveredTitles.some((line) => line.includes(title))) {
    fail(`canonical scenario ${id} ("${title}") was not discovered by playwright-bdd`);
  }
}

if (process.exitCode === undefined) {
  console.log(
    `WIRING OK (${OWNED_IDS.size}/8 owned canonical scenario ids discovered and unique, ${REGRESSION_IDS.size} regression ids wired, all step phrases defined)`,
  );
}
