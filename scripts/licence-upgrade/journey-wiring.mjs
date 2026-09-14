#!/usr/bin/env node
/** FEAT-017 Phase 7 Task 7.2: .NET catalogue/binding/discovery checks.
 * Runtime and acceptance proof require the separate real E2E command.
 * FEAT-016 regression IDs are checked for presence, not claimed as passing.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const SERVER_ROOT = join(REPO_ROOT, '..', 'hush-server-node');
const AREA = join(SERVER_ROOT, 'Node', 'HushNode.IntegrationTests', 'HushVoting');
const FEATURES_DIR = process.env.FEAT017_WIRING_FEATURES ?? join(AREA, 'Features', 'licence-upgrade');
const REGRESSION_FEATURES_DIR = process.env.FEAT017_WIRING_REGRESSION_FEATURES ?? join(AREA, 'Features', 'licence-entitlements');
const STEPS_DIR = process.env.FEAT017_WIRING_STEPS ?? join(AREA, 'Steps');
const canonical = JSON.parse(readFileSync(process.env.FEAT017_CANONICAL_PATH ?? join(import.meta.dirname, 'canonical-ids.json'), 'utf8'));
const owned = new Set(canonical.ownedScenarioIds.map(entry => entry.id));
const regressions = new Set(canonical.regressionScenarioIds.map(entry => entry.id));

function fail(message) {
  console.error(`WIRING FAIL: ${message}`);
  process.exitCode = 1;
}

/**
 * Scan a Gherkin catalogue.
 *
 * `uniqueIds` selects between the two ID models in `canonical-ids.json`:
 *  - the FEAT-017 owned catalogue is 1:1: one canonical scenario ID per
 *    journey, so a repeated ID is a wiring defect that must fail;
 *  - the inherited FEAT-016 regression catalogue uses EPIC-002 acceptance
 *    criterion tags. One criterion is legitimately covered by several
 *    scenarios (many:1, for example AT-LIC-012 across the unknown-plan,
 *    unknown-family, unknown-governance and incompatible-projection cases),
 *    so only presence is contractual there and the first owning scenario is
 *    recorded.
 */
function scan(dir, { uniqueIds }) {
  const scenarios = new Map();
  for (const file of readdirSync(dir).filter(name => name.endsWith('.feature'))) {
    let ids = [], current = null, kind = null;
    for (const raw of readFileSync(join(dir, file), 'utf8').split('\n')) {
      const line = raw.trim();
      if (line.startsWith('@')) ids.push(...[...line.matchAll(/@(AT-LIC-016-\d{3}|AT-LIC-\d{3})\b/g)].map(match => match[1]));
      else if (line.startsWith('Scenario:')) {
        if (ids.length !== 1) fail(`${file}: scenario must have exactly one canonical ID`);
        current = { title: line.slice('Scenario:'.length).trim(), steps: [] };
        for (const id of ids) {
          if (scenarios.has(id)) {
            if (uniqueIds) fail(`duplicate canonical scenario ID ${id}`);
            // Many:1 acceptance criterion tag: presence is the contract.
          } else {
            scenarios.set(id, current);
          }
        }
        ids = []; kind = null;
      } else if (/^(Feature:|Background:|Scenario Outline:|Rule:)/.test(line)) {
        if (!line.startsWith('Feature:')) fail(`${file}: unsupported catalogue construct`);
        ids = []; current = null;
      } else if (current) {
        const match = /^(Given|When|Then|And|But) (.+)$/.exec(line);
        if (match) {
          if (['Given', 'When', 'Then'].includes(match[1])) kind = match[1];
          current.steps.push({ kind, phrase: match[2] });
        }
      }
    }
  }
  return scenarios;
}

const scenarios = scan(FEATURES_DIR, { uniqueIds: true });
for (const id of owned) if (!scenarios.has(id)) fail(`owned canonical scenario ID ${id} is missing`);
for (const id of scenarios.keys()) if (!owned.has(id)) fail(`unknown owned scenario ID ${id}`);
const regressionScenarios = scan(REGRESSION_FEATURES_DIR, { uniqueIds: false });
for (const id of regressions) if (!regressionScenarios.has(id)) fail(`regression scenario ID ${id} is missing`);

// Candidate matching is restricted to scoped HushVoting C# bindings.
// Actual SpecFlow execution remains the binding authority.
const bindings = [];
for (const file of readdirSync(STEPS_DIR).filter(name => name.endsWith('.cs'))) {
  const text = readFileSync(join(STEPS_DIR, file), 'utf8');
  if (!text.includes('[Scope(Tag = "HV-E2E")]')) { fail(`${file}: missing HushVoting binding scope`); continue; }
  for (const match of text.matchAll(/\[(Given|When|Then)\((?:@"((?:[^"]|"")*)"|"((?:[^"\\]|\\.)*)")\)\]/g)) {
    const pattern = match[2] === undefined ? JSON.parse(`"${match[3]}"`) : match[2].replaceAll('""', '"');
    bindings.push({ kind: match[1], pattern: new RegExp(`^(?:${pattern})$`) });
  }
}
for (const [id, scenario] of scenarios) {
  if (scenario.steps.length === 0) fail(`${id}: no executable steps`);
  for (const step of scenario.steps) {
    const count = bindings.filter(binding => binding.kind === step.kind && binding.pattern.test(step.phrase)).length;
    if (count !== 1) fail(`${id}: expected one scoped binding candidate, found ${count} for ${step.kind} ${step.phrase}`);
  }
}
if (process.exitCode) process.exit(process.exitCode);

// Used by seeded input checks. This does not claim discovery or runtime PASS.
if (process.env.FEAT017_WIRING_SKIP_LIST === '1') {
  console.log(`CATALOGUE CHECK ONLY (${owned.size} owned IDs; ${regressions.size} regression IDs present; .NET discovery not executed)`);
  process.exit(0);
}
let listed;
try {
  listed = execFileSync('bash', [join(SERVER_ROOT, 'scripts', 'run-hushvoting-e2e.sh'), '--list'],
    { cwd: SERVER_ROOT, encoding: 'utf8', stdio: 'pipe', timeout: 90_000 });
} catch {
  fail('.NET discovery failed or build provenance is stale; run npm run test:licence-upgrade:bdd to build and execute the migrated group');
  process.exit(1);
}
const lines = listed.split('\n').map(line => line.trim());
for (const [id, scenario] of scenarios) {
  if (lines.filter(line => line === scenario.title).length !== 1) fail(`${id}: not discovered exactly once in the verified .NET assembly`);
}
if (!process.exitCode) console.log(`WIRING OK (${owned.size} .NET scenarios discovered, scoped binding candidates checked; ${regressions.size} regression IDs present; runtime execution is separate)`);
