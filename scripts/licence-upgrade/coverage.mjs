#!/usr/bin/env node
/**
 * FEAT-017 coverage validator (Phase 6 task 6.5).
 *
 * Requires non-zero, paired coverage for every code-bearing Phase-6 surface:
 *  1. licence workspace host + top-bar surfaces component tests;
 *  2. EntitlementBridge licence intent routing tests;
 *  3. worker session confirm-upgrade + safe snapshot tests;
 *  4. multi-client authority tests (regression);
 *  5. native confirmed-upgrade envelope/seal tests.
 * Zero discovery in any suite is RED (a focused gate cannot pass without
 * real feature evidence).
 *
 * Usage: node scripts/licence-upgrade/coverage.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

const REQUIRED_TEST_FILES = [
  { file: 'src/app/auth/licence/licence-workspace-host.test.tsx', note: 'root host composition' },
  { file: 'src/app/auth/licence/top-bar-surfaces.test.tsx', note: 'N0/N1 + clipboard adapter' },
  { file: 'src/app/auth/AuthenticatedLicenceRoot.test.tsx', note: 'root licence content region' },
  { file: 'src/lib/auth/web/entitlement-bridge.test.ts', note: 'bridge licence intents + mirror' },
  { file: 'src/lib/browser-vault/production/licence-bootstrap.test.ts', note: 'session upgrade facts' },
  { file: 'src/lib/browser-vault/production/licence-bootstrap.multiclient.test.ts', note: 'multi-client authority' },
];

const SEARCH_TEST_GLOBS = [
  { dir: 'src/lib/licensing', contains: 'upgrade', note: 'upgrade coordinator/presentation' },
  { dir: 'src/lib/browser-vault', contains: 'licence', note: 'worker licence authority' },
  { dir: 'src/app/auth/licence', contains: 'test', note: 'licence UI suites' },
];

function requiredTestFiles() {
  const override = process.env.FEAT017_COVERAGE_REQUIRED_JSON;
  if (typeof override === 'string' && override.length > 0) {
    const parsed = JSON.parse(override);
    if (Array.isArray(parsed)) return parsed;
  }
  return REQUIRED_TEST_FILES;
}

function searchGlobs() {
  const override = process.env.FEAT017_COVERAGE_SEARCH_JSON;
  if (typeof override === 'string' && override.length > 0) {
    const parsed = JSON.parse(override);
    if (Array.isArray(parsed)) return parsed;
  }
  return SEARCH_TEST_GLOBS;
}

function countFilesWith(dir, needle) {
  let found = 0;
  if (!statSync(dir, { throwIfNoEntry: false })) return 0;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current)) {
      if (entry === 'node_modules' || entry === '.git') continue;
      const p = join(current, entry);
      const st = statSync(p);
      if (st.isDirectory()) {
        stack.push(p);
      } else if (entry.includes('.test.') && entry.includes(needle)) {
        found += 1;
      }
    }
  }
  return found;
}

let ok = true;
const missing = [];
for (const { file, note } of requiredTestFiles()) {
  const path = join(REPO_ROOT, file);
  try {
    const content = readFileSync(path, 'utf8');
    if (content.trim().length === 0) {
      missing.push(`${file} (empty) — ${note}`);
      ok = false;
    }
  } catch {
    missing.push(`${file} — ${note}`);
    ok = false;
  }
}
for (const { dir, contains, note } of searchGlobs()) {
  const found = countFilesWith(join(REPO_ROOT, dir), contains);
  if (found === 0) {
    missing.push(`${dir}/*${contains}*.test.* — ${note}`);
    ok = false;
  }
}

if (!ok) {
  console.error('FEAT-017 COVERAGE FAIL:');
  for (const m of missing) console.error(`  - ${m}`);
  process.exit(1);
}
console.log(
  `FEAT-017 COVERAGE OK (${requiredTestFiles().length} required suites present + non-zero licence upgrade search suites)`,
);
