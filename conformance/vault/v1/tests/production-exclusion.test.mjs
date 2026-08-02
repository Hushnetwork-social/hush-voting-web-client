/**
 * Vault corpus production-exclusion tests (Task 2.6).
 * Test-only selectors and public synthetic credentials must never cross into production
 * source, scripts, or corpus-unrelated paths.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { ROOT } from '../scripts/generate-manifest.mjs';

const PROD_SOURCE_DIRS = [join(ROOT, '../../../src'), join(ROOT, '../../../scripts')];
const ALLOWLIST_PREFIXES = ['conformance/vault/', 'conformance/identity/'];

/** All production source files (ts/tsx/mjs/js/json), excluding reference-only paths. */
const REFERENCE_ONLY = ['src/lib/vault-core/canonical/suite-reference.ts', 'src/lib/vault-core/conformance/'];
function productionFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (['node_modules', '.next', '.next-web', '.next-static', '.next-tauri', 'out', 'target', 'coverage'].includes(entry)) continue;
        walk(p);
      } else if (/\.(ts|tsx|mjs|js|json)$/.test(entry)) {
        const rel = relative(join(ROOT, '../../..'), p).split('/').join('/');
        if (REFERENCE_ONLY.some((r) => rel === r || rel.startsWith(r))) continue;
        out.push(p);
      }
    }
  };
  for (const dir of PROD_SOURCE_DIRS) {
    if (existsSync(dir)) walk(dir);
  }
  return out;
}

test('deterministic suite selectors never appear in production source outside allowlist', () => {
  const selectors = ['DETERMINISTIC_TEST_PROVIDER', 'vault-reference-runner', 'PUBLIC_TEST_CREDENTIAL'];
  const findings = [];
  for (const file of productionFiles()) {
    const rel = relative(join(ROOT, '../../..'), file);
    if (ALLOWLIST_PREFIXES.some((p) => rel.startsWith(p))) continue;
    const content = readFileSync(file, 'utf8');
    for (const s of selectors) {
      if (content.includes(s)) findings.push(`${rel} contains ${s}`);
    }
  }
  assert.deepEqual(findings, [], 'test-only selectors leaked into production source');
});

test('metadata declares public-only test credentials with an allowlist', () => {
  const metadata = JSON.parse(readFileSync(join(ROOT, 'metadata.json'), 'utf8'));
  assert.equal(metadata.publicTestCredentials.declaredPublicOnly, true);
  for (const path of metadata.publicTestCredentials.allowlistPaths) {
    assert.ok(existsSync(join(ROOT, path)), `allowlisted corpus path missing: ${path}`);
  }
});

test('corpus paths contain no stable device/session identifiers or secret patterns', () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  for (const f of manifest.files) {
    assert.doesNotMatch(f.path, /(password|secret|private|mnemonic|key)[-/]/, `suspicious corpus path: ${f.path}`);
  }
});
