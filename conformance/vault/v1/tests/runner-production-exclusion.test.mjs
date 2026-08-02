import test from 'node:test';
import assert from 'node:assert/strict';
import { runProductionExclusion, scanText } from '../../../../scripts/vault/production-exclusion.mjs';

test('runner, deterministic providers, and public vector fingerprints are excluded', () => {
  assert.deepEqual(runProductionExclusion(), []);
});

test('an accidental production dependency edge is detected', () => {
  assert.deepEqual(scanText("import '../../../tools/vault-reference-runner';", ['tools/vault-reference-runner']), ['tools/vault-reference-runner']);
  assert.deepEqual(scanText('const mode = "DETERMINISTIC_TEST_PROVIDER";', ['DETERMINISTIC_TEST_PROVIDER']), ['DETERMINISTIC_TEST_PROVIDER']);
});

test('a clean production module has no findings', () => {
  assert.deepEqual(scanText("export const safe = 'vault-core';", ['vault-reference-runner', 'DETERMINISTIC_TEST_PROVIDER']), []);
});
