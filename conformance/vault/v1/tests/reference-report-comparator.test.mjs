import test from 'node:test';
import assert from 'node:assert/strict';
import { compareReports } from '../../../../scripts/vault/compare-reference-reports.mjs';

function report(generator) {
  return {
    schemaVersion: 1,
    generator,
    corpusVersion: '1.0.0',
    manifestSha256: 'a'.repeat(64),
    passed: true,
    total: 1,
    records: [{
      id: 'C-001',
      category: 'canonical',
      ok: true,
      expectedDigest: 'b'.repeat(64),
      actualDigest: 'b'.repeat(64),
    }],
  };
}

test('accepts equivalent independently generated reports', () => {
  const result = compareReports(report('hush-vault-ts-reference'), report('hush-vault-rust-reference'));
  assert.equal(result.total, 1);
});

test('rejects digest, record, and failure divergence without echoing vector content', () => {
  const ts = report('hush-vault-ts-reference');
  const rust = report('hush-vault-rust-reference');
  rust.records[0].actualDigest = 'c'.repeat(64);
  assert.throws(() => compareReports(ts, rust), /canonical:C-001/);
  rust.records[0].actualDigest = 'b'.repeat(64);
  rust.passed = false;
  assert.throws(() => compareReports(ts, rust), /contains mismatches/);
});

test('rejects undeclared categories and malformed digests', () => {
  const ts = report('hush-vault-ts-reference');
  const rust = report('hush-vault-rust-reference');
  ts.records[0].category = 'secret-value';
  assert.throws(() => compareReports(ts, rust), /invalid record category/);
  ts.records[0].category = 'canonical';
  ts.records[0].actualDigest = 'not-a-digest';
  assert.throws(() => compareReports(ts, rust), /invalid digest/);
});
