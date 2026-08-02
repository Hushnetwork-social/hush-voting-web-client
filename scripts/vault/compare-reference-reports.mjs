#!/usr/bin/env node
/** Compare independently generated TypeScript and Rust vault reports. */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA256 = /^[0-9a-f]{64}$/;
const CATEGORIES = new Set([
  'schema', 'canonical', 'algorithm', 'password', 'lifecycle', 'session',
  'typed-result', 'integrity', 'extension', 'migration', 'performance',
]);

function validateReport(report, expectedGenerator) {
  if (report?.schemaVersion !== 1 || report?.corpusVersion !== '1.0.0') throw new Error('unsupported report contract');
  if (report.generator !== expectedGenerator) throw new Error('unexpected report generator');
  if (!SHA256.test(report.manifestSha256 ?? '')) throw new Error('invalid report manifest digest');
  if (typeof report.passed !== 'boolean' || !Number.isSafeInteger(report.total) || !Array.isArray(report.records)) {
    throw new Error('invalid report summary');
  }
  if (report.total !== report.records.length) throw new Error('report total mismatch');
  const identifiers = new Set();
  for (const record of report.records) {
    if (typeof record.id !== 'string' || record.id.length === 0 || record.id.length > 256) throw new Error('invalid record identifier');
    if (!CATEGORIES.has(record.category)) throw new Error('invalid record category');
    const key = `${record.category}:${record.id}`;
    if (identifiers.has(key)) throw new Error('duplicate report record');
    identifiers.add(key);
    for (const digest of [record.expectedDigest, record.actualDigest]) {
      if (digest !== undefined && !SHA256.test(digest)) throw new Error(`invalid digest for ${key}`);
    }
    for (const code of [record.expectedCode, record.actualCode]) {
      if (code !== undefined && (typeof code !== 'string' || code.length === 0 || code.length > 64)) {
        throw new Error(`invalid code for ${key}`);
      }
    }
  }
}

function comparable(record) {
  return JSON.stringify({
    id: record.id,
    category: record.category,
    ok: record.ok,
    expectedDigest: record.expectedDigest,
    actualDigest: record.actualDigest,
    expectedCode: record.expectedCode,
    actualCode: record.actualCode,
  });
}

export function compareReports(typeScriptReport, rustReport) {
  validateReport(typeScriptReport, 'hush-vault-ts-reference');
  validateReport(rustReport, 'hush-vault-rust-reference');
  if (!typeScriptReport.passed || !rustReport.passed) throw new Error('reference report contains mismatches');
  if (typeScriptReport.manifestSha256 !== rustReport.manifestSha256) throw new Error('reference manifest digests differ');
  if (typeScriptReport.total !== rustReport.total) throw new Error('reference report totals differ');
  const tsRecords = [...typeScriptReport.records].sort((a, b) => `${a.category}:${a.id}`.localeCompare(`${b.category}:${b.id}`));
  const rustRecords = [...rustReport.records].sort((a, b) => `${a.category}:${a.id}`.localeCompare(`${b.category}:${b.id}`));
  for (let index = 0; index < tsRecords.length; index++) {
    if (comparable(tsRecords[index]) !== comparable(rustRecords[index])) {
      throw new Error(`reference report record differs: ${tsRecords[index].category}:${tsRecords[index].id}`);
    }
  }
  return { total: typeScriptReport.total, manifestSha256: typeScriptReport.manifestSha256 };
}

function main() {
  const [tsPath = 'conformance/reports/vault-ts-reference.json', rustPath = 'conformance/reports/vault-rust-reference.json'] = process.argv.slice(2);
  const typeScriptReport = JSON.parse(readFileSync(resolve(tsPath), 'utf8'));
  const rustReport = JSON.parse(readFileSync(resolve(rustPath), 'utf8'));
  const result = compareReports(typeScriptReport, rustReport);
  process.stdout.write(`VAULT REFERENCE REPORTS AGREE (total=${result.total}, manifest=${result.manifestSha256.slice(0, 16)})\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`VAULT REFERENCE REPORT COMPARISON FAILED: ${error.message}\n`);
    process.exitCode = 1;
  }
}
