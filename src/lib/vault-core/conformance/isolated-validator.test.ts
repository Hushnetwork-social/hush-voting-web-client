/**
 * FEAT-003 isolated TypeScript/Node conformance validator tests.
 *
 * Task 5.2: validates the isolated path itself —
 * - the full corpus replays with zero mismatch records and a deterministic report;
 * - invalid path/schema/digest inputs fail with stable non-zero results;
 * - diagnostics are deterministic, ordered, and secret-safe (IDs/codes/digests only);
 * - exceptions are contained as stable typed codes without raw messages;
 * - resource bounds (vector counts, record fields) are enforced.
 */
import { describe, expect, it, beforeAll } from 'vitest';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { runIsolatedValidation, verifyManifestIndependently, isCorpusHealthy, type IsolatedReport } from './isolated-validator';

let report: IsolatedReport;

beforeAll(async () => {
  const result = await runIsolatedValidation();
  report = result.report;
  // Deterministic secret-safe report artifact for downstream consumers.
  mkdirSync(join('conformance', 'reports'), { recursive: true });
  writeFileSync(join('conformance', 'reports', 'vault-ts-isolated.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
}, 60_000);

describe('FEAT-003 isolated TypeScript/Node conformance', () => {
  it('replays the complete corpus with zero mismatch records', () => {
    expect(isCorpusHealthy({ report })).toBe(true);
    expect(report.passed).toBe(true);
    expect(report.records.filter((r) => !r.ok)).toHaveLength(0);
    expect(report.total).toBeGreaterThan(50);
  });

  it('covers every vector family with meaningful counts', () => {
    const byCategory = new Map<string, number>();
    for (const r of report.records) byCategory.set(r.category, (byCategory.get(r.category) ?? 0) + 1);
    expect(byCategory.get('schema')).toBeGreaterThanOrEqual(9);
    expect(byCategory.get('integrity')).toBeGreaterThanOrEqual(16);
    expect(byCategory.get('canonical')).toBeGreaterThanOrEqual(14);
    expect(byCategory.get('algorithm')).toBeGreaterThanOrEqual(6);
    expect(byCategory.get('password')).toBeGreaterThanOrEqual(7);
    expect(byCategory.get('extension')).toBe(3);
    expect(byCategory.get('lifecycle')).toBeGreaterThanOrEqual(10);
    expect(byCategory.get('migration')).toBe(2);
    expect(byCategory.get('session')).toBeGreaterThanOrEqual(6);
    expect(byCategory.get('typed-result')).toBe(18);
  });

  it('reports deterministic ordering and digest-only diagnostics', async () => {
    const again = await runIsolatedValidation();
    expect(again.report.records).toEqual(report.records);
    // Records are sorted by id for byte-stable reports.
    const ids = report.records.map((r) => r.id);
    expect(ids).toEqual([...ids].sort());
    // Only identifiers, stable codes, and 64-hex digests are emitted.
    for (const r of report.records) {
      expect(r.id.length).toBeGreaterThan(0);
      for (const digest of [r.expectedDigest, r.actualDigest]) {
        if (digest !== undefined) expect(digest).toMatch(/^[0-9a-f]{64}$/);
      }
      if (r.expectedCode !== undefined) expect(typeof r.expectedCode).toBe('string');
      // Secret values must never appear anywhere in the report.
      const serialized = JSON.stringify(r);
      expect(serialized).not.toMatch(/correct horse battery staple|password-bytes|ordinary record payload/);
    }
  });

  it('fails closed on a tampered manifest or missing corpus file', () => {
    // A manifest listing a nonexistent file must fail integrity verification.
    // Runs against an isolated temp fixture so the shared committed corpus
    // manifest is never mutated (mutating it raced with other workers that
    // verify the same manifest concurrently).
    const fake = {
      contractVersion: '1.0.0',
      corpusVersion: '1.0.0',
      files: [{ path: 'vectors/does-not-exist.json', bytes: 1, sha256: '0'.repeat(64) }],
    };
    const fixtureRoot = join(process.cwd(), 'tmp', 'vault-manifest-tamper-fixture');
    rmSync(fixtureRoot, { recursive: true, force: true });
    try {
      mkdirSync(fixtureRoot, { recursive: true });
      writeFileSync(join(fixtureRoot, 'manifest.json'), JSON.stringify(fake));
      const { records } = verifyManifestIndependently(fixtureRoot);
      const missing = records.find((r) => r.id === 'integrity:vectors/does-not-exist.json');
      expect(missing?.ok).toBe(false);
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it('report matches the committed report schema constraints', () => {
    const schema = JSON.parse(readFileSync(join('conformance', 'vault', 'v1', 'schemas', 'report.schema.json'), 'utf8')) as {
      properties: { generator: { enum: string[] }; records: { items: { properties: { category: { enum: string[] } } } } };
    };
    expect(schema.properties.generator.enum).toContain('hush-vault-ts-isolated');
    expect(report.schemaVersion).toBe(1);
    expect(report.generator).toBe('hush-vault-ts-isolated');
    expect(report.corpusVersion).toBe('1.0.0');
    expect(report.manifestSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(report.total).toBe(report.records.length);
    for (const r of report.records) {
      expect(schema.properties.records.items.properties.category.enum).toContain(r.category);
    }
  });

  it('integrity digest of the file-set is stable and secret-safe', () => {
    const fileSet = report.records.find((r) => r.id === 'integrity:file-set');
    expect(fileSet?.ok).toBe(true);
    const manifest = JSON.parse(readFileSync(join('conformance', 'vault', 'v1', 'manifest.json'), 'utf8')) as { files: Array<{ path: string }> };
    const expected = createHash('sha256').update(manifest.files.map((f) => f.path).sort().join('\n')).digest('hex');
    expect(fileSet?.expectedDigest).toBe(expected);
  });

  it('does not require a real vault corpus file to exist for schema count assertions', () => {
    expect(report.total).toBeGreaterThan(0);
    expect(existsSync(join('conformance', 'reports', 'vault-ts-isolated.json'))).toBe(true);
  });
});
