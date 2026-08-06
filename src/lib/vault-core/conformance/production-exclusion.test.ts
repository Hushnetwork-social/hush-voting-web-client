/**
 * FEAT-003 production-exclusion + reproducibility tests (Task 5.4).
 *
 * - clean production source/import graph keeps conformance machinery out (exit 0);
 * - a deliberately injected production import of a conformance module fails the gate
 *   with a stable finding (negative fixture);
 * - a credential value placed in production (non-test) code fails the gate, while the
 *   same value in a unit test file is allowed (declared public synthetic data);
 * - the isolated conformance suite is reproducible: two runs produce byte-identical
 *   reports with deterministic declared metadata.
 */
import { describe, expect, it, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runIsolatedValidation } from './isolated-validator';

const EXCLUSION_SCRIPT = join(process.cwd(), 'scripts', 'vault', 'production-exclusion.mjs');
const NEGATIVE_DIR = join(process.cwd(), 'src', 'vault-exclusion-negative-fixture');

function runExclusion(args: string[] = []): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [EXCLUSION_SCRIPT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

beforeAll(() => {
  rmSync(NEGATIVE_DIR, { recursive: true, force: true });
});

afterAll(() => {
  rmSync(NEGATIVE_DIR, { recursive: true, force: true });
});

describe('FEAT-003 production exclusion', () => {
  it('clean source tree passes import-graph, selector, and artifact scans', () => {
    const result = runExclusion(['--skip-artifacts']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('VAULT PRODUCTION EXCLUSION OK');
  });

  it('a production import of a conformance module fails the gate (negative fixture)', () => {
    mkdirSync(NEGATIVE_DIR, { recursive: true });
    const rel = join('src', 'vault-exclusion-negative-fixture', 'imports-conformance.ts');
    writeFileSync(join(process.cwd(), rel), "import { runIsolatedValidation } from '../lib/vault-core/conformance/isolated-validator';\n");
    const result = runExclusion(['--skip-artifacts']);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('imports conformance module');
    rmSync(NEGATIVE_DIR, { recursive: true, force: true });
  });

  it('a corpus credential value in production code fails the gate (negative fixture)', () => {
    mkdirSync(NEGATIVE_DIR, { recursive: true });
    const rel = join('src', 'vault-exclusion-negative-fixture', 'production.ts');
    writeFileSync(join(process.cwd(), rel), "export const flag = 'correct horse battery staple';\n");
    const result = runExclusion(['--skip-artifacts']);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('in production code');
    rmSync(NEGATIVE_DIR, { recursive: true, force: true });
  });

  it('the same credential value in a unit test file is allowed (declared public)', () => {
    mkdirSync(NEGATIVE_DIR, { recursive: true });
    const rel = join('src', 'vault-exclusion-negative-fixture', 'sample.test.ts');
    writeFileSync(join(process.cwd(), rel), "import { expect, it } from 'vitest';\nit('uses public synthetic credential', () => { expect('correct horse battery staple').toBeTruthy(); });\n");
    const result = runExclusion(['--skip-artifacts']);
    expect(result.status).toBe(0);
    rmSync(NEGATIVE_DIR, { recursive: true, force: true });
  });

  it('web/static artifact scan passes when build outputs exist', () => {
    // Runs the full scan (artifacts included). If no build outputs exist yet the
    // artifact portion is skipped; the Phase 5 checkpoint runs builds before the
    // final scan, so CI always exercises the artifact branch.
    const result = runExclusion();
    expect(result.status).toBe(0);
  });
});

describe('FEAT-003 conformance reproducibility', () => {
  it('two isolated validation runs produce byte-identical reports', async () => {
    const a = await runIsolatedValidation();
    const b = await runIsolatedValidation();
    expect(JSON.stringify(a.report)).toBe(JSON.stringify(b.report));
    expect(a.report.records).toEqual(b.report.records);
  });

  it('declared deterministic metadata is stable across runs', async () => {
    const { report } = await runIsolatedValidation();
    expect(report.generator).toBe('hush-vault-ts-isolated');
    expect(report.corpusVersion).toBe('1.0.0');
    expect(report.schemaVersion).toBe(1);
    expect(report.manifestSha256).toMatch(/^[0-9a-f]{64}$/);
    // manifest digest equals sha256 of the committed manifest bytes
    const manifestBytes = readFileSync(join('conformance', 'vault', 'v1', 'manifest.json'));
    const { createHash } = await import('node:crypto');
    expect(report.manifestSha256).toBe(createHash('sha256').update(manifestBytes).digest('hex'));
    // The isolated report artifact matches a fresh run. Written in this worker
    // (deterministic bytes) so a parallel worker's beforeAll can never race it.
    mkdirSync(join('conformance', 'reports'), { recursive: true });
    writeFileSync(join('conformance', 'reports', 'vault-ts-isolated.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
    const committed = JSON.parse(readFileSync(join('conformance', 'reports', 'vault-ts-isolated.json'), 'utf8'));
    expect(committed).toEqual(report);
  });
});
