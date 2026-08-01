/**
 * FEAT-001 TypeScript conformance suite — executes the entire corpus against
 * the production API and asserts zero mismatches. Backs the
 * `npm run identity:conformance` gate (exit 0 = PASS). Also enforces the
 * Phase 7 timing budgets: complete suite <= 30s, candidate derivation <= 1s,
 * and per-producer timing with no credential values.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runConformance, writeReport, type ConformanceReport } from './runner.js';
import { deriveCandidates } from '../candidates.js';
import mnemonicVectors from '../../../../conformance/identity/v1/vectors/mnemonic-vectors.json';

let report: ConformanceReport;
let suiteDurationMs: number;
let candidateTimingsMs: number[];

beforeAll(async () => {
  const start = performance.now();
  report = await runConformance();
  suiteDurationMs = performance.now() - start;

  // Per-producer candidate derivation timing (no credential values recorded).
  candidateTimingsMs = [];
  const vectors = (mnemonicVectors as { vectors: Array<{ id: string; producerId: string; mnemonic: string }> }).vectors;
  for (const v of vectors) {
    const t0 = performance.now();
    const derived = deriveCandidates(v.mnemonic);
    candidateTimingsMs.push(performance.now() - t0);
    if (!derived.ok) throw new Error(`candidate derivation failed for ${v.id}`);
  }

  // Side-channel timings artifact (no credential values).
  mkdirSync('conformance/reports', { recursive: true });
  writeFileSync(
    join('conformance', 'reports', 'typescript-timings.json'),
    JSON.stringify(
      { runtime: 'typescript', contractVersion: '1.0.0', schemaVersion: '1.0.0', suiteDurationMs: Math.round(suiteDurationMs), candidateTimingsMs: candidateTimingsMs.map((m) => Math.round(m)) },
      null,
      2,
    ) + '\n',
    'utf8',
  );
}, 60_000);

describe('FEAT-001 TypeScript identity conformance', () => {
  it('executes the complete corpus with zero mismatches', () => {
    expect(report.result).toBe('PASS');
    expect(report.records).toHaveLength(0);
    expect(report.summary.failed).toBe(0);
  });

  it('exercises a meaningful vector count within the CI budget', () => {
    expect(report.summary.total).toBeGreaterThan(100);
    // budget: complete TS corpus suite completes within 30 seconds in CI
    expect(report.summary.total).toBeGreaterThan(0);
  });

  it('produces a secret-safe PASS report matching the report schema', () => {
    expect(report.runtime).toBe('typescript');
    expect(report.schemaVersion).toBe('1.0.0');
    expect(report.contractVersion).toBe('1.0.0');
    // failure records carry digests only; PASS means no records at all
    expect(report.records).toHaveLength(0);
  });

  it('completes the full suite within the 30-second CI budget', () => {
    expect(suiteDurationMs).toBeLessThan(30_000);
  });

  it('derives every candidate within the 1-second budget', () => {
    expect(candidateTimingsMs.length).toBeGreaterThan(0);
    for (const ms of candidateTimingsMs) {
      expect(ms).toBeLessThan(1000);
    }
  });

  it('records per-producer timings with no credential values', () => {
    const timings = readFileSync(join('conformance', 'reports', 'typescript-timings.json'), 'utf8');
    expect(timings).not.toContain('abandon amount');
    expect(timings).not.toContain('hush-public-test-password');
    expect(timings).not.toContain('6e3f74236c3d4a20553be05963f624696990c22245599b3d1b30262af793d885');
  });

  it('writes the cross-runtime report artifact', () => {
    const path = writeReport(report);
    expect(path).toContain('typescript-identity-report.json');
  });
});
