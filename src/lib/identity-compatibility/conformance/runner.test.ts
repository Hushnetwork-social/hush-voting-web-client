/**
 * FEAT-001 TypeScript conformance suite — executes the entire corpus against
 * the production API and asserts zero mismatches. Backs the
 * `npm run identity:conformance` gate (exit 0 = PASS).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { runConformance, writeReport, type ConformanceReport } from './runner.js';

let report: ConformanceReport;

beforeAll(async () => {
  report = await runConformance();
}, 30_000);

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

  it('writes the cross-runtime report artifact', () => {
    const path = writeReport(report);
    expect(path).toContain('typescript-identity-report.json');
  });
});
