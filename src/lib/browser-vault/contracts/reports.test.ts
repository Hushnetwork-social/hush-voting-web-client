/**
 * FEAT-004 evidence report tests — digest-only safety.
 *
 * Proves reports identify versions/digests/outcomes only and reject any
 * identity, secret, endpoint, DB, or stable-identifier material.
 *
 * Normative source: FEAT-004 FeatureDescription "Browser-Version
 * Infrastructure"; Task 2.5 report schema.
 */
import { describe, expect, it } from 'vitest';
import { createAdapterReport, validateReportSafety } from './reports';

const BASE = {
  outcome: 'pass',
  appVersion: '0.1.0',
  buildDigest: 'a1b2c3d4e5f6',
  protocolVersion: 1,
  corpusVersion: '1.0.0',
  corpusManifestSha256: 'e8dfdfa49b9e33cfc8a47b1266c5a14cb978c4be28f21d87cc2f034d435582e5',
  browserFamily: 'chrome',
  browserMajorVersion: '128',
} as const;

describe('adapter reports — safe fields only', () => {
  it('accepts a digest-only report', () => {
    const report = createAdapterReport(BASE);
    expect(validateReportSafety(report)).toBe(true);
    expect(report.reportVersion).toBe(1);
  });

  it('rejects identity/secret/endpoint/DB-shaped values', () => {
    expect(validateReportSafety({ ...BASE, identity: 'hush:abc' })).toBe(false);
    expect(validateReportSafety({ ...BASE, alias: 'alice' })).toBe(false);
    expect(validateReportSafety({ ...BASE, address: 'Nxyz' })).toBe(false);
    expect(validateReportSafety({ ...BASE, ciphertext: 'c2VjcmV0' })).toBe(false);
    expect(validateReportSafety({ ...BASE, url: 'https://x.example' })).toBe(false);
    expect(validateReportSafety({ ...BASE, db: 'hushvoting-vault' })).toBe(false);
    expect(validateReportSafety({ ...BASE, timestamp: '2026-08-02T00:00:00Z' })).toBe(false);
    expect(validateReportSafety({ ...BASE, details: ['secret', 'mismatch'] })).toBe(false);
  });

  it('permits coarse performance buckets and adapter digests', () => {
    const report = createAdapterReport({ ...BASE, coarseDurationBucketMs: 750, adapterDigestSha256: 'abc123' });
    expect(validateReportSafety(report)).toBe(true);
  });
});
