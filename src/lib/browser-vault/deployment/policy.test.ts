/**
 * FEAT-004 deployment policy tests — restrictive first-party contract.
 *
 * Proves the production security headers satisfy the reviewed CSP/HSTS/
 * anti-framing/no-service-worker baseline and reject unsafe drift.
 *
 * Normative source: FEAT-004 FeatureDescription "CSP and same-origin
 * hardening"; Task 6.4 behavior spec.
 */
import { describe, expect, it } from 'vitest';
import { PRODUCTION_CSP, assertPolicySafe, productionNonceCsp, productionSecurityHeaders, serializeCsp } from './policy';

describe('CSP serialization', () => {
  it('serializes the production directive set', () => {
    const value = serializeCsp(PRODUCTION_CSP);
    expect(value).toContain("default-src 'self'");
    expect(value).toContain("script-src 'self'");
    expect(value).toContain("object-src 'none'");
    expect(value).toContain("frame-ancestors 'none'");
    expect(value).toContain('upgrade-insecure-requests');
    expect(value).not.toContain("'unsafe-inline'");
    expect(value).not.toContain("'unsafe-eval'");
  });

  it('authorizes framework bootstrap code with one bounded nonce, never unsafe-inline', () => {
    const nonce = 'MDEyMzQ1Njc4OWFiY2RlZg==';
    const value = serializeCsp(productionNonceCsp(nonce));
    expect(value).toContain(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`);
    expect(value).toContain(`style-src 'self' 'nonce-${nonce}'`);
    expect(value).not.toContain("'unsafe-inline'");
    expect(value).not.toContain("'unsafe-eval'");
  });

  it('rejects malformed or unbounded nonce input', () => {
    expect(() => productionNonceCsp('short')).toThrow();
    expect(() => productionNonceCsp("validvaluebut'unsafe-inline")).toThrow();
  });
});

describe('production headers', () => {
  it('satisfies the reviewed policy', () => {
    const headers = productionSecurityHeaders();
    const check = assertPolicySafe(headers);
    expect(check.ok).toBe(true);
    expect(check.violations).toEqual([]);
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['Referrer-Policy']).toBe('no-referrer');
    expect(headers['Strict-Transport-Security']).toContain('max-age=31536000');
  });

  it('rejects unsafe drift (broad script, missing frame denial)', () => {
    expect(assertPolicySafe({ 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-eval'" }).ok).toBe(false);
    expect(assertPolicySafe({ 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'self'" }).ok).toBe(false);
    expect(
      assertPolicySafe({
        'Content-Security-Policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'; worker-src 'self'; base-uri 'none'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
      }).ok,
    ).toBe(true);
  });

  it('limits connect-src to approved origins', () => {
    const connect = PRODUCTION_CSP['connect-src'];
    expect(connect).toContain("'self'");
    for (const origin of ['https://api.hushnetwork.app', 'https://www.hushnetwork.app']) {
      expect(connect).toContain(origin);
    }
    expect(connect.some((entry) => entry.includes('third-party') || entry.includes('analytics'))).toBe(false);
  });
});
