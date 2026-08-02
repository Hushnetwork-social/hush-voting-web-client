/**
 * FEAT-004 browser-vault deployment — Next.js header wiring (production only).
 *
 * Applies the reviewed restrictive security headers to the PRODUCTION web
 * build; development/HMR stays untouched so the FEAT-002 dev server and
 * Playwright harnesses are unaffected. Pure function for testability.
 *
 * Normative source: FEAT-004 FeatureDescription "CSP and same-origin
 * hardening", "Supported Browser and Deployment Baseline".
 */
import type { NextConfig } from 'next';
import { productionSecurityHeaders } from './policy';

/** True only for the production web build (never dev/HMR/static export). */
export function isProductionWebBuild(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.NODE_ENV === 'production' && env.STANDALONE_BUILD === 'true';
}

/** Next.js headers() configuration for authenticated production pages. */
export function productionSecurityHeaderConfig(env: NodeJS.ProcessEnv = process.env): NonNullable<NextConfig['headers']> {
  return async () => {
    if (!isProductionWebBuild(env)) {
      return [];
    }
    const headers = Object.entries(productionSecurityHeaders()).map(([key, value]) => ({ key, value }));
    return [{ source: '/:path*', headers }];
  };
}
