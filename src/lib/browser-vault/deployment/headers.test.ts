/**
 * FEAT-004 headers wiring tests — production-only security headers.
 *
 * Proves the restrictive headers apply ONLY to the production web build and
 * dev/HMR/static-export paths stay unaffected (so FEAT-002 dev servers and
 * Playwright harnesses never break).
 *
 * Normative source: FEAT-004 FeatureDescription "CSP and same-origin
 * hardening"; Task 6.4 behavior spec.
 */
import { describe, expect, it } from 'vitest';
import { isProductionWebBuild, productionSecurityHeaderConfig } from './headers';

describe('production header wiring', () => {
  it('applies headers only for the production standalone web build', async () => {
    const prodEnv = { NODE_ENV: 'production', STANDALONE_BUILD: 'true' } as NodeJS.ProcessEnv;
    const devEnv = { NODE_ENV: 'development' } as NodeJS.ProcessEnv;
    const staticEnv = { NODE_ENV: 'production', STATIC_EXPORT: 'true' } as NodeJS.ProcessEnv;

    expect(isProductionWebBuild(prodEnv)).toBe(true);
    expect(isProductionWebBuild(devEnv)).toBe(false);
    expect(isProductionWebBuild(staticEnv)).toBe(false);

    const prodHeaders = await productionSecurityHeaderConfig(prodEnv)();
    expect(prodHeaders.length).toBe(1);
    expect(prodHeaders[0].source).toBe('/:path*');
    expect(prodHeaders[0].headers.some((h) => h.key === 'Content-Security-Policy')).toBe(true);

    expect(await productionSecurityHeaderConfig(devEnv)()).toEqual([]);
    expect(await productionSecurityHeaderConfig(staticEnv)()).toEqual([]);
  });
});
