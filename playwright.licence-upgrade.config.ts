/**
 * FEAT-017 playwright-bdd configuration — canonical post-login account
 * licence + higher-Veritas upgrade journeys (Phase 7 task 7.1).
 *
 * Executable Gherkin for the eight canonical FEAT-017-owned EPIC acceptance
 * journeys (AT-LIC-001/004/005/006/008/009 TwinTest-paired and AT-LIC-015/016
 * client-only IDs) against the ORDINARY production composition: real
 * target-aware root, real SharedWorker credential authority, real encrypted
 * licence journal, real same-origin no-store licence BFF, real
 * SubmitSignedTransaction ingress and the real account/licence UI mounted by
 * the authenticated root.
 *
 * Every scenario is post-login and fixture-bound: it reaches the licence
 * surfaces only through the CONTROLLED REAL HushServerNode fixture with
 * test-owned identities and network. Capture is OFF by default
 * (trace/screenshot/video) because credential/secret material is present.
 * When the fixture composition is supplied (`FEAT017_RUN_WEB=1` plus the
 * fixture server and identity environment), Playwright starts the bounded
 * production web server itself and runs the journeys; without the fixture the
 * catalog is validated by the non-zero-discovery wiring gate in
 * `scripts/licence-upgrade/`.
 */
import { defineConfig } from '@playwright/test';
import { defineBddConfig } from 'playwright-bdd';

const testDir = defineBddConfig({
  features: 'features/licence-upgrade',
  steps: ['browser/licence-entitlements/steps/**/*.ts', 'browser/licence-upgrade/steps/**/*.ts'],
  tags: '@FEAT-017',
  outputDir: '.features-gen-licence-upgrade',
});

export default defineConfig({
  testDir,
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.FEAT017_BASE_URL ?? 'http://localhost:3201',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  ...(process.env.FEAT017_RUN_WEB === '1'
    ? {
        webServer: {
          command: 'npm run build:web && npm run start -- -p 3201',
          url: 'http://localhost:3201',
          reuseExistingServer: false,
          timeout: 180_000,
        },
      }
    : {}),
});
