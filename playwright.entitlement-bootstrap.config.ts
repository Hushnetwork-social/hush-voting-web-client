/**
 * FEAT-016 playwright-bdd configuration — canonical post-login entitlement
 * bootstrap journeys (Phase 7 task 7.1).
 *
 * Executable Gherkin for the thirteen canonical EPIC acceptance journeys
 * (AT-LIC-002/003/007/010/011/012 TwinTest-paired and AT-LIC-016-001…007
 * client-only IDs) against the ORDINARY production composition: real
 * target-aware root, real SharedWorker credential authority, real encrypted
 * licence journal, real same-origin no-store licence BFF and real
 * SubmitSignedTransaction ingress.
 *
 * Every scenario is post-login: reaching the entitlement gate requires the
 * CONTROLLED REAL HushServerNode fixture with test-owned identities and
 * network. Capture is OFF by default (trace/screenshot/video) because
 * credential/secret material is present. When the fixture composition is
 * supplied (`FEAT016_RUN_WEB=1` plus the fixture server and identity
 * environment), Playwright starts the bounded production web server itself
 * and runs the journeys; without the fixture the catalog is validated by the
 * non-zero-discovery wiring gate in `scripts/entitlement-bootstrap/`.
 */
import { defineConfig } from '@playwright/test';
import { defineBddConfig } from 'playwright-bdd';

const testDir = defineBddConfig({
  features: 'features/licence-entitlements',
  steps: 'browser/licence-entitlements/steps',
  tags: '@FEAT-016',
  outputDir: '.features-gen-entitlement-bootstrap',
});

export default defineConfig({
  testDir,
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.FEAT016_BASE_URL ?? 'http://localhost:3201',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  ...(process.env.FEAT016_RUN_WEB === '1'
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
