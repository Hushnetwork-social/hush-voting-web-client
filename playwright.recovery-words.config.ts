/**
 * FEAT-008 playwright-bdd configuration (Task 7.1/7.2).
 *
 * Executable Gherkin for the platform-neutral acceptance catalog. Full
 * production-composition execution requires the controlled pinned
 * HushServerNode fixture (external release gate EXT-008-002) and is RED until
 * that artifact is available — no mock or local reservation substitutes. The
 * coverage-manifest validator (`npm run recovery-words:coverage`) is the
 * machine-checked gate that runs in CI regardless.
 */
import { defineConfig } from '@playwright/test';
import { defineBddConfig } from 'playwright-bdd';

const testDir = defineBddConfig({
  features: 'features/recovery-words',
  steps: 'browser/recovery-words/steps',
  tags: '@FEAT-008',
});

export default defineConfig({
  testDir,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.FEAT008_BASE_URL ?? 'http://localhost:3000',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  // webServer: starts the production composition for the run (bounded by the
  // playwright run lifecycle). Enabled when the pinned server fixture exists.
  ...(process.env.FEAT008_RUN_WEB === '1'
    ? {
        webServer: {
          command: 'npm run build:web && npm run start',
          url: 'http://localhost:3000',
          reuseExistingServer: false,
          timeout: 120_000,
        },
      }
    : {}),
});
