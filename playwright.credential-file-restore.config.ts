/**
 * FEAT-009 playwright-bdd configuration (Task 7.1/7.2).
 *
 * Remaining legacy sources awaiting replacement validation. Final browser/server
 * E2E is owned by the isolated HushVoting .NET infrastructure. Validated
 * replacements have dedicated test:credential-*:bdd commands.
 * This config discovers only remaining TypeScript sources; coverage mapping
 * independently validates all original .NET declarations.
 */
import { defineConfig } from '@playwright/test';
import { defineBddConfig } from 'playwright-bdd';

const testDir = defineBddConfig({
  features: 'features/credential-file-restore',
  steps: 'browser/credential-file-restore/steps',
  tags: '@FEAT-009',
});

export default defineConfig({
  testDir,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.FEAT009_BASE_URL ?? 'http://localhost:3000',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  // webServer: starts the production composition for the run (bounded by the
  // playwright run lifecycle). Enabled when the pinned server fixture exists.
  ...(process.env.FEAT009_RUN_WEB === '1'
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
