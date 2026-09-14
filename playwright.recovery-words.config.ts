/**
 * FEAT-008 playwright-bdd configuration (Task 7.1/7.2).
 *
 * Legacy scenarios still awaiting replacement validation. Final browser/server
 * E2E is owned by HushServerNode's isolated HushVoting .NET infrastructure.
 * Validated replacements run via dedicated test:recovery-*:bdd commands
 * and remain in the .NET catalogue. This config discovers
 * only the remaining TypeScript sources. Coverage mapping uses all 85 .NET
 * declarations, independently of runtime or semantic acceptance readiness.
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
