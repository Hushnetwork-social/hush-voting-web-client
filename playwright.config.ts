import { defineConfig, devices } from '@playwright/test';

/**
 * FEAT-002 focused browser evidence harness.
 *
 * Small, independently runnable auth blocks — NEVER a giant election E2E
 * suite. Blocks are shardable by `--grep`. Server starts are foreground and
 * bounded; no persistent dev server is left running.
 *
 * Run a single block:
 *   npx playwright test --grep "first-run"
 * Run all auth blocks:
 *   npx playwright test
 */

export default defineConfig({
  testDir: './browser',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:3201',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    viewport: { width: 1280, height: 800 },
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
  ],
});
