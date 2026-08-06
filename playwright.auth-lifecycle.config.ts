/**
 * FEAT-010 playwright-bdd configuration — real-root Web matrix (Task 7.3).
 *
 * Executable Gherkin for the FEAT-010 Web acceptance matrix against the
 * ORDINARY production composition (real target-aware composition, real
 * SharedWorker vault authority, real IndexedDB, real BFF). Capture is OFF by
 * default (trace/screenshot/video) because secret-bearing scenarios forbid
 * recording before input.
 *
 * The full Create→confirm→verify journeys additionally require the controlled
 * pinned HushServerNode fixture (external release blocker, EXT-010-001/002);
 * those scenarios are tagged @server-fixture and only execute when
 * FEAT010_RUN_WEB=1 with the fixture present. Without the fixture, the
 * offline/fail-closed journeys still run and prove the honest surface.
 */
import { defineConfig } from '@playwright/test';
import { defineBddConfig } from 'playwright-bdd';

const testDir = defineBddConfig({
  features: 'features/auth-lifecycle',
  steps: 'browser/auth-lifecycle/steps',
  tags: '@FEAT-010 and not @server-fixture',
  outputDir: '.features-gen-auth-lifecycle',
});

export default defineConfig({
  testDir,
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.FEAT010_BASE_URL ?? 'http://localhost:3201',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  ...(process.env.FEAT010_RUN_WEB === '1'
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
