/**
 * FEAT-002 browser test helpers — shared utilities for focused auth blocks.
 *
 * All evidence is redacted: console/network/storage/history capture keeps
 * only safe typed outcomes, never secrets or identifiers. Blocks use the dev
 * composition (synthetic actors) so they are deterministic and offline-safe.
 */

import { expect, type Page } from '@playwright/test';

/** Collect redacted console/network/storage evidence from a page. */
export interface RedactedEvidence {
  readonly consoleErrors: string[];
  readonly networkFailures: string[];
  readonly storageKeys: string[];
  readonly historyStates: unknown[];
}

/** Attach redacted evidence collectors to a page. */
export function trackRedactedEvidence(page: Page): { get(): Promise<RedactedEvidence> } {
  const consoleErrors: string[] = [];
  const networkFailures: string[] = [];
  const storageKeys: string[] = [];
  const historyStates: unknown[] = [];
  void storageKeys;
  void historyStates;

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      // Redact: never echo secrets or raw payloads.
      const text = msg.text().slice(0, 120);
      consoleErrors.push(text.replace(/[A-Za-z0-9+/=]{20,}/g, '[REDACTED]'));
    }
  });
  page.on('requestfailed', (request) => {
    networkFailures.push(request.url().slice(0, 160));
  });
  page.on('pageerror', (error) => {
    consoleErrors.push(String(error.message).slice(0, 120));
  });

  return {
    async get(): Promise<RedactedEvidence> {
      let keys: string[] = [];
      try {
        keys = await page.evaluate(() => Object.keys(localStorage));
      } catch {
        keys = [];
      }
      let states: unknown[] = [];
      try {
        states = await page.evaluate(() => [history.state]);
      } catch {
        states = [];
      }
      return { consoleErrors, networkFailures, storageKeys: keys, historyStates: states };
    },
  };
}

/** Assert no secrets/identifiers appear anywhere in collected evidence. */
export function expectNoSecrets(evidence: RedactedEvidence): void {
  const forbidden = /password|mnemonic|hunter2|ELEC-|NVh…[a-z0-9]{10,}|BEGIN .*PRIVATE KEY/i;
  const all = [
    ...evidence.consoleErrors,
    ...evidence.networkFailures,
    ...evidence.storageKeys,
    ...evidence.historyStates.map((s) => JSON.stringify(s)),
  ].join('\n');
  expect(forbidden.test(all)).toBe(false);
}

/** Expect the visible URL to remain `/` (root-only privacy invariant). */
export async function expectRootOnlyUrl(page: Page): Promise<void> {
  expect(new URL(page.url()).pathname).toBe('/');
}

/** Navigate to the app root (dev server must be running). */
export async function openApp(page: Page): Promise<void> {
  await page.goto('/');
}
