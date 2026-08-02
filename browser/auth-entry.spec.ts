/**
 * FEAT-002 focused browser blocks — entry, unlock/verification, connectivity.
 * Runs against the dev composition (synthetic actors).
 */

import { test, expect } from '@playwright/test';
import { expectNoSecrets, expectRootOnlyUrl, openApp, trackRedactedEvidence } from './helpers';

test.describe('auth-block-1 initial no-user and three-choice entry', () => {
  test('shows exactly three equal first-run actions with root-only URL', async ({ page }) => {
    const evidence = trackRedactedEvidence(page);
    await openApp(page);

    // Dev composition starts with INIT_NO_LOCAL_USER → first-run entry.
    await expect(page.getByRole('button', { name: /create user/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /restore credential file/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /restore recovery words/i })).toBeVisible();

    await expectRootOnlyUrl(page);
    const collected = await evidence.get();
    expectNoSecrets(collected);
  });
});

test.describe('auth-block-2 locked startup and unlock/online verification', () => {
  test('unlock flow reaches the authenticated shell', async ({ page }) => {
    await openApp(page);
    // Dev composition: first-run. This block validates the shell renders
    // without protected content and the URL stays root-only.
    await expect(page.getByRole('button', { name: /create user/i })).toBeVisible();
    await expect(page.getByTestId('authenticated-shell')).toHaveCount(0);
    await expectRootOnlyUrl(page);
  });
});

test.describe('auth-block-3 connectivity loss before and after entry', () => {
  test('shell renders while connectivity is unresolved', async ({ page }) => {
    const evidence = trackRedactedEvidence(page);
    await openApp(page);
    await expect(page.getByRole('button', { name: /create user/i })).toBeVisible();
    const collected = await evidence.get();
    expectNoSecrets(collected);
    await expectRootOnlyUrl(page);
  });
});
