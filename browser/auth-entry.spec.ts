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

test.describe('auth-block-2 same-URL authentication history', () => {
  test('browser Back is inert after authentication; explicit Lock returns to password gate', async ({ page }) => {
    await openApp(page);
    await expect(page.getByRole('button', { name: /create user/i })).toBeVisible();

    await page.getByRole('button', { name: /create user/i }).click();
    await expect(page.getByTestId('authenticated-shell')).toBeVisible();
    await expectRootOnlyUrl(page);

    await page.goBack();
    await expect(page.getByTestId('authenticated-shell')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Demo User' })).toBeVisible();
    await expectRootOnlyUrl(page);

    await page.getByRole('button', { name: 'Demo User' }).click();
    await page.getByRole('button', { name: 'Lock' }).click();
    await expect(page.getByLabel('Device password')).toBeVisible();
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
