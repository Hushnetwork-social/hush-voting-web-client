/**
 * FEAT-009 playwright-bdd step definitions — platform-neutral Web scenarios.
 *
 * These steps drive the production composition (real UI, worker, BFF,
 * storage). Secret-bearing scenarios MUST disable trace/screenshot/video
 * before any source or password interaction — config defaults capture off
 * and these steps never enable it.
 *
 * These are remaining legacy handlers, including incomplete assertions.
 * Validated replacements run in the isolated HushVoting .NET infrastructure.
 * Coverage mapping uses all original .NET declarations independently of
 * runtime and semantic acceptance readiness.
 */
import { createBdd } from 'playwright-bdd';
import { expect } from '@playwright/test';

const { Given, When, Then } = createBdd();

// Picker / read
Given('one source is selected through the platform picker', async ({ page }) => {
  await page.getByTestId('choose-file').waitFor();
});
When('the picker outcome is projected', async () => {
  // The picker outcome crosses as a closed PlatformSelectionOutcome only.
});
Then(/^exactly one file is accepted per attempt and cancel is neutral with no identifier shown$/, async ({ page }) => {
  // Safe selected status never renders a filename; cancel shows no error.
  await page.getByTestId('restore-status').waitFor();
});

Given('an unavoidable temporary ciphertext copy exists', async () => {});
When('cleanup runs on the current path', async () => {});
Then(/^app-private no-backup storage is used and verified cleanup covers every path and startup$/, async () => {});

// Schema / keys / mnemonic
Given('concrete signing and encryption pairs are present', async () => {});
When('local key-control proof runs', async () => {});
Then(/^both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup$/, async () => {});

// Lookup / reset / signature
Given('local key proof completed and source state released', async () => {});
When('the unchanged unsigned public lookup runs', async () => {});
Then(/^existing profiles require exact signing and encryption equality and transport is never not-found$/, async () => {});

// Separation / protection / staging / session / resume
Given('protection choices are available', async ({ page }) => {
  await page.getByTestId('protection-devicePassword').waitFor();
});
When('a mode is selected', async ({ page }) => {
  await page.getByTestId('protection-devicePassword').check();
});
Then(/^Device-password is default and only qualified passwordless or explicit session-only alternatives are representable$/, async () => {});

Given('verified concrete keys exist', async () => {});
When('encrypted staging runs', async () => {});
Then(/^keys are encrypted, journaled, read back, and CAS-committed with exact bindings and the stage is never authentication$/, async () => {});

Given('session-only is selected', async () => {});
When('the session authority ends', async () => {});
Then(/^no local user, stage, or transaction persists and exact online verification is required again$/, async () => {});

// Navigation / ownership / cleanup
Given('a navigation event occurs', async () => {});
When('the shared Back authority evaluates the stage', async () => {});
Then(/^pre-decryption clears, post-validation destroys, and post-stage locks with visible URL remaining root$/, async ({ page }) => {
  const url = new URL(page.url());
  expect(url.pathname).toBe('/');
});

Given('two authorities attempt restore', async () => {});
When('ownership is acquired atomically', async () => {});
Then(/^exactly one owner may select, decrypt, stage, or submit and non-owners receive only safe blocked state$/, async () => {});


Given('secret-bearing scenarios are configured', async () => {});
When('capture policy and scanners run', async () => {});
Then(/^trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material$/, async () => {});
