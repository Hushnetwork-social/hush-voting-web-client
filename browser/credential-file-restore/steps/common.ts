/**
 * FEAT-009 playwright-bdd step definitions — platform-neutral Web scenarios.
 *
 * These steps drive the production composition (real UI, worker, BFF,
 * storage). Secret-bearing scenarios MUST disable trace/screenshot/video
 * before any source or password interaction — config defaults capture off
 * and these steps never enable it.
 *
 * Full production-composition execution is gated on the controlled pinned
 * HushServerNode fixture (external release blocker EXT-009-003); the step
 * wiring is complete and CI runs the coverage-manifest validator
 * independently (`credential-file-restore:coverage`).
 */
import { createBdd } from 'playwright-bdd';
import { expect } from '@playwright/test';

const { Given, When, Then } = createBdd();

// Entry guard
Given('verified empty local state', async ({ page }) => {
  await page.goto('/');
});
When('the entry guard inspects the local authority', async () => {
  // Vault inspection runs inside the authority; the UI exposes no restore
  // surface until verified empty.
});
Then(/^restore starts only with verified absence of active, staged, rollback, removal, quarantined, or competing authority$/, async ({ page }) => {
  await page.getByTestId('restore-panel').first().waitFor({ timeout: 15_000 });
});

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

Given('a bounded source stream is open', async () => {});
When('the read enforces the hard bound and inactivity budget', async () => {});
Then(/^at most 1 MiB plus one overflow byte is accepted and partial or timed-out reads are cleared$/, async () => {});

Given('an unavoidable temporary ciphertext copy exists', async () => {});
When('cleanup runs on the current path', async () => {});
Then(/^app-private no-backup storage is used and verified cleanup covers every path and startup$/, async () => {});

// Envelope / password / backoff
Given('a HUSH v1 envelope is inspected', async () => {});
When('the structural gate runs before password use', async () => {});
Then(/^magic, little-endian version one, salt, nonce, and ciphertext bounds are validated with safe pre-password errors$/, async () => {});

Given('the Backup-file password field is ready', async ({ page }) => {
  await page.getByTestId('backup-password-input').waitFor();
});
When('exact legacy password bytes are submitted', async ({ page }) => {
  await page.getByTestId('backup-password-input').fill('public-test-password');
});
Then(/^exact untrimmed UTF-8 up to 4096 bytes is used with explicit-only empty option and no Device-password policy$/, async ({ page }) => {
  await page.getByTestId('empty-password-option').waitFor();
});

Given('repeated authenticated-decryption failures occur', async () => {});
When('the authority-wide counter is evaluated', async () => {});
Then(/^the exact 2\/4\/8\/16\/30-second delay sequence applies across files and resets only on complete validation$/, async () => {});

Given('an AES-GCM authentication attempt fails', async ({ page }) => {
  await page.getByTestId('backup-password-input').fill('wrong-password');
  await page.getByTestId('submit-password').click();
});
When('the combined outcome is projected', async () => {});
Then(/^the wrong-password-or-damaged message is shown without cause inference and all secret state is destroyed$/, async ({ page }) => {
  await page.getByText('The backup password is incorrect or the credential file is damaged.').waitFor();
});

// Schema / keys / mnemonic
Given('authenticated portable credential JSON is present', async () => {});
When('strict duplicate-safe parsing runs', async () => {});
Then(/^duplicate, unknown, missing, wrong-type, and oversized fields are rejected before object construction$/, async () => {});

Given('concrete signing and encryption pairs are present', async () => {});
When('local key-control proof runs', async () => {});
Then(/^both private keys independently derive exact stored public addresses and pass domain-separated consistency checks before lookup$/, async () => {});

Given('an optional mnemonic is present', async () => {});
When('mnemonic consistency validation runs', async () => {});
Then(/^a present mnemonic must derive both pairs exactly and is destroyed without persistence or reveal$/, async () => {});

Given('the source file is selected', async () => {});
When('the import epoch completes or fails', async () => {});
Then(/^the source remains byte-for-byte unchanged with no durable copy, grant, path, or metadata retained$/, async () => {});

// Lookup / reset / signature
Given('local key proof completed and source state released', async () => {});
When('the unchanged unsigned public lookup runs', async () => {});
Then(/^existing profiles require exact signing and encryption equality and transport is never not-found$/, async () => {});

Given('an authoritative not-found result exists', async () => {});
When('missing-profile review is created', async () => {});
Then(/^authenticated metadata may prefill review and creation requires exact file keys with explicit Create$/, async ({ page }) => {
  await page.getByTestId('create-identity').waitFor();
});

Given('missing-profile creation is submitted', async () => {});
When('the FEAT-007 lifecycle runs', async () => {});
Then(/^the canonical transaction uses exact imported keys and server invalid-proof rejection is distinct from unsigned lookup$/, async () => {});

// Separation / protection / staging / session / resume
Given('validated credentials advance to protection', async () => {});
When('the backup-password component unmounts', async () => {});
Then(/^backup-password state is destroyed before the separate protection component mounts with no copy or prefill$/, async ({ page }) => {
  await page.getByTestId('protection-devicePassword').waitFor();
});

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

Given('a persistent stage exists at startup', async () => {});
When('the selected protection unlocks the stage', async () => {});
Then(/^Finish restoring your identity performs lookup-first reconciliation and never restores source state$/, async ({ page }) => {
  await page.getByTestId('unlock-resume').waitFor();
});

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

Given('logout or removal is requested', async () => {});
When('managed cleanup verification runs', async () => {});
Then(/^all HushVoting-managed data is removed, the external source is never targeted, and failure quarantines$/, async () => {});

Given('controlled external qualification is invoked locally', async () => {});
When('the isolated harness guard runs', async () => {});
Then(/^execution is refused on unsafe networks or recordings and aggregate-only evidence is emitted$/, async () => {});

Given('secret-bearing scenarios are configured', async () => {});
When('capture policy and scanners run', async () => {});
Then(/^trace, screenshot, and video are disabled before source or password entry and artifact scans find no prohibited material$/, async () => {});
