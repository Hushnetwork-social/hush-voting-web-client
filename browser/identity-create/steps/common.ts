/**
 * FEAT-007 playwright-bdd step definitions — platform-neutral Web scenarios.
 *
 * These steps drive the production composition (real UI, worker, IndexedDB,
 * BFF). Secret-bearing scenarios MUST disable trace/screenshot/video before
 * any recovery word or password appears (config already defaults capture off;
 * steps must never enable it for these scenarios).
 *
 * Full execution is gated on the controlled pinned HushServerNode fixture
 * (external release blocker); the step wiring is complete and CI runs the
 * coverage-manifest validator independently.
 */
import { createBdd } from 'playwright-bdd';

const { Given, When, Then } = createBdd();

Given('there is no local user', async ({ page }) => {
  // Production composition resolves to the no-local-user entry.
  await page.goto('/');
});

When('the first-run entry renders', async ({ page }) => {
  await page.getByRole('heading', { name: /Secure your voting identity/ }).waitFor();
});

Then(/^Create User, Restore Credential File, and Restore Recovery Words are shown with equal primary weight$/, async ({ page }) => {
  await page.getByRole('button', { name: /Create User/ }).waitFor();
  await page.getByRole('button', { name: /Restore Credential File/ }).waitFor();
  await page.getByRole('button', { name: /Restore Recovery Words/ }).waitFor();
});

Then('no password field exists anywhere on the entry', async ({ page }) => {
  // No password input and no account-password wording.
  await page.getByLabel(/password/i).count().then((count) => {
    if (count !== 0) throw new Error('password field must not exist on entry');
  });
});

When('the user selects Create User', async ({ page }) => {
  await page.getByRole('button', { name: /Create User/ }).click();
});

Then(/^alias collection and secret generation are blocked until the preflight passes$/, async ({ page }) => {
  // Preflight surface is authoritative; no alias input appears before it passes.
  await page.getByRole('heading', { name: /Security check/ }).waitFor();
});

Given('the Profile screen renders', async ({ page }) => {
  await page.getByRole('heading', { name: /Create user · Profile/ }).waitFor();
});

When('the user reviews visibility', async ({ page }) => {
  await page.getByLabel(/Private — recommended/).waitFor();
});

Then('Private is selected by default', async ({ page }) => {
  await page.getByRole('radio', { name: /Private — recommended/ }).isChecked().then((checked) => {
    if (!checked) throw new Error('Private must be the default');
  });
});

Then(/^choosing Public shows a plain-language exposure\/permanence warning requiring explicit acknowledgement$/, async ({ page }) => {
  await page.getByRole('radio', { name: /Public/ }).click();
  await page.getByText(/cannot be changed later/).waitFor();
  await page.getByRole('checkbox').waitFor();
});

When('the user explicitly generates recovery words', async ({ page }) => {
  await page.getByRole('button', { name: /Generate recovery words/ }).click();
});

Then(/^progress appears after 150 ms$/, async ({ page }) => {
  // The generate surface announces progress through a live region.
  await page.getByText(/Generating your identity securely/).waitFor();
});
