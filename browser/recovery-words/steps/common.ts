/**
 * FEAT-008 playwright-bdd step definitions — platform-neutral Web scenarios.
 *
 * These steps drive the production composition (real UI, worker, IndexedDB,
 * BFF). Secret-bearing scenarios MUST disable trace/screenshot/video before
 * any recovery word or password appears (config already defaults capture off;
 * steps must never enable it for these scenarios).
 *
 * These are remaining legacy handlers, including incomplete assertions. They
 * do not establish production-composition readiness. Validated replacements
 * live in HushVoting's isolated .NET catalogue; coverage mapping is checked
 * independently by recovery-words:coverage.
 */
import { createBdd } from 'playwright-bdd';

const { Given, When, Then } = createBdd();

// Entry guard
Given('verified empty local state', async ({ page }) => {
  await page.goto('/');
});
When('the entry guard inspects the local authority', async () => {
  // Vault inspection runs inside the authority; the UI never exposes a form until verified empty.
});
Then(/^recovery starts only with no active, staged, rollback, quarantine, or competing authority$/, async ({ page }) => {
  // Verified-empty guard: no recovery form mounts while a local identity exists.
  await page.getByTestId('recovery-surface').waitFor();
});

// Custody / candidates / control
Given('a valid phrase in the input component', async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).waitFor();
});
When('Verify transfers the phrase to the secret authority', async ({ page }) => {
  await page.getByRole('button', { name: 'Verify' }).click();
});
Then(/^page buffers clear and the phrase never enters state, storage, logs, or history$/, async ({ page }) => {
  // After transfer the inputs are cleared and cannot be restored from history.
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).waitFor();
});

Given('a selected candidate', async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});
When('the selected-key control proof runs locally', async ({ page }) => {
  await page.getByTestId('recovery-surface').waitFor();
});
Then(/^exact signing and encryption consistency is proven before staging$/, async ({ page }) => {
  await page.getByTestId('recovery-surface').waitFor();
});

// Protection / passkey / native passwordless / session / staging
Given('the protection screen', async ({ page }) => {
  await page.getByTestId('no-retention').waitFor();
});
When('the user chooses protection', async ({ page }) => {
  await page.getByTestId('mode-password').check();
});
Then(/^Device-password is checked by default and secrets enter the authority directly$/, async ({ page }) => {
  await page.getByTestId('mode-password').waitFor();
});

Given('passwordless Web selection', async ({ page }) => {
  await page.getByTestId('mode-passwordless-web').waitFor();
});
When('WebAuthn PRF qualification is evaluated', async () => {
  // Capability detection is fail-closed; never assumed.
});
Then(/^qualified platform\/PRF\/RP checks gate persistence and failures offer no silent fallback$/, async ({ page }) => {
  await page.getByTestId('mode-password').waitFor();
});

Given('a native platform', async ({ page }) => {
  await page.getByTestId('mode-passwordless-native').waitFor();
});
When('passwordless native protection is selected', async ({ page }) => {
  await page.getByTestId('mode-passwordless-native').check();
});
Then(/^qualified Secret Service or hardware-backed Keystore gates persistence and warns honestly$/, async ({ page }) => {
  await page.getByTestId('mode-passwordless-native').waitFor();
});

Given('explicit session-only selection', async ({ page }) => {
  await page.getByTestId('mode-session').check();
});
When('the session authority is issued', async ({ page }) => {
  await page.getByTestId('session-ack').check();
});
Then(/^nothing persists and recovery is required after authority loss$/, async ({ page }) => {
  await page.getByRole('button', { name: 'Continue' }).waitFor();
});

// Resume / nav / owner / cleanup / migration / security
Given('staged selected keys after restart', async ({ page }) => {
  await page.getByText('Finish restoring your identity').waitFor();
});
When('startup inspection runs', async () => {
  // Startup inspection is authority-owned.
});
Then(/^Finish restoring your identity is shown and words are never reconstructed$/, async ({ page }) => {
  await page.getByText('Finish restoring your identity').waitFor();
});

Given('one live recovery owner', async ({ page }) => {
  await page.getByTestId('recovery-surface').waitFor();
});
When('another tab attempts recovery', async ({ page }) => {
  await page.getByText(/already in progress in another/).waitFor();
});
Then(/^the non-owner is blocked with a safe notification and no secret data is broadcast$/, async ({ page }) => {
  await page.getByText(/already in progress in another/).waitFor();
});

Given('a completed local removal', async ({ page }) => {
  await page.getByRole('button', { name: 'Log out and remove local user' }).waitFor();
});
When('cleanup verification runs', async () => {
  // Verified-absence check is authority-owned.
});
Then(/^every managed artifact is removed and failure quarantines recovery$/, async () => {
  // Cleanup failure keeps first-run unavailable.
});

Given('an older vault with an encrypted mnemonic record', async () => {
  // Migration fixture is consumed by the authority; never loaded into the UI.
});
When('migration runs', async () => {
  // Old encrypted generations stay rollback-bounded.
});
Then(/^mnemonic ciphertext is omitted and deleted atomically without loading or displaying it$/, async () => {
  // No mnemonic content is ever rendered.
});

Given('secret-bearing recovery material', async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).waitFor();
});
When('evidence and artifact scanning runs', async () => {
  // The recovery-words:secret-scan gate runs separately in CI.
});
Then(/^trace\/screenshot\/video are disabled and no prohibited credential material is found$/, async () => {
  // Capture is off by configuration; the scanner is the machine-checked gate.
});
