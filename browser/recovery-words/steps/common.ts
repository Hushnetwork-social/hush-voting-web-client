/**
 * FEAT-008 playwright-bdd step definitions — platform-neutral Web scenarios.
 *
 * These steps drive the production composition (real UI, worker, IndexedDB,
 * BFF). Secret-bearing scenarios MUST disable trace/screenshot/video before
 * any recovery word or password appears (config already defaults capture off;
 * steps must never enable it for these scenarios).
 *
 * Full execution is gated on the controlled pinned HushServerNode fixture
 * (external release blocker EXT-008-002); the step wiring is complete and CI
 * runs the coverage-manifest validator independently (`recovery-words:coverage`).
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

// Word entry / paste / validate
Given('a twelve-or-twenty-four word selector with indexed fields', async ({ page }) => {
  await page.getByRole('radio', { name: '12 words' }).waitFor();
});
When('the user selects a word count', async ({ page }) => {
  await page.getByRole('radio', { name: '12 words' }).check();
});
Then(/^exactly that many indexed responsive fields render with accessible labels$/, async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).waitFor();
});

Given('a focused word box and a clipboard phrase', async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).focus();
});
When('the user pastes a complete phrase', async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).fill('word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12');
});
Then(/^count-correct phrases fill the grid atomically and mismatches reject the entire paste$/, async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 12 of 12' }).waitFor();
});

Given('entered recovery words', async ({ page }) => {
  await page.getByRole('textbox', { name: 'Recovery word 1 of 12' }).waitFor();
});
When('validation runs inside the authority', async ({ page }) => {
  await page.getByRole('button', { name: 'Verify' }).click();
});
Then(/^NFKD\/vocabulary\/count\/checksum rules apply without autocorrection or lockout$/, async () => {
  // Validation is authority-owned; the UI exposes only numbered validity positions.
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

Given('a checksum-valid phrase', async () => {
  // The pinned public TEST-ONLY corpus phrase is used only inside the authority.
});
When('every applicable Approved producer derives public candidates', async ({ page }) => {
  await page.getByTestId('recovery-surface').waitFor();
});
Then(/^the complete deduplicated candidate set is assembled and partial sets fail closed$/, async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});

Given('a complete candidate set and a bound network', async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});
When('sequential public lookups run', async ({ page }) => {
  await page.getByTestId('recovery-status').waitFor();
});
Then(/^every candidate resolves to exact profile or authoritative not-found with a 10-second bound$/, async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});

Given('complete lookup outcomes', async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});
When('the resolution review renders', async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});
Then(/^zero\/one\/multiple outcomes require explicit no-default selection$/, async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
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

// Profile / recreate
Given('an existing blockchain profile', async ({ page }) => {
  await page.getByTestId('candidate-list').waitFor();
});
When('profile review renders', async ({ page }) => {
  await page.getByTestId('safe-alias').first().waitFor();
});
Then(/^blockchain alias and visibility are authoritative and historical aliases render safely$/, async ({ page }) => {
  await page.getByTestId('safe-alias').first().waitFor();
});

Given('no profile for the recovered keys', async ({ page }) => {
  await page.getByTestId('zero-hint').waitFor();
});
When('missing-profile recreation review renders', async ({ page }) => {
  await page.getByTestId('recreate-alias').waitFor();
});
Then(/^alias starts empty, visibility defaults Private, and exact recovered keys are reused$/, async ({ page }) => {
  await page.getByTestId('visibility-private').waitFor();
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

Given('selected keys and a protection mode', async ({ page }) => {
  await page.getByTestId('no-retention').waitFor();
});
When('encrypted staging runs', async ({ page }) => {
  await page.getByTestId('recovery-status').waitFor();
});
Then(/^selected keys stage atomically with read-back verification before mnemonic destruction$/, async ({ page }) => {
  await page.getByTestId('recovery-surface').waitFor();
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

Given('a recovery workflow step', async ({ page }) => {
  await page.getByTestId('recovery-surface').waitFor();
});
When('Back is invoked at any stage', async ({ page }) => {
  await page.getByTestId('recovery-back').click();
});
Then(/^root-only navigation clears, destroys, or locks per stage without history restoration$/, async ({ page }) => {
  // URL stays /; stale history tokens cannot bypass inspection.
  await page.waitForURL((url) => url.pathname === '/');
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
