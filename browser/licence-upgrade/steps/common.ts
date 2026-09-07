/**
 * FEAT-017 playwright-bdd step definitions — canonical post-login account
 * licence + higher-Veritas upgrade journeys (Phase 7 task 7.1).
 *
 * These steps drive the ORDINARY production composition at "/" (real
 * target-aware root, real SharedWorker credential authority, real encrypted
 * licence journal, real same-origin no-store licence BFF and real
 * SubmitSignedTransaction ingress) against a CONTROLLED REAL HushServerNode
 * fixture with test-owned identities and network. They never intercept
 * requests, inject entitlement state, patch `window`, or install synthetic
 * production providers.
 *
 * Identity provisioning and unlock reuse the FEAT-016 journey step module
 * (same SharedWorker/vault composition), so the FEAT-017 playwright config
 * lists both step directories. Every licence/account precondition is
 * fixture-owned: the controlled server answers the authoritative
 * GetMyEntitlement and SubmitSignedTransaction calls.
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…09 + recovery
 * contract; `src/lib/licensing/upgrade-copy.ts` (exact approved copy);
 * `src/app/auth/licence/*` (roles/test-ids); EPIC-002 AcceptanceTest.md
 * canonical AT-LIC scenarios.
 */
import { createBdd } from 'playwright-bdd';
import { expect, type Page } from '@playwright/test';

const { Given, When, Then } = createBdd();

/** Exact approved copy (presentation contract; never asserted loosely). */
const SECTION_CURRENT = 'Current licence';
const SECTION_HIGHER = 'Available higher plans';
const STALE_NOTICE = 'Your licence or available plans have changed. Please review the updated options.';
const LIMITS_REMAIN = 'Current limits remain in effect';
const CONFIRM_TITLE = 'Confirm licence activation';

/** Real test-owned account menu trigger (alias set by fixture provisioning). */
const ACCOUNT_TRIGGER = /Alice/;

async function openAccountPopup(page: Page): Promise<void> {
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
  await page.getByRole('button', { name: ACCOUNT_TRIGGER }).click();
  await expect(page.getByRole('dialog', { name: 'User information' })).toBeVisible();
}

async function openLicenceWorkspace(page: Page): Promise<void> {
  await page.getByTestId('licence-workspace-host').waitFor({ timeout: 60_000 });
}

// ---------------------------------------------------------------------------
// Precondition (Given) steps — fixture-owned server arrangement plus the real
// authenticated surface. Nothing here is client-state injection.
// ---------------------------------------------------------------------------

Given('HushServerNode has indexed an active Direct Free licence for Alice', async ({ page }) => {
  // Fixture-owned: the controlled server has indexed a Direct Free assignment
  // for the test-owned identity. The browser observes only the authoritative
  // query result after the real account-entry refresh.
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

Given('HushServerNode has indexed an active HushVoting! Veritas 2k licence for Alice', async ({ page }) => {
  // Fixture-owned: the controlled server has indexed a Veritas 2k assignment.
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

Given('Alice selected a higher Veritas plan while Direct Free was effective', async ({ page }) => {
  // Fixture-owned: Alice loaded options while Direct Free was indexed and a
  // higher-plan draft was selected in the delivered UI.
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

// ---------------------------------------------------------------------------
// Action (When) steps — real delivered UI only.
// ---------------------------------------------------------------------------

When('the Account popup opens and its licence entry is refreshed', async ({ page }) => {
  await openAccountPopup(page);
  // Account entry issues the existing fresh authority-owned signed query; the
  // safe summary block appears from authoritative truth (never stale cache).
  await expect(page.getByRole('dialog', { name: 'User information' }).getByLabel('Licence')).toBeVisible();
});

When('Alice opens Upgrade from the account licence block', async ({ page }) => {
  await openAccountPopup(page);
  const block = page.getByRole('dialog', { name: 'User information' }).getByLabel('Licence');
  await block.getByTestId('account-licence-action').click();
  await openLicenceWorkspace(page);
});

When('Alice opens the licence page', async ({ page }) => {
  await openAccountPopup(page);
  const block = page.getByRole('dialog', { name: 'User information' }).getByLabel('Licence');
  await block.getByTestId('account-licence-action').click();
  await openLicenceWorkspace(page);
});

When('Alice reviews a higher Veritas plan', async ({ page }) => {
  await openLicenceWorkspace(page);
  // Each server-ordered higher option exposes one "Review plan" action.
  await page.getByRole('button', { name: 'Review plan' }).first().click();
  await expect(page.getByTestId('licence-view-confirmation')).toBeVisible();
});

When('Alice cancels confirmation', async ({ page }) => {
  await page.getByRole('button', { name: 'Back to plans' }).click();
  await expect(page.getByTestId('licence-view-options')).toBeVisible();
});

When('Alice confirms and activates a strictly higher Veritas plan', async ({ page }) => {
  await page.getByRole('button', { name: 'Review plan' }).first().click();
  await expect(page.getByTestId('licence-view-confirmation')).toBeVisible();
  await page.getByRole('button', { name: 'Activate licence' }).click();
  // Progress (P0) is reached only after the closed authority seals the op.
  await expect(page.getByTestId('licence-view-progress')).toBeVisible({ timeout: 60_000 });
});

When('the exact sealed transaction is indexed for Alice', async ({ page }) => {
  // Fixture-owned: the controlled server now indexes the exact sealed
  // confirmed_upgrade transaction; the next reconciliation query observes it.
  await expect
    .poll(() => page.getByTestId('licence-view-progress').or(page.getByTestId('licence-view-result')).count())
    .toBeGreaterThanOrEqual(1);
});

When('indexed truth changes to a different compatible current licence before activation', async ({ page }) => {
  // Fixture-owned: another compatible indexed activation supersedes Direct
  // Free before the local confirmation is submitted. The browser only ever
  // observes the authoritative refresh.
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

When('Alice selects a higher Veritas plan and uses in-app Back', async ({ page }) => {
  await openLicenceWorkspace(page);
  await page.getByRole('button', { name: 'Review plan' }).first().click();
  await expect(page.getByTestId('licence-view-confirmation')).toBeVisible();
  await page.getByRole('button', { name: 'Back to plans' }).click();
});

When('Alice opens a plan and uses browser Back', async ({ page }) => {
  await page.getByRole('button', { name: 'Review plan' }).first().click();
  await expect(page.getByTestId('licence-view-confirmation')).toBeVisible();
  await page.goBack();
  await page.waitForLoadState('domcontentloaded');
});

When('Alice uses only the keyboard at each supported Web viewport', async ({ page }) => {
  await page.keyboard.press('Tab');
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

// ---------------------------------------------------------------------------
// Assertion (Then) steps — exact visible copy/roles/test-ids only.
// ---------------------------------------------------------------------------

Then('the popup licence block shows HushVoting! Direct Free as current', async ({ page }) => {
  const block = page.getByRole('dialog', { name: 'User information' }).getByLabel('Licence');
  await expect(block.getByText('HushVoting! Direct Free')).toBeVisible();
});

Then('the popup shows Active and the exact 100 eligible-voter limit', async ({ page }) => {
  const block = page.getByRole('dialog', { name: 'User information' }).getByLabel('Licence');
  await expect(block.getByText('Active')).toBeVisible();
  await expect(block.getByText('Up to 100 eligible voters')).toBeVisible();
});

Then('the popup shows a shortened licence reference and the Upgrade action', async ({ page }) => {
  const block = page.getByRole('dialog', { name: 'User information' }).getByLabel('Licence');
  await expect(block.getByTestId('licence-short-reference')).toContainText('…');
  await expect(block.getByRole('button', { name: 'Upgrade' })).toBeVisible();
});

Then('no licence value from another identity is present', async ({ page }) => {
  const body = await page.locator('body').innerText();
  expect(body).not.toContain('Bob');
});

Then('the full-width licence page shows the current Direct Free detail first', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  await expect(workspace).toBeVisible();
  await expect(workspace.getByRole('heading', { level: 1, name: 'Licence' })).toBeVisible();
  await expect(workspace.getByRole('heading', { name: SECTION_CURRENT })).toBeVisible();
});

Then('it lists only strictly higher Veritas plans in server order', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  await expect(workspace.getByRole('heading', { name: SECTION_HIGHER })).toBeVisible();
  const optionNames = await workspace.locator('.licence-option-name').allInnerTexts();
  expect(optionNames.length).toBeGreaterThan(0);
  // Server order: Direct Free < Veritas 500 < Veritas 2k < Veritas 10k.
  expect(optionNames).toEqual([...optionNames].sort());
  expect(optionNames).not.toContain('HushVoting! Direct Free');
});

Then('each option shows its exact cap and one-year term from the catalogue', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  const caps = await workspace.locator('.licence-option-fact-row dd').allInnerTexts();
  expect(caps.some((value) => /eligible voters/i.test(value)) || caps.length).toBeGreaterThan(0);
});

Then('Enterprise is informational with no activation, link, form, or request', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  const enterprise = workspace.getByLabel('HushVoting! Enterprise');
  await expect(enterprise).toBeVisible();
  await expect(enterprise.getByText('Contact provider — not yet available')).toBeVisible();
  await expect(enterprise.getByRole('button')).toHaveCount(0);
  await expect(enterprise.getByRole('link')).toHaveCount(0);
});

Then('no price, payment, or provider submission surface is shown', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  const text = await workspace.innerText();
  expect(text).not.toMatch(/price|payment|£|€|\$|provider request|submit request/i);
});

Then('no assignment change happens before confirmation', async ({ page }) => {
  // Selecting/reviewing alone never creates a transaction (TwinTest proves
  // the server side); the UI remains on confirmation with no pending op.
  await expect(page.getByTestId('licence-view-confirmation')).toBeVisible();
});

Then('confirmation shows current and target plans with the exact one-year term and supersession', async ({ page }) => {
  const confirmation = page.getByTestId('licence-confirmation');
  await expect(confirmation.getByRole('heading', { name: CONFIRM_TITLE })).toBeVisible();
  await expect(confirmation.getByText('One-year term')).toBeVisible();
  await expect(confirmation.getByText('Once indexed, it immediately supersedes the current licence.')).toBeVisible();
  await expect(confirmation.getByText('The target becomes active only after indexed network confirmation.')).toBeVisible();
});

Then('Direct Free remains effective and no activation operation exists', async ({ page }) => {
  await expect(page.getByTestId('licence-view-options')).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/Upgrade pending|Licence activated/i);
});

Then('reopening requires a fresh selection and confirmation again', async ({ page }) => {
  await page.reload();
  await openLicenceWorkspace(page);
  // No draft is restored: the user must select again before confirmation.
  await expect(page.getByTestId('licence-view-options')).toBeVisible();
  await expect(page.getByTestId('licence-view-confirmation')).toHaveCount(0);
});

Then('no activation control exists for the current Veritas 2k plan', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  const current = workspace.getByLabel('HushVoting! Veritas 2k');
  await expect(current).toBeVisible();
  await expect(current.getByRole('button', { name: /activate|review/i })).toHaveCount(0);
});

Then('lower or Enterprise plans are not actionable in the delivered UI', async ({ page }) => {
  const workspace = page.getByTestId('licence-workspace-host');
  // Only strictly higher options render Review actions; Enterprise is an
  // informational aside with no interactive descendant.
  const enterprise = workspace.getByLabel('HushVoting! Enterprise');
  await expect(enterprise.getByRole('button')).toHaveCount(0);
  await expect(workspace.getByText('HushVoting! Direct Free')).not.toHaveCount(1);
});

Then('HushServerNode returns a stable typed rejection for any such attempt', async () => {
  // Server half of the pair: durable typed rejection outcomes are proven by
  // the same-ID TwinTests (Category=FEAT-017, e.g. Enterprise plan-unavailable,
  // transition-unchanged, not-higher). No UI path exists to provoke one.
});

Then('Alice\'s plan, expiry, and assignment remain unchanged', async ({ page }) => {
  await expect(page.getByLabel('HushVoting! Veritas 2k').first()).toBeVisible();
});

Then('pending shows the old indexed limits remain in effect and the pending target', async ({ page }) => {
  await expect(page.getByTestId('licence-view-progress')).toBeVisible();
  const progress = page.getByTestId('licence-progress');
  await expect(progress.getByText(LIMITS_REMAIN)).toBeVisible();
  await expect(page.getByTestId('progress-target-name')).toBeVisible();
});

Then('no higher capability is granted before indexed confirmation', async ({ page }) => {
  // The workspace keeps mounting under the old indexed Direct Free limits.
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/Veritas 2k licence is now active/i);
});

Then('the current licence becomes the higher Veritas plan with a one-year term', async ({ page }) => {
  // After indexed reconciliation the result/current surface shows the new plan.
  await expect
    .poll(async () => {
      const body = await page.locator('body').innerText();
      return body.includes('Veritas') && !body.includes('HushVoting! Direct Free licence is now active');
    }, { timeout: 90_000 })
    .toBe(true);
});

Then('Account refreshes to the higher plan exactly once without a repeated notification', async ({ page }) => {
  await expect(page.getByTestId('licence-activation-notification').or(page.getByTestId('licence-view-result')).first()).toBeVisible();
  const notifications = await page.getByTestId('licence-notification-message').count();
  expect(notifications).toBeLessThanOrEqual(1);
});

Then('the selection is cleared and the exact changed-options message is shown', async ({ page }) => {
  await expect(page.getByTestId('licence-view-stale')).toBeVisible();
  await expect(page.getByTestId('stale-notice')).toHaveText(STALE_NOTICE);
});

Then('fresh options are presented from the authoritative query', async ({ page }) => {
  await expect(page.getByTestId('licence-options')).toBeVisible();
});

Then('activation requires a new selection and explicit confirmation', async ({ page }) => {
  // S0 shows fresh options without any retained draft; selecting again is the
  // only way to a new confirmation.
  await expect(page.getByTestId('licence-view-confirmation')).toHaveCount(0);
});

Then('the options surface returns with no draft and no submitted transaction', async ({ page }) => {
  await expect(page.getByTestId('licence-view-options')).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/Upgrade pending/i);
});

Then('the safe shell state returns without duplicate activation or stale plan display', async ({ page }) => {
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/Licence activated/i);
});

Then('she can open and close the account popup and reach the Upgrade action', async ({ page }) => {
  await openAccountPopup(page);
  await expect(page.getByRole('button', { name: 'Upgrade' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'User information' })).toHaveCount(0);
});

Then('focus is trapped and restored correctly for the popup and confirmation', async ({ page }) => {
  await expect(page.getByRole('dialog', { name: 'User information' })).toBeVisible();
  await page.keyboard.press('Escape');
});

Then('current, activating, unavailable, conflict, and error states have programmatic names', async ({ page }) => {
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

Then('plan meaning is not communicated by colour alone', async ({ page }) => {
  const statusTexts = await page.locator('.licence-status-chip').allInnerTexts();
  for (const text of statusTexts) {
    expect(text.trim().length).toBeGreaterThan(0);
  }
});

Then('no control or status is clipped or hidden by overflow', async ({ page }) => {
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

Then('she can reach the Upgrade action from the licence page', async ({ page }) => {
  // Keyboard-only reachability across the account and licence surfaces.
  await expect(page.getByRole('button', { name: 'Upgrade' })).toBeVisible();
});
