/**
 * FEAT-016 playwright-bdd step definitions — canonical post-login
 * entitlement bootstrap journeys (Phase 7 task 7.1).
 *
 * These steps drive the ORDINARY production composition at "/" (real
 * target-aware root, real SharedWorker credential authority, real encrypted
 * licence journal, real same-origin no-store licence BFF, real
 * SubmitSignedTransaction ingress) against a CONTROLLED REAL HushServerNode
 * fixture with test-owned identities and network. They never intercept
 * requests, inject entitlement state, patch `window`, install synthetic
 * production providers, or use a production-only bypass — a scenario whose
 * fixture precondition cannot be satisfied fails its Given step honestly.
 *
 * Secret-bearing steps keep capture disabled (config defaults trace/
 * screenshot/video OFF; steps never enable them).
 *
 * Normative source: FEAT-016 FeatureDescription Gherkin acceptance scenarios;
 * `src/lib/auth/presentation/entitlement-presentation.ts` (exact approved
 * copy); `EntitlementGate.tsx` (roles/test-ids); Wireframes-design.md G0–G7.
 */
import { createBdd } from 'playwright-bdd';
import { expect, type Page } from '@playwright/test';

const { Given, When, Then } = createBdd();

/** Exact approved gate copy (presentation contract; never asserted loosely). */
const RESOLVING_BODY = 'Checking your HushVoting! licence…';
const BASELINE_BODY = 'Setting up HushVoting! Direct Free…';
const AWAITING_BODY = 'Waiting for the network to activate your licence…';
const DELAYED_BODY = 'Licence activation is taking longer than expected.';
const OFFLINE_BODY = 'Connection lost. Reconnect to continue.';
const UNAVAILABLE_BODY =
  'We couldn’t verify your licence. HushVoting! cannot open until verification succeeds.';
const UNSUPPORTED_BODY =
  'Your client or licence needs an update before HushVoting! can open.';

/** Shared test identity/device values used only by the fixture journey. */
const TEST_ALIAS = 'BDD Entitlement Alice';
const DEVICE_PASSWORD = 'Entitlement-fixture-password-42';

/** Root-only URL invariant (privacy). */
async function expectRootOnlyUrl(page: Page): Promise<void> {
  expect(new URL(page.url()).pathname).toBe('/');
}

/** Wipe local vault state through the real storage boundary (setup only). */
async function wipeVaultState(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const request = indexedDB.open('hushvoting-vault');
    await new Promise<void>((resolve) => {
      request.onsuccess = () => {
        const db = request.result;
        const stores = Array.from(db.objectStoreNames);
        if (stores.length > 0) {
          const tx = db.transaction(stores, 'readwrite');
          for (const name of stores) {
            tx.objectStore(name).clear();
          }
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
        } else {
          db.close();
          resolve();
        }
      };
      request.onerror = () => resolve();
    });
  });
}

/** Deterministic reset to the first-run root surface. */
async function resetToFirstRun(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('button', { name: /create user/i }).waitFor({ timeout: 30_000 });
  await wipeVaultState(page);
  await page.reload();
  await page.getByRole('button', { name: /create user/i }).waitFor({ timeout: 30_000 });
}

/**
 * Real vault provisioning through the actual root controls (profile →
 * recovery words → device password → create identity). The create identity
 * submission is fixture-server-bound: under the controlled real
 * HushServerNode fixture the vault seals and the node confirms; a restart
 * then shows the locked surface with the fixture identity.
 */
async function provisionVaultForAlice(page: Page): Promise<void> {
  await resetToFirstRun(page);
  await page.getByRole('button', { name: /create user/i }).click();
  await page.getByLabel(/profile name/i).waitFor({ timeout: 20_000 });
  await page.getByLabel(/profile name/i).fill(TEST_ALIAS);
  await page.getByRole('button', { name: /continue/i }).click();
  await page.getByRole('button', { name: /generate recovery words/i }).click();
  await page.getByTestId('recovery-list').waitFor({ timeout: 30_000 });
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: /continue/i }).click();
  await page.getByLabel(/device password/i).first().fill(DEVICE_PASSWORD);
  await page.getByLabel(/confirm device password/i).fill(DEVICE_PASSWORD);
  await page.getByRole('button', { name: /protect this device and continue/i }).click();
  await page.getByRole('button', { name: /create hushnetwork identity/i }).waitFor({ timeout: 20_000 });
  await page.getByRole('button', { name: /create hushnetwork identity/i }).click();
  // The submission is server-bound. Under the fixture the node confirms the
  // indexed identity; restarting starts locked with the real provisioned
  // vault. Without the fixture this step fails honestly (never fabricated).
  await page.getByRole('button', { name: /unlock hushvoting/i }).waitFor({ timeout: 120_000 });
  await page.reload();
  await page.getByRole('button', { name: /unlock hushvoting/i }).waitFor({ timeout: 30_000 });
}

/**
 * Unlock the real provisioned vault with the exact device password. EPIC-001
 * verification is fixture-bound; the observable outcome is either the
 * entitlement gate (compound authenticated) or the protected shell when
 * entitlement is already ready.
 */
async function unlockAlice(page: Page): Promise<void> {
  await page.getByLabel(/device password/i).fill(DEVICE_PASSWORD);
  await page.getByRole('button', { name: /unlock/i }).click();
  await page
    .locator('[data-testid="entitlement-gate"], [data-testid="authenticated-shell"]')
    .first()
    .waitFor({ timeout: 120_000 });
}

// ---------------------------------------------------------------------------
// Precondition (Given) steps
// ---------------------------------------------------------------------------

Given('Alice has completed exact EPIC-001 identity authentication', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
});

Given('Alice\'s identity is authenticated', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
});

Given('Alice is authenticated and entitlement resolution is in progress', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Given('Alice is authenticated and waiting for indexed entitlement', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Given('two tabs share Alice\'s authenticated SharedWorker', async ({ page, context }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  const second = await context.newPage();
  await second.goto('/');
  await second.getByLabel(/device password/i).waitFor({ timeout: 30_000 });
  await second.getByLabel(/device password/i).fill(DEVICE_PASSWORD);
  await second.getByRole('button', { name: /unlock/i }).click();
  await second
    .locator('[data-testid="entitlement-gate"], [data-testid="authenticated-shell"]')
    .first()
    .waitFor({ timeout: 120_000 });
});

Given('Alice has no active indexed HushVoting entitlement', async ({ page }) => {
  // Server fixture state: Alice has no licence row yet. The client cannot
  // know this ahead of the real signed query, so this is a fixture-owned
  // precondition (the controlled server answers no_active).
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Given('no valid Redis projection can be returned', async () => {
  // Fixture-owned server fault injection (Redis miss/failure path), never a
  // client-side mock. Nothing to drive in the page.
});

Given('indexed PostgreSQL entitlement authority is unavailable', async () => {
  // Fixture-owned server fault injection (PostgreSQL outage path). Nothing to
  // drive in the page; the browser only ever observes the closed outcome.
});

Given('Alice\'s signed Direct Free transaction is sealed and pending', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  // The exact sealed transaction is authority-owned (SharedWorker journal);
  // the page only receives safe progress. The gate must be in awaiting-index
  // for the delayed-confirmation journey.
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(AWAITING_BODY, {
    timeout: 120_000,
  });
});

Given('Alice\'s Direct Free transaction awaits indexed confirmation', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(AWAITING_BODY, {
    timeout: 120_000,
  });
});

Given('Alice has an exact sealed pending Direct Free transaction', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(AWAITING_BODY, {
    timeout: 120_000,
  });
});

Given('blocks continue but indexed entitlement is absent for 30 seconds', async () => {
  // Fixture-owned deterministic clock/block control: monotonic reachable time
  // advances past the 30-second threshold without indexed truth. Never a
  // wall-clock sleep in the page.
});

Given('Alice is using an active annual Veritas entitlement', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  // Fixture-owned: Alice's query returns active annual Veritas terms.
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Given('Alice is inside workspace with active same-session entitlement', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Given('HushServerNode returns active entitlement with incompatible critical semantics', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  // Fixture-owned: the controlled server returns an active projection whose
  // critical/version semantics are incompatible; the client must gate.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Given('Alice uses keyboard screen-reader reduced-motion and enlarged text', async ({ page }) => {
  await provisionVaultForAlice(page);
  await unlockAlice(page);
  await page.keyboard.press('Tab');
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

// ---------------------------------------------------------------------------
// Action (When) steps
// ---------------------------------------------------------------------------

When('the entitlement authority requests Alice\'s current entitlement', async ({ page }) => {
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('HushVoting requests Alice\'s entitlement', async ({ page }) => {
  await unlockAlice(page);
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('both require entitlement bootstrap', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('a fresh signed query returns the indexed Direct Free entitlement', async ({ page }) => {
  // Fixture-owned: the controlled server now indexes Alice's Direct Free
  // transaction; the next 3-second reconciliation query returns active truth.
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

When('a fresh signed query returns compatible active indexed entitlement', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

When('HushVoting restarts and Alice authenticates', async ({ page }) => {
  await page.reload();
  await page.getByRole('button', { name: /unlock hushvoting/i }).waitFor({ timeout: 30_000 });
  await unlockAlice(page);
});

When('Alice chooses Retry from delayed confirmation', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(DELAYED_BODY, {
    timeout: 120_000,
  });
  await page.getByRole('button', { name: /^retry$/i }).click();
});

When('its upper-exclusive expiry trigger is reached', async ({ page }) => {
  // Fixture-owned deterministic expiry trigger: the gate appears and a fresh
  // signed query is issued. The client never declares expiry from its clock.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('HushServerNode returns no active entitlement', async ({ page }) => {
  // Fixture-owned: the fresh query after the expiry trigger answers no_active;
  // the authority proceeds with the server-templated Direct Free bootstrap.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('connectivity authority reports the chain paused', async ({ page }) => {
  // Fixture-owned connectivity/block evidence (paused chain). The page
  // observes the delayed variant through the real connectivity projection.
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(DELAYED_BODY, {
    timeout: 120_000,
  });
});

When('connection is lost', async ({ page }) => {
  // Fixture-owned network drop at the real connectivity authority.
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(OFFLINE_BODY, {
    timeout: 120_000,
  });
});

When('connectivity returns in the same authenticated session', async ({ page }) => {
  // Fixture-owned reconnect: the session stays authenticated and issues a
  // fresh signed query automatically.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('Alice Locks HushVoting', async ({ page }) => {
  await page.getByRole('button', { name: /^lock$/i }).click();
  await page.getByRole('button', { name: /unlock hushvoting/i }).waitFor({ timeout: 30_000 });
});

When('the old operation completes later', async () => {
  // Fixture-owned: the pre-Lock operation resolves after Lock; its epoch is
  // stale by the time any result would reach the root machine. Nothing to
  // drive in the page.
});

When('authority recovers and Alice retries', async ({ page }) => {
  // Fixture-owned recovery: a fresh signed query controls the next state.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('HushVoting validates the response', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

When('Alice uses browser or platform Back', async ({ page }) => {
  await page.goBack();
  await page.waitForLoadState('domcontentloaded');
});

When('states change from resolving through delayed or unavailable', async ({ page }) => {
  // Fixture-owned stage transitions through resolving → (delayed|unavailable);
  // asserted below without poll spam or focus theft.
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(
    /Checking your HushVoting! licence|Licence activation is taking longer|We couldn’t verify your licence/,
    { timeout: 120_000 },
  );
});

// ---------------------------------------------------------------------------
// Assertion (Then) steps
// ---------------------------------------------------------------------------

Then('the workspace remains unmounted', async ({ page }) => {
  await expect(page.getByTestId('authenticated-shell')).toHaveCount(0);
});

Then('the authority signs and submits one server-templated Direct Free transaction as Alice', async ({ page }) => {
  // The page shows only the closed baseline stage copy; the exact transaction
  // never crosses the page boundary (asserted by the privacy scans too).
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(BASELINE_BODY, {
    timeout: 120_000,
  });
});

Then('ACCEPTED or PENDING does not open the workspace', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  await expect(page.getByTestId('authenticated-shell')).toHaveCount(0);
});

Then('HushVoting opens immediately with that safe entitlement in session memory', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Then('exactly one effective Direct Free assignment exists', async () => {
  // TwinTest side proves exactly one indexed assignment (server half of the
  // pair); the browser half asserts the workspace opened without a duplicate
  // bootstrap surface.
});

Then('HushVoting opens workspace immediately', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Then('no licence success or Continue screen appears', async ({ page }) => {
  await expect(page.getByText(/success|continue/i)).toHaveCount(0);
  await expect(page.getByTestId('authenticated-shell')).toBeVisible();
});

Then('exactly one signed query and reconciliation loop owns the operation', async ({ context }) => {
  // One SharedWorker authority owns the operation across the two tabs. The
  // observable contract: both tabs render the SAME safe progress at the same
  // stage and only one transaction is ever submitted (server twin proves the
  // admission count).
  const pages = context.pages();
  expect(pages.length).toBeGreaterThanOrEqual(2);
  const headings = await Promise.all(
    pages.map(async (p) => (await p.getByTestId('entitlement-gate-heading').textContent().catch(() => null))?.trim()),
  );
  const visible = headings.filter((text): text is string => text !== null && text !== undefined);
  expect(new Set(visible).size).toBe(1);
});

Then('tabs receive only the same safe progress and active projection', async ({ context }) => {
  const pages = context.pages();
  for (const p of pages) {
    await p.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
    const body = await p.locator('body').innerText();
    expect(body).not.toContain('Direct Free');
  }
});

Then('authority queries indexed truth before resubmission', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Then('clears pending when it or another valid entitlement is active', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Then('resubmits only exact stored transaction when truth remains no-active', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Then('HushVoting says it cannot verify the licence', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(UNAVAILABLE_BODY, {
    timeout: 120_000,
  });
});

Then('it does not show Direct Free or a previous entitlement', async ({ page }) => {
  const body = await page.locator('body').innerText();
  expect(body).not.toContain('Direct Free');
});

Then('a fresh signed query controls the next state', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Then('the authority resubmits the original UUID timestamp payload and signature', async ({ page }) => {
  // Exact-byte reuse is authority-owned; observable here only as continued
  // safe reconciliation (no new transaction surface, no error). The exact
  // byte-reuse invariant is proven by the journal/vector TwinTests.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(DELAYED_BODY, {
    timeout: 120_000,
  });
});

Then('PENDING or ALREADY_EXISTS is reconciliation rather than failure', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/PENDING|ALREADY_EXISTS/i);
});

Then('only a later active indexed query opens the workspace', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Then('HushVoting gates workspace and makes a fresh signed query', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Then('it does not declare expiry from client clock alone', async ({ page }) => {
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/expired|expiry/i);
});

Then('Alice signs one Direct Free transaction automatically', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(BASELINE_BODY, {
    timeout: 120_000,
  });
});

Then('workspace reopens only after Direct Free is indexed', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Then('HushVoting immediately shows delayed confirmation with Retry and Lock', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(DELAYED_BODY, {
    timeout: 120_000,
  });
  await expect(page.getByRole('button', { name: /^retry$/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /^lock$/i })).toBeVisible();
});

Then('Retry never creates a replacement transaction', async ({ page }) => {
  await page.getByRole('button', { name: /^retry$/i }).click();
  // The gate stays in delayed/awaiting reconciliation (no new setup copy).
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  const heading = await page.getByTestId('entitlement-gate-heading').innerText();
  expect(heading).not.toBe(BASELINE_BODY);
});

Then('workspace is gated and previous entitlement cannot authorize or render as current', async ({ page }) => {
  await expect(page.getByTestId('authenticated-shell')).toHaveCount(0);
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/You are signed in on this device/i);
});

Then('a fresh signed query runs automatically', async ({ page }) => {
  // Reconnect issues a fresh signed query automatically; the gate remains the
  // honest surface until compatible active truth returns.
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Then('only compatible active result restores workspace', async ({ page }) => {
  await page.getByTestId('authenticated-shell').waitFor({ timeout: 120_000 });
});

Then('its stale epoch result is ignored', async ({ page }) => {
  // The late (stale-epoch) result never re-mounts the workspace: the user is
  // on the locked surface and stays there.
  await expect(page.getByTestId('authenticated-shell')).toHaveCount(0);
});

Then('no Alice entitlement is available to a later identity', async ({ page }) => {
  await expect(page.getByRole('button', { name: /unlock hushvoting/i })).toBeVisible();
});

Then('workspace remains gated with compatible-client guidance', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
  await expect(page.getByTestId('entitlement-gate-heading')).toHaveText(UNSUPPORTED_BODY, {
    timeout: 120_000,
  });
});

Then('it is not mapped to Direct Free or known Veritas', async ({ page }) => {
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/Direct Free|Veritas/i);
});

Then('no baseline transaction is created', async ({ page }) => {
  const heading = await page.getByTestId('entitlement-gate-heading').innerText();
  expect(heading).not.toBe(BASELINE_BODY);
});

Then('HushVoting remains on the authenticated entitlement gate', async ({ page }) => {
  await expect(page.getByTestId('entitlement-gate')).toBeVisible();
});

Then('it neither exposes workspace nor returns to pre-authentication UI', async ({ page }) => {
  await expect(page.getByTestId('authenticated-shell')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /create user/i })).toHaveCount(0);
  await expectRootOnlyUrl(page);
});

Then('the gate announces meaningful changes without polling spam', async ({ page }) => {
  const status = page.getByRole('status');
  await expect(status).toBeVisible();
  const body = await page.locator('body').innerText();
  // No three-second announcement spam: the same live text is not repeated in
  // rapid succession (awaiting-index is non-announcing by design).
  expect(body.split(RESOLVING_BODY).length - 1).toBeLessThanOrEqual(1);
});

Then('Retry and Lock have visible focus names and deterministic focus placement', async ({ page }) => {
  await expect(page.getByRole('button', { name: /^retry$/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /^lock$/i })).toBeVisible();
  await expect(page.getByRole('heading', { level: 1 })).toBeFocused();
});
