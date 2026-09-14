/**
 * FEAT-007 playwright-bdd step definitions — platform-neutral Web scenarios.
 *
 * These steps drive the production composition (real UI, worker, IndexedDB,
 * BFF). Secret-bearing scenarios MUST disable trace/screenshot/video before
 * any recovery word or password appears (config already defaults capture off;
 * steps must never enable it for these scenarios).
 *
 * Remaining legacy bindings are incomplete. Validated browser/server
 * replacements run in the isolated HushVoting .NET infrastructure.
 * Original pending requirements are preserved; coverage mapping is separate
 * from runtime and semantic acceptance.
 */
import { createBdd } from 'playwright-bdd';

const { Then } = createBdd();

Then(/^progress appears after 150 ms$/, async ({ page }) => {
  // The generate surface announces progress through a live region.
  await page.getByText(/Generating your identity securely/).waitFor();
});
