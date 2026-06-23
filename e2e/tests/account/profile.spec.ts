import { expect, test } from '@playwright/test';
import { tagged } from '../../lib/factories';
import { blockLiveReload, setInputValue } from '../../lib/login';
import { attachPageDiagnostics } from '../../lib/page-diagnostics';

// Profile-edit coverage (BUNYIP-149). Runs in the `account-ui` project: the
// browser is ALREADY authenticated (storageState saved by `setup`), so this
// spec does NOT call loginViaHub - doing so would spend a login against the
// 5/min rate limit. The live session carries the cookies for both the page
// navigation and any page.request call.
//
// Non-destructive: the profile is the only mutable field group that does not
// invalidate the session or change credentials. Each run writes run-unique
// first/last names (via `tagged`) and a fixed phone, submits the real
// server-rendered POST /settings/profile, reloads, and asserts the values
// persisted. The next run overwrites them, so there is nothing to sweep.
// BUNYIP-148: /settings consistently kills the chromium renderer on the CI
// runner. The page-diagnostics dump (commit 6f7ba14) proved the failure
// happens BETWEEN navigation-commit and DOMContentLoaded - goto returns with
// `currentUrl=/settings` (so the server response landed), but the renderer
// then dies during initial parse/paint. The request trail at death always
// ends at the four fontawesome CSS shards (ka-f.fontawesome.com/.../free.min,
// free-v4-shims, free-v5-font-face, free-v4-font-face), with no follow-up
// font (.woff2) requests - so the renderer dies parsing those CSS files or
// running the kit JS that pre-loaded them. The browser process itself stays
// up (closes cleanly with exitCode=0 between tests, /membership succeeds on
// the same browser), so only the renderer process dies.
//
// Attempts made so far that did NOT fix it (all kept in the config as
// defense in depth):
//   - --disable-dev-shm-usage (commit 0407e4f)
//   - channel: 'chromium' (commit dadf184)
//   - project ordering, so account-ui runs uninterrupted (commit 9c0aa9f)
//   - waitUntil: 'commit' + waitForLoadState split (commit 6f7ba14)
//   - --disable-gpu + --no-sandbox (commit 9c56dcf)
//
// What is left to try (out of scope for this fix, tracked under BUNYIP-148):
//   - reproduce against staging in a real terminal with DEBUG=pw:browser*,
//     pw:protocol* and inspect the trace.zip artifact to see exactly what is
//     in the DOM when the renderer dies;
//   - block fontawesome's CDN at the page.route layer as a diagnostic to
//     confirm or rule out the kit JS / CSS as the trigger;
//   - audit the /settings handler for a server-side change since the spec
//     was added (e.g. trusted-devices card, gradient header) that would
//     explain why /membership renders cleanly on the same browser.
//
// Skipping via test.fixme follows the established pattern in this suite
// (the auth-ui specs already fixme magic-link, password-reset, signup, and
// two-factor for similar reasons). The skip keeps CI green so unrelated PRs
// can land; the coverage gap stays tracked under the ticket.
test.describe('account profile', () => {
  // bunyip-web reloads the page on SSE events (BUNYIP-168); block it so a reload
  // never wipes a form mid-edit.
  test.beforeEach(async ({ page }) => {
    await blockLiveReload(page);
  });

  test('update profile fields and confirm they persist', async ({ page }) => {
    // BUNYIP-148: /settings goto fails with "Target page, context or browser
    // has been closed" on the CI runner. The previous `channel: 'chromium'` +
    // `--disable-dev-shm-usage` + project-ordering attempts did not fix it.
    // Theory: the default `waitUntil: 'load'` waits for every subresource on a
    // heavy page (settings = profile + email + password + 2FA + sessions +
    // trusted-devices), and the renderer dies between `commit` and `load`
    // while playwright is still blocked on the load promise. Switching to
    // `commit` returns as soon as the navigation commits (response headers
    // arrived, URL updated). If the renderer dies after that, subsequent
    // locator calls fail with their own (more diagnosable) errors instead of
    // the opaque page-closed message from goto.
    //
    // attachPageDiagnostics tracks the URL trail + request log; if this still
    // fails, the thrown error carries both so the next iteration is precise.
    const diag = attachPageDiagnostics(page);
    try {
      await page.goto('/settings', { waitUntil: 'commit' });
      await page.waitForLoadState('domcontentloaded', { timeout: 15_000 });
    } catch (e) {
      throw new Error(`${(e as Error).message}\n${diag.snapshot('after goto /settings')}`);
    }

    const firstName = tagged('First');
    const lastName = tagged('Last');
    const phone = '+15555550123';

    const form = page.locator('form').first();
    const firstInput = form.locator('input#first_name, input[name="first_name"]').first();
    const lastInput = form.locator('input#last_name, input[name="last_name"]').first();
    const phoneInput = form.locator('input#phone, input[name="phone"]').first();

    await firstInput.waitFor({ state: 'visible', timeout: 15_000 });
    // DOM-set, not fill(): Playwright fill() is a no-op on these inputs in the CI
    // runner's headless chromium (BUNYIP-168).
    await setInputValue(firstInput, firstName);
    await setInputValue(lastInput, lastName);
    await setInputValue(phoneInput, phone);

    await form.getByRole('button', { name: /save|update|submit/i }).first().click();

    // Reload from the server so the assertion proves persistence, not just the
    // in-page form state we typed. Same `commit` strategy as the first goto.
    await page.goto('/settings', { waitUntil: 'commit' });
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 });
    const reloadedForm = page.locator('form').first();
    await expect(
      reloadedForm.locator('input#first_name, input[name="first_name"]').first(),
    ).toHaveValue(firstName);
    await expect(
      reloadedForm.locator('input#last_name, input[name="last_name"]').first(),
    ).toHaveValue(lastName);
    await expect(
      reloadedForm.locator('input#phone, input[name="phone"]').first(),
    ).toHaveValue(phone);
  });
});
