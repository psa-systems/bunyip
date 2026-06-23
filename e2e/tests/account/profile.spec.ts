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
