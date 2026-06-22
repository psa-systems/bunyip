import { expect, test } from '@playwright/test';
import { tagged } from '../../lib/factories';
import { blockLiveReload } from '../../lib/login';

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
    // BUNYIP-148 diag: /settings closes the page before goto in CI; surface why.
    page.on('crash', () => console.log('[/settings] PAGE CRASHED'));
    page.on('pageerror', (e) => console.log('[/settings] pageerror:', e.message));
    page.on('console', (m) => {
      if (m.type() === 'error') console.log('[/settings] console.error:', m.text());
    });
    await blockLiveReload(page);
  });

  test('update profile fields and confirm they persist', async ({ page }) => {
    await page.goto('/settings');

    const firstName = tagged('First');
    const lastName = tagged('Last');
    const phone = '+15555550123';

    const form = page.locator('form').first();
    const firstInput = form.locator('input#first_name, input[name="first_name"]').first();
    const lastInput = form.locator('input#last_name, input[name="last_name"]').first();
    const phoneInput = form.locator('input#phone, input[name="phone"]').first();

    await firstInput.waitFor({ state: 'visible', timeout: 15_000 });
    await firstInput.fill(firstName);
    await lastInput.fill(lastName);
    await phoneInput.fill(phone);

    await form.getByRole('button', { name: /save|update|submit/i }).first().click();

    // Reload from the server so the assertion proves persistence, not just the
    // in-page form state we typed.
    await page.goto('/settings');
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
