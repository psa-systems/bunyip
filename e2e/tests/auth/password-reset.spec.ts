import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Password-reset coverage (BUNYIP-149).
//
// `test.fixme`: blocked on a mail sink (BUNYIP-150). bunyip's reset is a
// two-step server-rendered flow: POST /password-reset (request a token, emailed
// to the account) then /password-reset/confirm (set a new password with that
// token). The token only arrives by email, so without a programmatic mailbox
// the confirm step cannot run. Resetting the SHARED E2E account credential
// would also break every other spec, so even with a sink this should target a
// disposable account. Un-fixme once the mail sink lands (BUNYIP-150) and a
// throwaway account is available.
//
// The body sketches the intended flow against the real forms.
test.describe('password reset', () => {
  test.fixme('request a reset token and set a new password', async ({ page }) => {
    // 1. Request the reset email for a disposable account (NOT env.email - that
    //    is the shared E2E credential).
    await page.goto('/password-reset');
    const requestForm = page.locator('form').first();
    await requestForm
      .locator('input#email, input[name="email"], input[type="email"]')
      .first()
      .fill('disposable@example.invalid');
    await requestForm.getByRole('button', { name: /reset|send|submit|continue/i }).first().click();

    // 2. BUNYIP-150: read the reset token out of the mail sink and open the
    //    confirm page with it.
    const token = 'TOKEN_FROM_MAIL_SINK';
    await page.goto(`/password-reset/confirm?token=${token}`);
    const confirmForm = page.locator('form').first();
    const newPassword = 'E2e-Reset-Passw0rd!'; // policy-compliant.
    await confirmForm
      .locator('input#password, input[name="password"]')
      .first()
      .fill(newPassword);
    await confirmForm
      .locator('input#confirm, input[name="confirm"], input[name="password_confirm"]')
      .first()
      .fill(newPassword);
    await confirmForm.getByRole('button', { name: /reset|set|confirm|submit/i }).first().click();

    // 3. Assert login with the new password succeeds.
    expect(env.baseURL).toBeTruthy();
  });
});
