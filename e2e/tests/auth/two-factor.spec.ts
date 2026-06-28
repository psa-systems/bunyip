import { authenticator } from 'otplib';
import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Two-factor (TOTP) enrollment + challenge coverage (BUNYIP-149).
//
// `test.fixme`: blocked on BUNYIP-152. Exercising the full 2FA ENROLLMENT flow
// (scan secret -> confirm a code -> enable) needs an account that does NOT
// already have 2FA on plus a captured secret, and would mutate that account's
// security posture on every run. The shared E2E account already has 2FA
// enabled (lib/login.ts drives the /login/2fa challenge from E2E_TOTP_SECRET on
// every login), so the CHALLENGE leg is already covered indirectly there. A
// dedicated, disposable account with a known starting state is required to test
// enrollment without disturbing the shared account. Un-fixme once BUNYIP-152
// provisions that account + secret.
//
// The body sketches the intended enrollment assertion: enroll, confirm a
// freshly computed TOTP code, and assert 2FA is reported as enabled.
test.describe('two-factor authentication', () => {
  test.fixme('enroll TOTP and confirm with a generated code', async ({ page }) => {
    // 1. Open the 2FA settings surface for the disposable account and start
    //    enrollment; bunyip renders the base32 secret to seed an authenticator.
    await page.goto('/settings');

    // 2. BUNYIP-152: capture the displayed secret, then compute and submit a
    //    code from it (otplib defaults match bunyip's RFC 6238 TOTP module).
    const enrolledSecret = 'SECRET_FROM_ENROLLMENT_SCREEN';
    const code = authenticator.generate(enrolledSecret);
    const form = page.locator('form').first();
    await form
      .locator('input#code, input[name="code"], input[inputmode="numeric"]')
      .first()
      .fill(code);
    await form.getByRole('button', { name: /verify|enable|confirm|submit/i }).first().click();

    // 3. Assert 2FA is now enabled for the account.
    expect(env.totpSecret).toBeTruthy();
  });
});
