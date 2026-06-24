import { expect, test } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, deleteMe, DISPOSABLE_PASSWORD } from '../../lib/accounts';
import { clearMailbox, waitForLink, tokenFromLink, PASSWORD_RESET_RE } from '../../lib/mail-sink';

// Password-reset coverage (BUNYIP-149).
//
// bunyip's reset is a two-step flow: request a token (emailed to the account),
// then confirm a new password with that token. Driven over the JSON API + the
// Mailpit sink (BUNYIP-150): request the reset, read the token out of the sink,
// confirm a new password, and prove the new password logs in.
//
// Runs against a disposable account (resetting the shared E2E credential would
// break every other spec). Skips when no mail sink is configured.
test.describe('password reset', () => {
  const NEW_PASSWORD = 'E2e-Reset-Passw0rd!';

  test('request a reset token and set a new password', async ({ playwright }) => {
    test.skip(!env.mailSinkURL, 'needs E2E_MAIL_SINK_URL (BUNYIP-150)');

    const owner = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    const reauth = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    try {
      const account = await registerDisposable(owner);
      expect(account.password).toBe(DISPOSABLE_PASSWORD);

      await clearMailbox();
      const requested = await owner.post(routes.authPasswordReset, {
        data: { email: account.email },
      });
      expect(
        requested.ok(),
        `POST ${routes.authPasswordReset} -> ${requested.status()}: ${await requested.text()}`,
      ).toBeTruthy();

      const link = await waitForLink(account.email, PASSWORD_RESET_RE);
      const token = tokenFromLink(link);

      const confirmed = await owner.post(routes.authPasswordResetConfirm, {
        data: { token, new_password: NEW_PASSWORD },
      });
      expect(
        confirmed.ok(),
        `POST ${routes.authPasswordResetConfirm} -> ${confirmed.status()}: ${await confirmed.text()}`,
      ).toBeTruthy();

      // The reset is real only if the NEW password now logs in (and the account
      // has no 2FA, so login completes in one step).
      const login = await reauth.post(routes.authLogin, {
        data: { email: account.email, password: NEW_PASSWORD },
      });
      expect(
        login.ok(),
        `login with the reset password -> ${login.status()}: ${await login.text()}`,
      ).toBeTruthy();
    } finally {
      // The reset revoked the original session on `owner`; delete via the
      // re-authenticated context instead.
      await deleteMe(reauth);
      await owner.dispose();
      await reauth.dispose();
    }
  });
});
