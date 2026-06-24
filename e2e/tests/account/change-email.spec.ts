import { expect, test } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, deleteMe, disposableEmail } from '../../lib/accounts';
import { clearMailbox, waitForLink, tokenFromLink, EMAIL_CHANGE_RE } from '../../lib/mail-sink';

// Change-email coverage (BUNYIP-149).
//
// POST /v1/users/me/email starts an email-change that bunyip confirms by
// emailing a verification link to the NEW address; the change only takes effect
// once that link is followed. Driven over the JSON API + the Mailpit sink
// (BUNYIP-150): request the change, read the link out of the sink (sent to the
// new address), confirm the token, then prove the account's email is now the
// new value.
//
// This spec is in the account-ui project, which injects the SHARED storageState
// into the default browser context. We never use that context (the whole flow
// runs on isolated request contexts for a disposable account), and pin
// storageState: undefined so a future edit cannot accidentally mutate the
// shared login. Skips when no mail sink is configured.
test.use({ storageState: undefined });

test.describe('change email', () => {
  test('request an email change and confirm via the emailed link', async ({ playwright }) => {
    test.skip(!env.mailSinkURL, 'needs E2E_MAIL_SINK_URL (BUNYIP-150)');

    const owner = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    const reauth = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    try {
      const account = await registerDisposable(owner);
      const newEmail = disposableEmail();

      await clearMailbox();
      const requested = await owner.post(routes.userEmail, {
        data: { new_email: newEmail, current_password: account.password },
      });
      expect(
        requested.ok(),
        `POST ${routes.userEmail} -> ${requested.status()}: ${await requested.text()}`,
      ).toBeTruthy();

      // The verification link is sent to the NEW address.
      const link = await waitForLink(newEmail, EMAIL_CHANGE_RE);
      const token = tokenFromLink(link);

      const confirmed = await owner.post(routes.userEmailConfirm, { data: { token } });
      expect(
        confirmed.ok(),
        `POST ${routes.userEmailConfirm} -> ${confirmed.status()}: ${await confirmed.text()}`,
      ).toBeTruthy();

      // bunyip tells the user to log in with the new email after confirming;
      // do exactly that, then assert the account now reports the new address.
      const login = await reauth.post(routes.authLogin, {
        data: { email: newEmail, password: account.password },
      });
      expect(
        login.ok(),
        `login with the new email -> ${login.status()}: ${await login.text()}`,
      ).toBeTruthy();

      const me = await reauth.get(routes.userMe);
      expect(me.status(), `GET ${routes.userMe}`).toBe(200);
      expect(await me.text(), 'current user should report the new email').toContain(newEmail);
    } finally {
      await deleteMe(reauth);
      await owner.dispose();
      await reauth.dispose();
    }
  });
});
