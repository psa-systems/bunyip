import { expect, test } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, deleteMe, disposableEmail } from '../../lib/accounts';
import { waitForLink, tokenFromLink, EMAIL_CHANGE_RE, EMAIL_VERIFY_RE } from '../../lib/mail-sink';

// Change-email coverage (BUNYIP-149).
//
// POST /v1/users/me/email starts an email-change that bunyip confirms by
// emailing a verification link to the NEW address; the change only takes effect
// once that link is followed. Driven over the JSON API + the Stalwart JMAP sink
// (BUNYIP-150): request the change, read the link out of the mailbox (sent to
// the new address), confirm the token, then prove the account's email is now
// the new value.
//
// IMPORTANT: this emailed-confirm path only applies to a VERIFIED account.
// `request_email_change` (crates/bunyip-domain/src/services/auth.rs) changes an
// UNVERIFIED account's email immediately, without sending any link. A freshly
// registered disposable account is unverified, so the spec first verifies it
// via the verify-email flow (also over the sink) so the change takes the
// verified, link-confirmed path it is meant to exercise.
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

      // Verify the disposable account first (over the sink), so the email
      // change below takes the verified, link-confirmed path rather than the
      // unverified immediate-change path that sends no email.
      const verifyRequested = await owner.post(routes.userEmailVerify);
      expect(
        verifyRequested.ok(),
        `POST ${routes.userEmailVerify} -> ${verifyRequested.status()}: ${await verifyRequested.text()}`,
      ).toBeTruthy();
      const verifyLink = await waitForLink(account.email, EMAIL_VERIFY_RE);
      const verified = await owner.post(routes.userEmailVerifyConfirm, {
        data: { token: tokenFromLink(verifyLink) },
      });
      expect(
        verified.ok(),
        `POST ${routes.userEmailVerifyConfirm} -> ${verified.status()}: ${await verified.text()}`,
      ).toBeTruthy();

      const newEmail = disposableEmail();

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
