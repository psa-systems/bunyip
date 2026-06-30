import { expect, test, type APIRequestContext } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, deleteMe, DISPOSABLE_PASSWORD } from '../../lib/accounts';
import { waitForLink, tokenFromLink, PASSWORD_RESET_RE } from '../../lib/mail-sink';

// Request a password reset and return the reset-link from the emailed message.
// Stalwart usually delivers in a few seconds, but the relay can lag or drop a
// single message under load, which timed out the 30s wait on run #1306
// (BUNYIP-267). Re-request once if the first email has not landed within ~40s -
// two requests stay within the 3/hour PASSWORD_RESET limit - so a single
// dropped mail does not fail the spec.
async function requestResetLink(ctx: APIRequestContext, email: string): Promise<string> {
  let lastError: unknown = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const requested = await ctx.post(routes.authPasswordReset, { data: { email } });
    expect(
      requested.ok(),
      `POST ${routes.authPasswordReset} -> ${requested.status()}: ${await requested.text()}`,
    ).toBeTruthy();
    try {
      return await waitForLink(email, PASSWORD_RESET_RE, { timeoutMs: 40_000 });
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

// Password-reset coverage (BUNYIP-149).
//
// bunyip's reset is a two-step flow: request a token (emailed to the account),
// then confirm a new password with that token. Driven over the JSON API + the
// Stalwart JMAP sink (BUNYIP-150): request the reset, read the token out of the
// mailbox, confirm a new password, and prove the new password logs in.
//
// Runs against a disposable account (resetting the shared E2E credential would
// break every other spec). Skips when no mail sink is configured.
test.describe('password reset', () => {
  const NEW_PASSWORD = 'E2e-Reset-Passw0rd!';

  test('request a reset token and set a new password', async ({ playwright }) => {
    test.skip(!env.mailSinkURL, 'needs E2E_MAIL_SINK_URL (BUNYIP-150)');
    // Re-requesting the reset and polling the sink twice can take up to ~80s;
    // give this spec 3x the default 60s budget so a slow relay does not trip the
    // per-test timeout (BUNYIP-267).
    test.slow();

    const owner = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    const reauth = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    try {
      const account = await registerDisposable(owner);
      expect(account.password).toBe(DISPOSABLE_PASSWORD);

      const link = await requestResetLink(owner, account.email);
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
      // re-authenticated context instead. The account's password is now the
      // reset value, so purge with that (BUNYIP-246).
      await deleteMe(reauth, NEW_PASSWORD);
      await owner.dispose();
      await reauth.dispose();
    }
  });
});
