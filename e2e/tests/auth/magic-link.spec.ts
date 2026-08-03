import { expect, test, type APIRequestContext } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, deleteMe, DISPOSABLE_PASSWORD } from '../../lib/accounts';
import { waitForLink, tokenFromLink, MAGIC_LINK_RE } from '../../lib/mail-sink';

// Magic-link (passwordless) login coverage (BUNYIP-149).
//
// bunyip's /magic-link flow emails a one-time login link; following it
// establishes a session with no password. Driven over the JSON API + the
// Stalwart JMAP sink (BUNYIP-150): request the link, read it out of the
// mailbox, verify the token on a FRESH context, and assert it is authenticated.
//
// Uses a disposable account rather than the shared E2E account so the flow does
// not interact with the shared account's 2FA. Skips when no mail sink is
// configured (production, or an unprovisioned staging).

// Request a magic link and return the login-link from the emailed message.
// Stalwart usually delivers in a few seconds, but the relay can lag or drop a
// single message under load, which timed out the 30s wait on run #1415
// (BUNYIP-279), mirroring the password-reset flake fixed in BUNYIP-267. Re-request
// once if the first email has not landed within ~40s - two requests stay within
// the 3/10min MAGIC_LINK limit - so a single dropped mail does not fail the spec.
async function requestMagicLink(ctx: APIRequestContext, email: string): Promise<string> {
  let lastError: unknown = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const requested = await ctx.post(routes.authMagicLink, { data: { email } });
    expect(
      requested.ok(),
      `POST ${routes.authMagicLink} -> ${requested.status()}: ${await requested.text()}`,
    ).toBeTruthy();
    try {
      return await waitForLink(email, MAGIC_LINK_RE, { timeoutMs: 40_000 });
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

test.describe('magic-link login', () => {
  test('request a magic link and follow it to a live session', async ({ playwright }) => {
    test.skip(!env.mailSinkURL, 'needs E2E_MAIL_SINK_URL (BUNYIP-150)');
    // requestMagicLink re-requests once if the first email lags, so the mail
    // wait can run up to 2x40s; give this spec 3x the default 60s per-test
    // budget so the retry has room, mirroring password-reset.spec (BUNYIP-452).
    test.slow();

    const owner = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    const follower = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    try {
      const account = await registerDisposable(owner);

      const link = await requestMagicLink(owner, account.email);
      const token = tokenFromLink(link);

      // Verify on the follower context (no prior session): a 200 from
      // memberships afterwards means the magic link alone established a session.
      const verified = await follower.post(routes.authMagicLinkVerify, { data: { token } });
      expect(
        verified.ok(),
        `POST ${routes.authMagicLinkVerify} -> ${verified.status()}: ${await verified.text()}`,
      ).toBeTruthy();

      const me = await follower.get(routes.memberships);
      expect(me.status(), 'magic-link session should read memberships').toBe(200);
    } finally {
      // `owner` still holds the register session; purge with the disposable
      // account password (BUNYIP-246).
      await deleteMe(owner, DISPOSABLE_PASSWORD);
      await owner.dispose();
      await follower.dispose();
    }
  });
});
