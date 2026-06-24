import { expect, test } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, deleteMe } from '../../lib/accounts';
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
test.describe('magic-link login', () => {
  test('request a magic link and follow it to a live session', async ({ playwright }) => {
    test.skip(!env.mailSinkURL, 'needs E2E_MAIL_SINK_URL (BUNYIP-150)');

    const owner = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    const follower = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    try {
      const account = await registerDisposable(owner);

      const requested = await owner.post(routes.authMagicLink, { data: { email: account.email } });
      expect(
        requested.ok(),
        `POST ${routes.authMagicLink} -> ${requested.status()}: ${await requested.text()}`,
      ).toBeTruthy();

      const link = await waitForLink(account.email, MAGIC_LINK_RE);
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
      await deleteMe(owner);
      await owner.dispose();
      await follower.dispose();
    }
  });
});
