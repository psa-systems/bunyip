import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Magic-link (passwordless) login coverage (BUNYIP-149).
//
// `test.fixme`: blocked on a mail sink (BUNYIP-150). bunyip's /magic-link flow
// emails a one-time login link; following it establishes a session with no
// password. The link only arrives by email, so without a programmatic mailbox
// the flow cannot complete. Un-fixme once the mail sink lands (BUNYIP-150).
//
// The body sketches the intended flow against the real /magic-link form.
test.describe('magic-link login', () => {
  test.fixme('request a magic link and follow it to a live session', async ({ page }) => {
    // 1. Request the magic link for the E2E account.
    await page.goto('/magic-link');
    const form = page.locator('form').first();
    await form
      .locator('input#email, input[name="email"], input[type="email"]')
      .first()
      .fill(env.email);
    await form.getByRole('button', { name: /send|magic|link|continue|submit/i }).first().click();

    // 2. BUNYIP-150: read the magic link out of the mail sink and follow it.
    const magicUrl = 'MAGIC_URL_FROM_MAIL_SINK';
    await page.goto(magicUrl);

    // 3. Assert the session is live: a protected page renders instead of
    //    bouncing to /login.
    await page.goto('/settings');
    expect(page.url()).not.toMatch(/\/login(\/|$)/);
  });
});
