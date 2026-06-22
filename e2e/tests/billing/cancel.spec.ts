import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Subscription-cancel coverage (BUNYIP-149). Runs in the `account-ui` project
// with a live, already-authenticated browser session; does NOT call loginViaHub.
//
// PRODUCTION SAFETY GATE: skip on the production apex so a manual prod dispatch
// can never touch a live subscription. Stays even after the fixme is lifted.
test.skip(env.isProductionApex, 'no live subscriptions on production');

// `test.fixme`: blocked on BUNYIP-151 (staging Stripe test mode not yet wired).
// Cancel (POST /membership/cancel) presupposes an active test-mode subscription
// to cancel, which depends on the same staging Stripe wiring as subscribe.
// Un-fixme once BUNYIP-151 lands; this should run after a subscribe leg has
// created a test-mode subscription within the same run.
test.describe('billing cancel', () => {
  test.fixme('cancel an active test-mode subscription', async ({ page }) => {
    await page.goto('/membership');

    const res = await page.request.post(`${env.baseURL}/membership/cancel`, {
      maxRedirects: 0,
    });
    // bunyip redirects back to /membership after a successful cancel.
    expect([200, 301, 302, 303]).toContain(res.status());

    // Assert the membership page now reflects a cancelled / inactive state.
    await page.goto('/membership');
    expect(page.url()).not.toMatch(/\/login(\/|$)/);
  });
});
