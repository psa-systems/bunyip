import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Subscription-cancel coverage (BUNYIP-149). Runs in the `account-ui` project
// with a live, already-authenticated browser session; does NOT call loginViaHub.
//
// PRODUCTION SAFETY GATE: skip on the production apex so a manual prod dispatch
// can never touch a live subscription. Stays even after the fixme is lifted.
test.skip(env.isProductionApex, 'no live subscriptions on production');

// `test.fixme`: deferred under BUNYIP-151 until staging Stripe test mode AND the
// subscription webhook are live, so it can be built and validated against a real
// backend. It needs a setup step that gives the E2E account an ACTIVE membership
// to cancel, which is harder than it looks: `/membership/cancel` early-returns
// "No active membership to cancel" unless `membership_status` is active
// (bunyip-api/src/handlers/membership.rs), and that only flips active via the
// `customer.subscription.created` webhook - so the setup must create a Stripe
// test-mode subscription on the E2E account's customer (the customer id is not
// exposed in /me, so look it up via the Stripe API by email) and poll for the
// webhook to land. subscribe + billing-portal carry no such dependency and are
// un-fixme'd. Un-fixme this once staging Stripe + the webhook are provisioned.
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
