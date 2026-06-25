import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Subscription-checkout coverage (BUNYIP-149). Runs in the `account-ui` project
// with a live, already-authenticated browser session; does NOT call loginViaHub.
//
// PRODUCTION SAFETY GATE: skip on the production apex so a manual prod dispatch
// can never start a live subscription. This guard stays even after the fixme is
// lifted - it is the hard backstop against a real charge.
test.skip(env.isProductionApex, 'no live subscriptions on production');

// Skips until staging Stripe test mode is provisioned (BUNYIP-151): gated on
// E2E_STRIPE_SECRET_KEY, which the operator sets (as E2E_STAGING_STRIPE_SECRET_KEY)
// alongside the staging Stripe test-mode keys/price. POST /membership/subscribe
// 302s to checkout.stripe.com; asserting the redirect target needs a configured
// Stripe test-mode price on staging.
test.describe('billing subscribe', () => {
  test('subscribe redirects to the Stripe checkout host', async ({ page }) => {
    test.skip(!env.stripeSecretKey, 'needs staging Stripe test mode (BUNYIP-151)');
    await page.goto('/membership');

    // bunyip's Subscribe control POSTs /membership/subscribe and 302s to
    // checkout.stripe.com. Capture the redirect WITHOUT following it.
    const res = await page.request.post(`${env.baseURL}/membership/subscribe`, {
      maxRedirects: 0,
    });
    expect([301, 302, 303, 307, 308]).toContain(res.status());
    const location = res.headers()['location'] ?? '';
    expect(new URL(location).hostname, 'should redirect to Stripe checkout').toBe(
      'checkout.stripe.com',
    );
  });
});
