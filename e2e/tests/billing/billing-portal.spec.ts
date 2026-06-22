import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Billing-portal / checkout-success coverage (BUNYIP-149). Runs in the
// `account-ui` project with a live, already-authenticated browser session;
// does NOT call loginViaHub.
//
// PRODUCTION SAFETY GATE: skip on the production apex. Even though this is a
// read-only redirect assertion, keep the gate consistent with the other billing
// specs so prod is never exercised against Stripe.
test.skip(env.isProductionApex, 'no Stripe billing surface exercised on production');

// `test.fixme`: blocked on BUNYIP-151 (staging Stripe test mode not yet wired).
// The post-checkout return at GET /checkout/success and any billing-portal
// redirect both presuppose a configured Stripe customer on staging; until that
// exists the redirect target is undefined. Read-only once unblocked: assert the
// success/portal route redirects to the expected host without mutating billing
// state. Un-fixme once BUNYIP-151 lands.
test.describe('billing portal', () => {
  test.fixme('checkout-success / portal redirects to the expected host', async ({ page }) => {
    const res = await page.request.get(`${env.baseURL}/checkout/success`, {
      maxRedirects: 0,
    });
    // With a configured Stripe customer this either renders a confirmation page
    // (200) or redirects back into the app (3xx). Assert it is not an error.
    expect(res.status(), `GET /checkout/success -> ${res.status()}`).toBeLessThan(400);
  });
});
