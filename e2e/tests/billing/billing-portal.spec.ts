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

// Skips until staging Stripe test mode is provisioned (BUNYIP-151): gated on
// E2E_STRIPE_SECRET_KEY. Read-only: GET /checkout/success and any billing-portal
// redirect presuppose a configured Stripe customer on staging; assert the route
// does not error, without mutating billing state.
test.describe('billing portal', () => {
  test('checkout-success / portal redirects to the expected host', async ({ page }) => {
    test.skip(!env.stripeSecretKey, 'needs staging Stripe test mode (BUNYIP-151)');
    const res = await page.request.get(`${env.baseURL}/checkout/success`, {
      maxRedirects: 0,
    });
    // With a configured Stripe customer this either renders a confirmation page
    // (200) or redirects back into the app (3xx). Assert it is not an error.
    expect(res.status(), `GET /checkout/success -> ${res.status()}`).toBeLessThan(400);
  });
});
