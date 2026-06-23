import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';
import { tagged } from '../../lib/factories';

// Profile-edit coverage (BUNYIP-149). Runs in the `account-ui` project: the
// browser context is ALREADY authenticated (storageState saved by `setup`), so
// `page.request` carries the live session cookies without a fresh login.
//
// Request-context, NOT a browser render. `/settings` cannot be rendered on the
// CI runner: its software rasterizer (swiftshader, forced by `--disable-gpu` on
// a GPU-less container) crashes the chromium renderer mid-paint on that page -
// `goto` commits, `networkidle` fires, but `DOMContentLoaded` never does and the
// context dies (BUNYIP-176). The page renders fine for real GPU browsers, so the
// fault is the CI environment, not the product. This spec therefore exercises
// the real `POST /settings/profile` endpoint and verifies persistence by
// re-fetching the `/settings` HTML, both over `page.request` (no render). No CSRF
// token is needed: bunyip-web's settings forms are cookie + SameSite
// authenticated with no CSRF field (verified in bunyip-web/src/handlers).
//
// Non-destructive: profile is the only mutable field group that does not
// invalidate the session or change credentials. Each run writes run-unique
// first/last names (via `tagged`, well under the 64-char column cap) plus a
// fixed phone; the next run overwrites them, so there is nothing to sweep.
test.describe('account profile', () => {
  test('update profile fields and confirm they persist', async ({ page }) => {
    const firstName = tagged('First');
    const lastName = tagged('Last');
    const phone = '+15555550123';

    // Submit the real server-rendered profile form endpoint. page.request
    // follows the post-submit redirect back to /settings by default.
    const post = await page.request.post(env.baseURL + '/settings/profile', {
      form: { first_name: firstName, last_name: lastName, phone },
    });
    expect(post.ok(), `POST /settings/profile -> ${post.status()}`).toBeTruthy();

    // Re-fetch the settings page (HTML only, no render) so the assertion proves
    // the values round-tripped through the DB, not just the immediate response.
    // The form pre-fills each input's `value=`, so the unique names appear
    // verbatim in the markup when persisted.
    const res = await page.request.get(env.baseURL + '/settings');
    expect(res.ok(), `GET /settings -> ${res.status()}`).toBeTruthy();
    const html = await res.text();
    expect(html, 'first_name persisted').toContain(firstName);
    expect(html, 'last_name persisted').toContain(lastName);
    expect(html, 'phone persisted').toContain(phone);
  });
});
