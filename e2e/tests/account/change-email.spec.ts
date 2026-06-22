import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Change-email coverage (BUNYIP-149).
//
// `test.fixme`: blocked on a mail sink (BUNYIP-150). POST /settings/email starts
// an email-change that bunyip confirms by emailing a verification link to the
// NEW address; the change does not take effect until that link is followed.
// Without a programmatic mailbox the confirmation cannot be read, so the flow
// cannot complete. Changing the shared E2E account's email would also break the
// login credential for every other spec, so even with a sink this needs a
// disposable account. Un-fixme once the mail sink lands (BUNYIP-150).
//
// The body sketches the intended flow against the real form.
test.describe('change email', () => {
  test.fixme('request an email change and confirm via emailed link', async ({ page }) => {
    await page.goto('/settings');
    const form = page.locator('form[action*="/settings/email"]').first();
    await form
      .locator('input#email, input[name="email"], input[name="new_email"]')
      .first()
      .fill('changed@example.invalid');
    await form.getByRole('button', { name: /change|update|save|submit/i }).first().click();

    // BUNYIP-150: read the verification link out of the mail sink, GET it, then
    // assert the account's email now reads the new value.
    expect(env.email).toBeTruthy();
  });
});
