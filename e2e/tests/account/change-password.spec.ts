import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';

// Change-password coverage (BUNYIP-149).
//
// `test.fixme`: suite-design limitation, no sub-task id. POST /settings/password
// mutates the SHARED E2E account credential (E2E_PASSWORD). The setup project,
// every account-ui spec, and teardown all authenticate as that one account, so
// rotating its password mid-run would invalidate the live session and break
// every subsequent spec (and leave the stored E2E_PASSWORD wrong for the next
// run). Testing this safely needs a DISPOSABLE account whose credential can be
// thrown away after the assertion. Un-fixme once the suite can provision a
// throwaway account per run.
//
// The body sketches the intended flow against the real form.
test.describe('change password', () => {
  test.fixme('change the account password (needs a disposable account)', async ({ page }) => {
    await page.goto('/settings');
    const form = page.locator('form[action*="/settings/password"]').first();
    await form
      .locator('input#current_password, input[name="current_password"]')
      .first()
      .fill(env.password);
    const newPassword = 'E2e-Rotated-Passw0rd!'; // policy-compliant.
    await form.locator('input#new_password, input[name="new_password"]').first().fill(newPassword);
    await form
      .locator('input#confirm, input[name="confirm"], input[name="password_confirm"]')
      .first()
      .fill(newPassword);
    await form.getByRole('button', { name: /change|update|save|submit/i }).first().click();

    // Assert the new password authenticates and (for a disposable account) roll
    // it back or discard the account.
    expect(env.email).toBeTruthy();
  });
});
