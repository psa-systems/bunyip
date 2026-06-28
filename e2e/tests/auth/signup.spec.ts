import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';
import { tagged } from '../../lib/factories';

// Self-service registration coverage (BUNYIP-149).
//
// `test.fixme`: blocked on a mail sink (BUNYIP-150). bunyip's /register flow
// creates the account in an unconfirmed state and emails a confirmation link;
// the account cannot log in until the link is followed. Without a programmatic
// mailbox to read that link, the flow cannot complete end-to-end, and creating
// a real unconfirmed account on staging on every run would be untracked
// residue. Un-fixme once the suite has a mail sink to read the confirmation
// token (BUNYIP-150).
//
// The body below sketches the intended flow against the real server-rendered
// /register form (email, password, confirm; password policy: >=12 chars
// including upper, lower, digit, and a special character).
test.describe('registration', () => {
  test.fixme('register a new account and confirm via emailed link', async ({ page }) => {
    // 1. Open the registration form.
    await page.goto('/register');
    const form = page.locator('form').first();

    // 2. Fill a run-unique throwaway email and a policy-compliant password.
    //    `tagged` embeds the run id so teardown's name sweep could later reap
    //    the account if a delete route exists.
    const email = `${tagged('signup')}@example.invalid`;
    const password = 'E2e-Test-Passw0rd!'; // >=12, upper+lower+digit+special.

    await form.locator('input#email, input[name="email"]').first().fill(email);
    await form.locator('input#password, input[name="password"]').first().fill(password);
    await form
      .locator('input#confirm, input[name="confirm"], input[name="password_confirm"]')
      .first()
      .fill(password);
    await form.getByRole('button', { name: /register|sign ?up|create/i }).first().click();

    // 3. BUNYIP-150: read the confirmation link from the mail sink, GET it, then
    //    log in with the new credentials and assert the session is live. Until
    //    the sink exists this leg cannot run.
    expect(env.baseURL).toBeTruthy();
  });
});
