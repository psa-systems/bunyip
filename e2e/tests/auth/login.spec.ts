import { expect, test } from '@playwright/test';
import { expectAtLoginScreen, loginViaHub, logoutViaHub } from '../../lib/login';
import { attachPageDiagnostics } from '../../lib/page-diagnostics';

// Browser-driven auth coverage (BUNYIP-149). bunyip-web is server-rendered
// (Maud + htmx), so the session lives in cookies the browser carries; this
// spec drives the real /login form (TOTP-aware via lib/login.ts), confirms it
// lands on a protected page, then logs out and confirms protected pages bounce
// back to /login.
//
// Login and logout are folded into a SINGLE test on purpose. Each
// `loginViaHub` call counts toward bunyip's per-email login rate limit
// (5/min). The `setup` project already spends one login per run (two on a CI
// retry). Splitting login and logout into separate tests would add another
// 2-4 logins (extra bodies + their retries) and cross the cap, so the auth-ui
// project keeps to ONE login attempt per run. Any further login-bearing
// coverage in tests/auth/ is `test.fixme` for the same reason.
//
// This project runs ANONYMOUS (no stored storageState), so the logout
// assertion here cannot invalidate the shared `account-ui` session: this is a
// fresh browser context with its own cookies.
//
// Load-bearing defense: `attachPageDiagnostics` captures the URL trail +
// request log and folds it into the thrown error on failure, so the next
// iteration is precise instead of speculative. Do not drop it.
test.describe('auth login / session', () => {
  test('login + logout round-trip', async ({ page }) => {
    // loginViaHub waits out bunyip's 5/min login rate-limit window and resubmits
    // when a busy run trips it (BUNYIP-267), which can add tens of seconds. Give
    // this spec 3x the default timeout so the backoff has room to complete
    // instead of tripping the 60s per-test budget.
    test.slow();
    const diag = attachPageDiagnostics(page);

    try {
      await loginViaHub(page);

      // Prove we are actually past the gate: visit a protected page and assert
      // it renders (URL not on /login, a settings form/heading is visible)
      // rather than bouncing us back to the login screen.
      await page.goto('/settings');
      expect(page.url(), 'post-login /settings URL').not.toMatch(/\/login(\/|$)/);
      const settingsForm = page.locator('form').first();
      await expect(settingsForm, 'settings page should render a form').toBeVisible({
        timeout: 15_000,
      });
    } catch (err) {
      // `cause` preserves the underlying assertion so Playwright's reporter can
      // still surface its matcher details below the diagnostic dump.
      throw new Error(diag.snapshot('login diagnostic'), { cause: err });
    }

    try {
      await logoutViaHub(page);
      // After logout, a protected page must bounce back to /login.
      await page.goto('/settings');
      await expectAtLoginScreen(page);
    } catch (err) {
      throw new Error(diag.snapshot('logout diagnostic'), { cause: err });
    }
  });
});
