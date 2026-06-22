import { authenticator } from 'otplib';
import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// Drive the bunyip-web login form to establish a real session.
//
// bunyip-web is server-rendered (Maud + htmx): the login page at `/login`
// POSTs `email` + `password` back to `/login` as a full-page navigation
// (bunyip-web/src/handlers/auth_pages.rs). Selectors are scoped to the
// `<form>` and target the real input ids, with permissive fallbacks so a
// markup tweak does not immediately break the suite.
//
// The E2E account has 2FA enabled (matching the production hardening posture).
// When 2FA is required, bunyip sets a `bunyip_2fa` cookie and redirects to
// `/login/2fa?redirect=...`; the helper enters a TOTP code derived from
// `E2E_TOTP_SECRET`. The poll uses `/^\/login(\/|$)/` so multi-step flows count
// as IN /login and the helper only returns once bunyip has actually let us
// through to a post-login page.
export async function loginViaHub(page: Page): Promise<void> {
  await page.goto('/login');

  const form = page.locator('form').first();

  const email = form
    .locator('input#email, input[name="email"], input[type="email"]')
    .first();
  const password = form
    .locator(
      'input#password, input[name="password"], input[type="password"], input[autocomplete="current-password"]',
    )
    .first();

  await email.waitFor({ state: 'visible' });
  await email.fill(env.email);
  await password.fill(env.password);

  await form
    .getByRole('button', { name: /sign ?in|log ?in|continue|submit/i })
    .first()
    .click();

  // bunyip 302s to /login/2fa for an MFA-enabled account; anything else
  // (success or error) flows through to the URL-out-of-/login poll below.
  await page
    .waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 15_000 })
    .catch(() => {});
  if (/^\/login\/(2fa|mfa)/.test(new URL(page.url()).pathname)) {
    await fillTotpStep(page);
  }

  // bunyip navigates fully out of the /login path family on success. Match
  // anything starting with /login so multi-step flows (`/login/2fa`, etc) are
  // still treated as IN the login flow.
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 30_000,
      message:
        'hub login never navigated away from the /login flow ' +
        '(still on /login, /login/2fa, /login/mfa, or similar)',
    })
    .not.toMatch(/^\/login(\/|$)/);
}

// Compute the current TOTP code from E2E_TOTP_SECRET (RFC 6238, 30s window,
// 6 digits, SHA-1 - the otplib defaults match bunyip's TOTP module). Fill it
// into the `/login/2fa` form (field `code`) and submit.
async function fillTotpStep(page: Page): Promise<void> {
  const code = authenticator.generate(env.totpSecret);
  const form = page.locator('form').first();
  const codeInput = form
    .locator(
      'input#code, input[name="code"], input[autocomplete="one-time-code"], input[inputmode="numeric"]',
    )
    .first();
  await codeInput.waitFor({ state: 'visible', timeout: 10_000 });
  await codeInput.fill(code);
  await form
    .getByRole('button', { name: /verify|continue|submit|sign ?in|log ?in/i })
    .first()
    .click();
}

// Browser-driven logout: GET /logout clears the access_token / refresh_token /
// bunyip_2fa cookies and redirects. Used by the auth-ui project.
export async function logoutViaHub(page: Page): Promise<void> {
  await page.goto('/logout');
}

// An authenticated session can read its own memberships (200); an anonymous
// one is rejected (401/403). Cheapest universal session proof on bunyip.
export async function expectAuthenticated(request: APIRequestContext): Promise<void> {
  const res = await request.get(routes.memberships);
  expect(res.status(), `GET ${routes.memberships} should be 200 when authenticated`).toBe(200);
}

export async function expectAnonymous(request: APIRequestContext): Promise<void> {
  const res = await request.get(routes.memberships);
  expect(
    [401, 403],
    `GET ${routes.memberships} should be 401/403 when logged out, got ${res.status()}`,
  ).toContain(res.status());
}

// Browser-driven "logged out" proof: bunyip bounces protected pages back to
// /login when the session is gone. Match any /login* path.
export async function expectAtLoginScreen(page: Page): Promise<void> {
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 30_000,
      message: 'expected hub to navigate to /login after logout',
    })
    .toMatch(/^\/login(\/|$)/);
}
