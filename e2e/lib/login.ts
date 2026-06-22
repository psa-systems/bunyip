import { createHash } from 'node:crypto';
import { authenticator } from 'otplib';
import { expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// BUNYIP-167 (temporary): fingerprint a value for safe logging (length + sha256
// prefix, never plaintext), matching lib/env.ts so the POSTed credential bytes
// can be compared to the resolved-config fingerprints.
function fp(value: string): string {
  return `len ${value.length}/${createHash('sha256').update(value).digest('hex').slice(0, 12)}`;
}

// BUNYIP-167 (temporary): log the actual `/login` POST the browser sends - which
// fields, the credential fingerprints, key headers, and the response status +
// redirect - so we can prove whether the right bytes leave the browser and how
// bunyip responds. Remove with the rest of the BUNYIP-167 diagnostics.
function attachLoginWireDiagnostics(page: Page): void {
  page.on('request', (req) => {
    try {
      if (req.method() !== 'POST' || new URL(req.url()).pathname !== '/login') return;
      const params = new URLSearchParams(req.postData() ?? '');
      const fields = [...params.entries()]
        .map(([k, v]) => (k === 'email' || k === 'password' ? `${k}=${fp(v)}` : `${k}=${v}`))
        .join(' ');
      const h = req.headers();
      console.log(
        `[login POST req] ${req.url()} | ${fields} | ` +
          `origin=${h['origin'] ?? '(none)'} content-type=${h['content-type'] ?? '(none)'} ` +
          `cookie=${h['cookie'] ? 'present' : 'none'}`,
      );
    } catch {
      /* diagnostic only */
    }
  });
  page.on('response', (resp) => {
    try {
      const req = resp.request();
      if (req.method() !== 'POST' || new URL(resp.url()).pathname !== '/login') return;
      console.log(
        `[login POST res] -> ${resp.status()} location=${resp.headers()['location'] ?? '(none)'}`,
      );
    } catch {
      /* diagnostic only */
    }
  });
}

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
  attachLoginWireDiagnostics(page); // BUNYIP-167 temporary
  await page.goto('/login');

  // Scope to the login form specifically (action="/login"), not whatever form
  // happens to be first in the DOM.
  const form = page.locator('form[action="/login"]').first();

  const email = form
    .locator('input#email, input[name="email"], input[type="email"]')
    .first();
  const password = form
    .locator(
      'input#password, input[name="password"], input[type="password"], input[autocomplete="current-password"]',
    )
    .first();

  await email.waitFor({ state: 'visible' });

  // The wire diagnostic (BUNYIP-167) showed the form posting EMPTY email +
  // password despite fill() returning: bunyip-web re-renders the input nodes
  // shortly after load (htmx is loaded globally), discarding the JS-set `.value`
  // while attribute-valued hidden fields (redirect) survive. So fill, VERIFY the
  // value stuck, and retry until it does (which also waits out the re-render);
  // then re-fill once more immediately before submit as a last-moment guard.
  await fillVerified(email, env.email);
  await fillVerified(password, env.password);
  if ((await email.inputValue()) !== env.email) await email.fill(env.email);
  if ((await password.inputValue()) !== env.password) await password.fill(env.password);

  await form.locator('button[type="submit"]').first().click();

  // bunyip 302s to /login/2fa for an MFA-enabled account; anything else
  // (success or error) flows through to the URL-out-of-/login poll below.
  await page
    .waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 15_000 })
    .catch(() => {});
  if (/^\/login\/(2fa|mfa)/.test(new URL(page.url()).pathname)) {
    await fillTotpStep(page);
  }

  // bunyip navigates fully out of the /login path family on success (a 302 to
  // /dashboard or the OIDC return URL). A rejected login - bad credentials, or
  // the 5/min-per-email rate limit - re-renders /login with an `error_box`
  // instead. Race "left /login" against that error box appearing so a rejection
  // fails in ~1s WITH bunyip's own message, rather than blocking the full 30s
  // and reporting only "never left /login".
  const stillOnLogin = (): boolean => /^\/login(\/|$)/.test(new URL(page.url()).pathname);
  const leftLogin = page
    .waitForURL(() => !stillOnLogin(), { timeout: 30_000 })
    .then(() => 'ok' as const)
    .catch(() => 'timeout' as const);
  // `.text-destructive` is the only destructive-styled element on the login
  // page; bunyip's error_box (views/ui.rs) renders solely on a failed login, so
  // it is a false-positive-free signal.
  const errorShown = page
    .locator('.text-destructive')
    .first()
    .waitFor({ state: 'visible', timeout: 30_000 })
    .then(() => 'error' as const)
    .catch(() => 'timeout' as const);

  const outcome = await Promise.race([leftLogin, errorShown]);
  if (outcome === 'ok' && !stillOnLogin()) return;

  // An error box appeared, or the poll timed out still on /login. Surface the
  // rendered reason (e.g. "Too many attempts", "Invalid email or password").
  const reason = await readLoginError(page);
  throw new Error(
    `hub login did not leave /login (current: ${new URL(page.url()).pathname})` +
      (reason ? `: "${reason}"` : ' - no error message rendered (timed out waiting for navigation)'),
  );
}

// Fill a field and confirm the value persisted, retrying a few times. Guards
// against bunyip-web re-rendering the input after a too-early fill (BUNYIP-168):
// the retry loop both re-applies the value and waits out the re-render, so it
// returns only once the field actually holds `value`.
async function fillVerified(loc: Locator, value: string): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await loc.fill(value);
    if ((await loc.inputValue()) === value) return;
    await loc.page().waitForTimeout(250);
  }
  throw new Error(
    `login field value did not stick after fill (holds ${(await loc.inputValue()).length} chars, ` +
      `expected ${value.length}); the input is likely re-rendered after fill`,
  );
}

// Scrape bunyip's login error_box (`.text-destructive`, views/ui.rs) into a
// single-line string, or null when no error is rendered. The box holds an icon
// (svg, no text) plus the message, so innerText is the message.
async function readLoginError(page: Page): Promise<string | null> {
  try {
    const box = page.locator('.text-destructive').first();
    if ((await box.count()) === 0) return null;
    const text = (await box.innerText()).trim().replace(/\s+/g, ' ');
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
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
