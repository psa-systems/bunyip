import { authenticator } from 'otplib';
import { expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// Disable the bunyip-web live-reload subscriber for the test page. bunyip-web
// mounts it on every page (bunyip-web/src/views/layout.rs SSE_SUBSCRIBER): an
// EventSource to `/v1/events` that calls `window.location.reload()` on
// claims_changed / profile_changed / applications_changed / resync. On a form
// page that reload fires shortly after load and wipes the inputs, so the filled
// values never reach submit and the POST goes out empty (BUNYIP-168; the
// server-side fix is BUNYIP-169). The subscriber bails when `window.EventSource`
// is absent (`if(!window.EventSource)return`), so remove that global before any
// page script runs via addInitScript. NB: `page.route('**/v1/events')` does NOT
// reliably intercept an EventSource, so routing is not enough. Call this on any
// browser page the suite drives (login flows; the authenticated account-ui specs
// need it too) BEFORE the first navigation.
export async function blockLiveReload(page: Page): Promise<void> {
  await page.addInitScript('try { window.EventSource = undefined; } catch (e) {}');
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
  await blockLiveReload(page); // BUNYIP-168: stop the SSE reload wiping the form

  // bunyip rate-limits login at 5/min per email (RateLimitConfig::LOGIN). The
  // `setup` project's login plus a busy run can fill that window, and bunyip
  // then re-renders /login with "Too many requests. Please wait N seconds and
  // try again." instead of accepting the credentials. That rejection is
  // transient - the window resets on its own - so when we see it, wait out the
  // interval bunyip names and resubmit rather than failing the spec on a
  // harness-timing blip (BUNYIP-267). A Playwright-level retry cannot do this:
  // re-running the test fires another login POST immediately and only deepens
  // the 5/min hole, which is why the auth-ui project keeps retries: 0.
  const maxAttempts = 4;
  for (let attempt = 1; ; attempt += 1) {
    await page.goto('/login');
    const outcome = await submitLoginOnce(page);
    if (outcome === 'ok') return;

    const backoffMs = rateLimitBackoffMs(outcome);
    if (backoffMs !== null && attempt < maxAttempts) {
      await page.waitForTimeout(backoffMs);
      continue;
    }

    // A non-rate-limit rejection (e.g. bad credentials), or we have exhausted
    // the backoff attempts. Surface bunyip's rendered reason.
    throw new Error(
      `hub login did not leave /login (current: ${new URL(page.url()).pathname})` +
        (outcome
          ? `: "${outcome}"`
          : ' - no error message rendered (timed out waiting for navigation)'),
    );
  }
}

// Submit the login form once (filling credentials and any TOTP step) and
// resolve the outcome: the literal 'ok' once bunyip lets us out of the /login
// path family, or the rendered error_box text on rejection (e.g. the rate-limit
// message or "Invalid email or password"), or null when neither happens within
// the navigation budget. The caller decides whether the reason warrants a
// backoff-and-retry. Assumes the page is freshly on /login.
async function submitLoginOnce(page: Page): Promise<'ok' | string | null> {
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

  // Set the values via the DOM, not Playwright `fill()`. On the CI runner's
  // headless chromium, `fill()` is a no-op on these inputs (the value never
  // changes), while a direct `el.value = ...` assignment works and persists
  // (proven by the BUNYIP-168 probe). bunyip-web submits the native form, which
  // serializes each input's `.value`, so a DOM-set value is submitted correctly.
  await setInputValue(email, env.email);
  await setInputValue(password, env.password);

  await form.locator('button[type="submit"]').first().click();

  // bunyip 302s to /login/2fa for an MFA-enabled account. Race that redirect
  // against the error_box so a rate-limit rejection (which never reaches 2FA)
  // is seen in ~1s instead of after the 2FA wait's full 15s timeout - keeping
  // the per-attempt cost low enough for the backoff loop above to retry within
  // the test budget (BUNYIP-267).
  const reach2fa = page
    .waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 15_000 })
    .then(() => '2fa' as const)
    .catch(() => 'timeout' as const);
  const earlyError = page
    .locator('.text-destructive')
    .first()
    .waitFor({ state: 'visible', timeout: 15_000 })
    .then(() => 'error' as const)
    .catch(() => 'timeout' as const);
  const firstStep = await Promise.race([reach2fa, earlyError]);

  const onTwoFactor = (): boolean => /^\/login\/(2fa|mfa)/.test(new URL(page.url()).pathname);
  if (firstStep === 'error' && !onTwoFactor()) {
    // The credential POST was rejected before any 2FA step (bad creds or the
    // rate limit). Return the rendered reason for the caller to classify.
    return (await readLoginError(page)) ?? null;
  }
  if (onTwoFactor()) {
    await fillTotpStep(page);
  }

  // bunyip navigates fully out of the /login path family on success (a 302 to
  // /dashboard or the OIDC return URL). A rejection (e.g. a bad TOTP code)
  // re-renders /login with an `error_box` instead. Race "left /login" against
  // that error box appearing so a rejection fails fast WITH bunyip's own
  // message, rather than blocking the full 30s and reporting only "never left
  // /login".
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
  if (outcome === 'ok' && !stillOnLogin()) return 'ok';

  // An error box appeared, or the poll timed out still on /login. Surface the
  // rendered reason (e.g. "Too many attempts", "Invalid email or password").
  return (await readLoginError(page)) ?? null;
}

// Classify an error_box reason as a rate-limit rejection and return the backoff
// to wait before resubmitting, in ms, or null when the reason is NOT the rate
// limit (so the caller fails fast on a real credential error). bunyip renders
// "Too many requests. Please wait N seconds and try again."; parse N and add a
// 1s cushion for the window boundary, capped at the 60s login window
// (RateLimitConfig::LOGIN). Defaults to 5s when no count is rendered.
function rateLimitBackoffMs(reason: string | null): number | null {
  if (!reason || !/too many|rate.?limit/i.test(reason)) return null;
  const match = reason.match(/(\d+)\s*second/i);
  const seconds = match ? Number(match[1]) : 5;
  return Math.min(seconds, 60) * 1_000 + 1_000;
}

// Set an input's value via the DOM and confirm it persisted, retrying a few
// times. Playwright `fill()` is a no-op on these inputs in the CI runner's
// headless chromium (BUNYIP-168), so set `.value` directly and dispatch
// input/change; bunyip-web submits the native form, which serializes `.value`.
// Throws loudly if the value cannot be made to stick (so we never submit blank
// or partial credentials silently).
export async function setInputValue(loc: Locator, value: string): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await loc.evaluate((el, v) => {
      const input = el as HTMLInputElement;
      input.value = v as string;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }, value);
    if ((await loc.inputValue()) === value) return;
    await loc.page().waitForTimeout(200);
  }
  throw new Error(
    `login field value did not stick after a DOM set (holds ${(await loc.inputValue()).length} chars, ` +
      `expected ${value.length})`,
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
  // DOM-set, not fill(): same CI no-op applies to this input (BUNYIP-168).
  // setInputValue dispatches a bubbling `input` event, which the BUNYIP-331
  // data-otp-autosubmit snippet reacts to by submitting the form once the six
  // digits are present. Wait for that navigation off /login/2fa; only click the
  // submit button as a fallback if the auto-submit did not fire, so we never
  // double-POST (a second submit would trip the 2fa_verify rate limit and hit
  // TOTP replay rejection).
  await setInputValue(codeInput, code);
  const autoSubmitted = await page
    .waitForURL((url) => !/\/login\/(2fa|mfa)(\/|$|\?)/.test(url.pathname), { timeout: 15_000 })
    .then(() => true)
    .catch(() => false);
  if (!autoSubmitted) {
    await form
      .getByRole('button', { name: /verify|continue|submit|sign ?in|log ?in/i })
      .first()
      .click();
  }
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
