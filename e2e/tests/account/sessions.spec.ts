import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';
import { routes } from '../../lib/api';
import { blockLiveReload } from '../../lib/login';

// Active-sessions coverage (BUNYIP-149). Runs in the `account-ui` project with
// a live, already-authenticated browser session; does NOT call loginViaHub.
//
// READ-ONLY by design. bunyip exposes a session-revoke action
// (POST /settings/sessions/{id}/revoke), but revoking the current session - or
// "revoke all" - would tear down the shared storageState session that EVERY
// other account-ui/api spec depends on. So this spec only asserts that at least
// one session (the current one) is listed; revocation is left untested here.
//
// `page.request` carries the live session cookies, so the API probe is
// authenticated without a bearer.
test.describe('account sessions', () => {
  // bunyip-web reloads the page on SSE events (BUNYIP-168); block it.
  test.beforeEach(async ({ page }) => {
    // BUNYIP-148 diag: /settings closes the page before goto in CI; surface why.
    page.on('crash', () => console.log('[/settings] PAGE CRASHED'));
    page.on('pageerror', (e) => console.log('[/settings] pageerror:', e.message));
    page.on('console', (m) => {
      if (m.type() === 'error') console.log('[/settings] console.error:', m.text());
    });
    await blockLiveReload(page);
  });

  test('the settings page lists at least the current session', async ({ page }) => {
    await page.goto('/settings');
    expect(page.url(), 'settings page should not bounce to /login').not.toMatch(/\/login(\/|$)/);

    // The sessions surface is rendered on /settings. Assert at least one
    // session entry is present. The selector is permissive (data attribute or a
    // revoke control) so a markup tweak does not immediately break the suite.
    const sessionRows = page.locator(
      '[data-session-id], form[action*="/settings/sessions/"], [data-testid="session-row"]',
    );
    await expect(sessionRows.first(), 'expected at least one session row').toBeVisible({
      timeout: 15_000,
    });

    // Cross-check the API: GET /v1/users/me/sessions must return a non-empty
    // array. Use page.request so the live session cookies authenticate it.
    const res = await page.request.get(env.apiBaseURL + routes.userSessions);
    expect(res.status(), `GET ${routes.userSessions} -> ${res.status()}`).toBe(200);
    const body = (await res.json()) as unknown;
    const sessions = Array.isArray(body)
      ? body
      : ((body as { sessions?: unknown[] }).sessions ?? []);
    expect(Array.isArray(sessions), 'sessions response should be an array').toBe(true);
    expect(sessions.length, 'expected at least one active session').toBeGreaterThan(0);
  });
});
