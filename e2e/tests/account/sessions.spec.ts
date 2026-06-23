import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';
import { routes } from '../../lib/api';

// Active-sessions coverage (BUNYIP-149). Runs in the `account-ui` project with a
// live, already-authenticated browser context; `page.request` carries the
// session cookies, so the API probe is authenticated without a bearer.
//
// Request-context, NOT a browser render. The sessions surface is part of
// `/settings`, which cannot be rendered on the CI runner - its software
// rasterizer (swiftshader, `--disable-gpu`) crashes the chromium renderer
// mid-paint on that page (BUNYIP-176; the page renders fine for real GPU
// browsers). So this asserts the session list through its API instead of the
// rendered page.
//
// READ-ONLY by design. bunyip exposes a session-revoke action
// (POST /settings/sessions/{id}/revoke), but revoking the current session - or
// "revoke all" - would tear down the shared storageState session that EVERY
// other account-ui / api spec depends on. So this only asserts that at least
// one session (the current one) is listed; revocation is left untested here.
test.describe('account sessions', () => {
  test('the API lists at least the current session', async ({ page }) => {
    const res = await page.request.get(env.apiBaseURL + routes.userSessions);
    expect(res.status(), `GET ${routes.userSessions} -> ${res.status()}`).toBe(200);

    // bunyip-api wraps payloads in a success envelope and the handler nests the
    // list under `sessions`, so the shape is { data: { sessions: [...] } }
    // (bunyip-web/src/api/mod.rs parse() reads `.data`; handlers/user.rs
    // list_sessions emits `{ sessions }`). Unwrap both layers.
    const body = (await res.json()) as { data?: { sessions?: unknown[] } };
    const sessions = body.data?.sessions ?? [];
    expect(Array.isArray(sessions), 'data.sessions should be an array').toBe(true);
    expect(sessions.length, 'expected at least one active session').toBeGreaterThan(0);
  });
});
