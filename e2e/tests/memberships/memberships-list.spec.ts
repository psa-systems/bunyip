import { expect, test } from '@playwright/test';
import { env } from '../../lib/env';
import { routes } from '../../lib/api';

// Memberships coverage (BUNYIP-149). Runs in the `account-ui` project with a
// live, already-authenticated browser session; does NOT call loginViaHub.
//
// Asserts both the rendered surface (GET /membership renders instead of
// bouncing to /login) and the API (GET /v1/auth/memberships returns the active
// tenant). `page.request` carries the session cookies, so no bearer is needed.
test.describe('memberships', () => {
  test('membership page renders and reports the active tenant', async ({ page }) => {
    await page.goto('/membership');
    expect(page.url(), 'membership page should not bounce to /login').not.toMatch(/\/login(\/|$)/);

    const res = await page.request.get(env.apiBaseURL + routes.memberships);
    expect(res.status(), `GET ${routes.memberships} -> ${res.status()}`).toBe(200);

    const body = (await res.json()) as { active_tenant_id?: string };
    expect(body.active_tenant_id, 'memberships response missing active_tenant_id').toBeTruthy();
    // The E2E account is provisioned with E2E_TENANT_ID as its active tenant, so
    // the session must report acting in exactly that tenant.
    expect(body.active_tenant_id, 'active tenant should equal E2E_TENANT_ID').toBe(env.tenantId);
  });
});
