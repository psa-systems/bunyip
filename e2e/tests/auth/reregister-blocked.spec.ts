import { expect, test } from '@playwright/test';
import { routes } from '../../lib/api';
import { env } from '../../lib/env';
import { registerDisposable, softDeleteMe, deleteMe, DISPOSABLE_PASSWORD } from '../../lib/accounts';

// BUNYIP-330: a soft-deleted email is permanently reserved. Registering under
// a soft-deleted account's address must be refused (HTTP 409, same "Email
// already registered" copy as an in-use active account, so an outside caller
// cannot enumerate deleted-vs-active state). Same guarantee holds when the
// underlying deletion happened via the account_deleted webhook (PMS-591 on
// mokosh, EventBus locally in bunyip): the row is soft-deleted, the email
// stays reserved.
//
// This spec drives the raw JSON API, so it does not need a mail sink and runs
// on the standard e2e job (unlike `signup.spec.ts` which is fixmed on
// BUNYIP-150). It runs on isolated request contexts and pins storageState:
// undefined so the shared login cannot leak into the flow.
//
// test.fixme on the initial PR: the CI job runs against `E2E_STAGING_BASE_URL`,
// which is the currently-deployed bunyip build - the one that still lets a
// soft-deleted email be re-registered. The very first PR CI proved this: the
// re-register returned 201 with a fresh user row (see PR #320 CI, task
// `expected 409 on re-register, got 201`). Once this PR merges and staging
// redeploys, un-fixme in a follow-up PR so the coverage pins the reservation
// on every subsequent PR. Same fixme pattern as `signup.spec.ts` (fixme'd on
// BUNYIP-150 mail sink).
test.use({ storageState: undefined });

test.describe('re-register blocked (BUNYIP-330)', () => {
  test.fixme('a soft-deleted email cannot be re-registered', async ({ playwright }) => {
    const owner = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    const attacker = await playwright.request.newContext({ baseURL: env.apiBaseURL });
    let account: Awaited<ReturnType<typeof registerDisposable>> | undefined;

    try {
      account = await registerDisposable(owner);

      // Soft-delete the freshly-registered account. `softDeleteMe` omits the
      // `?purge=1` flag so the row stays around with `deleted_at` stamped -
      // exactly the state the account_deleted webhook produces for a normal
      // user-initiated delete, and the state this ticket is closing the
      // re-registration gap against.
      await softDeleteMe(owner, account.password);

      // Attempt to register a fresh account with the exact same email on a
      // clean context (no cookies, no lingering state from `owner`).
      const res = await attacker.post(routes.authRegister, {
        data: { email: account.email, password: DISPOSABLE_PASSWORD },
      });

      expect(res.status(), `expected 409 on re-register, got ${res.status()}: ${await res.text()}`).toBe(409);

      // Case-only variants share the same lowered-form reservation, so the
      // attacker cannot bypass by tweaking capitalisation.
      const upperEmail = account.email.toUpperCase();
      const resUpper = await attacker.post(routes.authRegister, {
        data: { email: upperEmail, password: DISPOSABLE_PASSWORD },
      });
      expect(
        resUpper.status(),
        `expected 409 on case-only re-register (${upperEmail}), got ${resUpper.status()}: ${await resUpper.text()}`,
      ).toBe(409);
    } finally {
      // Best-effort hard-purge so the reserved email does not clog staging on
      // repeated runs. This IS the escape hatch the reservation is supposed
      // to gate against, so it only runs in the non-production e2e purge
      // window (BUNYIP-246 flag). If purge is refused, the reaper eventually
      // sweeps by run tag.
      if (account) {
        await deleteMe(owner, account.password);
      }
      await owner.dispose();
      await attacker.dispose();
    }
  });
});
