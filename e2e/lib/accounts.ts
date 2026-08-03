// Disposable test accounts for the email-driven specs (BUNYIP-150).
//
// password-reset and change-email mutate an account's credentials/email, so
// they must NOT touch the shared E2E account (that would break the login every
// other spec depends on). bunyip registration requires no email confirmation
// (POST /v1/auth/register logs the user in immediately), so each such spec
// self-provisions a throwaway account, runs its flow, and self-deletes.
//
// The account is created on a Playwright request context whose cookie jar then
// holds the session, so the same context can later DELETE /v1/users/me without
// re-authenticating. Emails carry this run's tag so any residue from a crashed
// run is recognisable.

import { type APIRequestContext, type APIResponse } from '@playwright/test';
import { routes } from './api';
import { runSuffix } from './run';
import { subaddress } from './mail-sink';

// A throwaway, policy-compliant password (upper/lower/digit/symbol, long). The
// disposable accounts never have 2FA, so a constant is fine.
export const DISPOSABLE_PASSWORD = 'E2e-Disposable-Passw0rd!';

export interface DisposableAccount {
  email: string;
  password: string;
}

// A run-tagged, unique email that is a plus-subaddress of the sink mailbox
// (e.g. `e2e+e2e-...-1@a8n.run`), so Stalwart delivers its mail into the one
// mailbox the suite reads. The unique tag isolates this account's mail.
export function disposableEmail(): string {
  return subaddress(runSuffix());
}

// register-challenge sits under bunyip's per-IP unauthenticated rate-limit
// floor (RateLimitConfig::API_UNAUTH = 20 req/60s/IP; the route is NOT in
// rate_limit_floor::EXEMPT_PATHS), and every CI run shares one runner egress
// IP, so a burst of overlapping runs can 429 it (BUNYIP-449). Retry only on
// 429; any other status is returned unchanged for the caller to surface.
//
// The disposable specs run in the retries:0 `auth-ui` project under a 60s
// per-test timeout (playwright.config.ts), and cannot take a whole-test retry
// (that re-runs their login and deepens the 5/min login limit). So the in-test
// backoff must fit inside the 60s budget with margin: cap each wait at
// PER_WAIT_CAP_MS (10s) -> at most ~30s across the 3 retries. The floor's 429
// carries a truthful Retry-After (seconds until the window frees); honor it but
// clamp to the cap, and fall back to exponential backoff when it is absent. A
// full-window (up to 60s) throttle cannot be waited out in-test - the durable
// fix is exempting the route from the floor (BUNYIP-450).
const CHALLENGE_MAX_RETRIES = 3;
const PER_WAIT_CAP_MS = 10_000;

async function fetchRegisterChallenge(ctx: APIRequestContext): Promise<APIResponse> {
  for (let attempt = 0; ; attempt += 1) {
    const res = await ctx.get(routes.registerChallenge);
    if (res.status() !== 429) return res;

    const retryAfter = res.headers()['retry-after'];
    const body = (await res.text()).slice(0, 200);
    if (attempt >= CHALLENGE_MAX_RETRIES) {
      throw new Error(
        `register-challenge still 429 after ${attempt + 1} attempts ` +
          `(Retry-After: ${retryAfter ?? '(none)'}): ${body}`,
      );
    }
    const parsed = Number.parseInt(retryAfter ?? '', 10);
    const base = Number.isFinite(parsed) && parsed > 0 ? parsed * 1_000 : 2 ** attempt * 1_000;
    const waitMs = Math.min(base, PER_WAIT_CAP_MS);
    console.warn(
      `register-challenge 429 (attempt ${attempt + 1}/${CHALLENGE_MAX_RETRIES + 1}, ` +
        `Retry-After: ${retryAfter ?? '(none)'}); waiting ${waitMs}ms before retry. body=${body}`,
    );
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
}

// Register a fresh account on `ctx`. On success `ctx` holds the new account's
// session cookies (register logs the user in), so the caller can reuse it for
// authenticated calls and for the eventual self-delete.
export async function registerDisposable(ctx: APIRequestContext): Promise<DisposableAccount> {
  const account: DisposableAccount = { email: disposableEmail(), password: DISPOSABLE_PASSWORD };
  // BUNYIP-384: satisfy the BUNYIP-377 signup bot guard the same way the real
  // register form does, so the guard can stay enabled and validated on staging.
  // Fetch the timing-challenge token, leave the honeypot (contact_channel) empty,
  // and submit only after the 2s minimum fill time (SIGNUP_MIN_FILL_SECONDS) so
  // the request is not flagged as submitted-too-fast. When the guard is off
  // (dev / prod) the extra signup_token is simply ignored server-side.
  // fetchRegisterChallenge retries on a transient 429 from the per-IP rate
  // floor (BUNYIP-449); a non-429 non-ok status still surfaces below.
  const challenge = await fetchRegisterChallenge(ctx);
  if (!challenge.ok()) {
    throw new Error(`register-challenge failed: ${challenge.status()} ${await challenge.text()}`);
  }
  const signupToken = ((await challenge.json()) as { data?: { token?: string } }).data?.token;
  if (!signupToken) {
    throw new Error('register-challenge returned no token in the response envelope');
  }
  await new Promise((resolve) => setTimeout(resolve, 2_100));
  const res = await ctx.post(routes.authRegister, {
    data: { email: account.email, password: account.password, signup_token: signupToken },
  });
  if (!res.ok()) {
    throw new Error(`register disposable account failed: ${res.status()} ${await res.text()}`);
  }
  return account;
}

// Best-effort self-delete via DELETE /v1/users/me on an authenticated context.
// Never throws - cleanup must not turn a passing spec red. Call in a `finally`.
//
// `?purge=1` asks the API to HARD-delete the row instead of soft-deleting it,
// so disposable accounts do not pile up as soft-deleted rows on staging. The
// purge is honoured only server-side on a non-production deployment that sets
// BUNYIP_E2E_BOOTSTRAP_ALLOW=true; production ignores the flag and soft-deletes,
// and the email-driven specs skip there anyway (BUNYIP-246). The endpoint
// requires the same ownership proof as a normal delete, so the caller passes
// the account's current password (disposable accounts never enable 2FA, so the
// password alone suffices). The reaper sweeps anything this misses.
export async function deleteMe(ctx: APIRequestContext, password: string): Promise<void> {
  try {
    await ctx.delete(`${routes.userMe}?purge=1`, { data: { password } });
  } catch (err) {
    console.warn(`[accounts] self-delete failed (will be swept later): ${String(err)}`);
  }
}

// Best-effort self-delete WITHOUT `?purge=1`, so the row is soft-deleted (the
// production default). BUNYIP-330 uses this to prove the email reservation
// holds against a subsequent re-registration attempt. Callers should still
// pair this with a `deleteMe` in `finally` (with the reaper-friendly purge)
// so a run that crashes mid-spec doesn't leave a permanently reserved email
// behind on staging; when the spec succeeds the tombstoned row is exactly
// what we want to leave in place for the reservation assertion.
export async function softDeleteMe(ctx: APIRequestContext, password: string): Promise<void> {
  try {
    await ctx.delete(routes.userMe, { data: { password } });
  } catch (err) {
    console.warn(`[accounts] self-soft-delete failed (will be swept later): ${String(err)}`);
  }
}
