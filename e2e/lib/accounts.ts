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

import { type APIRequestContext } from '@playwright/test';
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

// Register a fresh account on `ctx`. On success `ctx` holds the new account's
// session cookies (register logs the user in), so the caller can reuse it for
// authenticated calls and for the eventual self-delete.
export async function registerDisposable(ctx: APIRequestContext): Promise<DisposableAccount> {
  const account: DisposableAccount = { email: disposableEmail(), password: DISPOSABLE_PASSWORD };
  const res = await ctx.post(routes.authRegister, {
    data: { email: account.email, password: account.password },
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
