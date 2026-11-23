# Authentication

How bunyip authenticates its own callers. For a user signing in to a bunyip-authenticated site, and for a deployment operator who needs to know why a request was accepted or refused. Separate from [OIDC provider](oidc-provider.md), which covers bunyip issuing tokens to downstream relying parties.

## Credential kinds bunyip accepts

A request to the bunyip api can carry one of three credentials, handled by the same bearer path.

- **`at+jwt` access token.** The normal browser session. Issued by bunyip's OP side and verified against bunyip's own JWKS. Short-lived; renewed through the refresh flow.
- **API token (`sfk_`-prefixed).** A machine credential, scoped and bound to the account that minted it. Shown once at create time; stored only as its hash. Revocable.
- **Session cookie.** The browser carries a session cookie for the web ssr paths. It lives alongside the access token, is renewed on activity, and ends on sign-out.

The api verifies whichever credential the request carries and refuses with `401` otherwise. Verification is idempotent per request: an auth check runs once and is reused by downstream handlers.

## Sign-in paths

- **Password.** The default for a human on the sign-in page. A correct password that satisfies the two-factor gate and the login-approval gate (see below) mints a session.
- **Magic link.** For a password reset or a first sign-in from a sign-up. The link is single-use and expires.
- **API login.** A machine client can POST to the login endpoint with a password to receive an API token; this path is not for users and is behind the same rate-limit floor as the browser login.

## Two-factor (TOTP)

Every user can enrol a TOTP second factor. The enrol flow stores a pending seed, shows a QR code, and binds the final confirm to a one-time setup token so an abandoned enrol never leaves an active seed behind. Ten recovery codes are shown on completion. Recovery codes are single-use and regenerable.

An enrolled user:

- Signs in with password and the current TOTP code, or with a recovery code.
- Can re-key to a new authenticator by starting a rekey (password + a current factor) and confirming the new seed before the pending candidate expires. The current secret and recovery codes stay active until the new code confirms.
- Cannot delete the second factor without password plus a current code.

A super-admin reset of a user's second factor (support path) writes a dedicated audit event and is gated by the super-admin's own password plus a current factor.

## Login approval

With login approval enabled, a sign-in from a country the account has not used before OR from a device the account has not completed a sign-in from before is held. No session is minted until the owner releases the hold from a single-use emailed link. One switch, two triggers (country and device), one hold.

- Approval is page-gated: the browser polls the approval endpoint after submitting credentials.
- The emailed link releases the session once; collection returns the session in the body and marks the reference used.
- The owner can review and remove devices on the account Devices page, so revoking a device no longer requires operator SQL.
- API sign-ins are exempt from the device trigger only, never the country trigger.

Login approval needs SMTP. If mail is down, every sign-in is held and nobody can release. [Troubleshooting](troubleshooting.md) covers the recovery for this case.

## Device enrolment

Every successful sign-in is matched against the account's recorded devices. A match keeps the sign-in from triggering the device gate. A miss (a browser the account has not completed a sign-in from before) triggers the hold.

- `user_devices` ships empty. A deployment that turns login approval on today is not asked to backfill; every account begins at the baseline, and devices are recorded as they are used.
- The account Devices page lists the devices the account has completed a sign-in from, marks the current one, and lets the owner remove any row. The removed browser's cookie is inert on its next request and is held for re-enrolment.

## API tokens

A user mints an API token from their account page. A token is bound to the issuing account, prefixed `sfk_`, shown once, stored only as its Argon2 hash. It cannot carry more privilege than the account at the time of mint. Revocation uses a single-use consume path so a token cannot be used after the revocation commits.

Create, revoke, and every verified use land in the audit log.

## Session lifetime

- Access tokens are short (minutes, configurable through `OIDC_ACCESS_TOKEN_TTL`).
- Refresh tokens are longer (hours to days through `OIDC_REFRESH_TOKEN_TTL`).
- The session cookie is renewed on activity; a signed-out session invalidates the session cookie everywhere.

## What authentication does NOT grant

- Authentication is not authorization. A verified bearer still has to pass the per-route gate: role, scope, tenant check, feature-flag check, rate-limit floor.
- A verified bearer under the wrong audience is a 401, not a 403: bunyip refuses to disclose whether the resource exists.
