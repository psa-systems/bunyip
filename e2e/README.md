# bunyip E2E suite (Playwright)

End-to-end tests that run against a **deployed** bunyip instance (staging by
default), not a CI-built artifact. The suite drives the real server-rendered
bunyip-web hub (Maud + htmx forms, real POSTs) and the bunyip-api `/v1` JSON API
+ OIDC OP. Tracked under BUNYIP-148 (harness) / BUNYIP-149 (coverage).

## What it covers

Specs live in `tests/<area>/`. A spec is one of: **runnable** (asserts now),
or **`test.fixme`** (intent sketched, blocked on a cited dependency). Every
`test.fixme` names its blocker inline.

| Area | Spec | Status | What |
| --- | --- | --- | --- |
| Auth | `tests/auth/login.spec.ts` | runnable | ONE combined login + logout round-trip via the real `/login` form (TOTP-aware), kept to a single login to stay under the 5/min rate limit |
| Auth | `tests/auth/signup.spec.ts` | `test.fixme` | self-service `/register`; needs a mail sink to read the confirmation link (BUNYIP-150) |
| Auth | `tests/auth/password-reset.spec.ts` | `test.fixme` | `/password-reset` -> `/password-reset/confirm`; needs a mail sink to read the token (BUNYIP-150) |
| Auth | `tests/auth/magic-link.spec.ts` | `test.fixme` | `/magic-link` passwordless login; needs a mail sink (BUNYIP-150) |
| Auth | `tests/auth/two-factor.spec.ts` | `test.fixme` | TOTP enrollment; needs a disposable account + captured secret (BUNYIP-152). The 2FA challenge leg is already exercised by every login in `lib/login.ts` |
| Account | `tests/account/profile.spec.ts` | runnable | edit `POST /settings/profile`, reload, assert persisted (non-destructive) |
| Account | `tests/account/sessions.spec.ts` | runnable (read-only) | assert the current session is listed (UI + `GET /v1/users/me/sessions`); never revokes, which would kill the shared session |
| Account | `tests/account/change-password.spec.ts` | `test.fixme` | mutates the shared E2E credential; needs a disposable account (suite-design limit, no sub-task) |
| Account | `tests/account/change-email.spec.ts` | `test.fixme` | needs an email-change confirmation sink (BUNYIP-150) |
| Memberships | `tests/memberships/memberships-list.spec.ts` | runnable | `/membership` renders; `GET /v1/auth/memberships` reports `active_tenant_id == E2E_TENANT_ID` |
| Billing | `tests/billing/subscribe.spec.ts` | `test.fixme` + prod skip | `POST /membership/subscribe` 302s to checkout.stripe.com; needs staging Stripe test mode (BUNYIP-151) |
| Billing | `tests/billing/cancel.spec.ts` | `test.fixme` + prod skip | `POST /membership/cancel`; needs staging Stripe test mode (BUNYIP-151) |
| Billing | `tests/billing/billing-portal.spec.ts` | `test.fixme` + prod skip | read-only redirect assertion on `/checkout/success`; needs staging Stripe configured (BUNYIP-151) |
| OIDC | `tests/oidc/authorize-redirect.spec.ts` | runnable | `/oauth2/authorize` (no-follow) returns a `code` to the registered redirect host; names `/login` vs `/consent` on a no-code bounce |
| OIDC | `tests/oidc/token-flow.spec.ts` | runnable | full PKCE: authorize -> code -> `/oauth2/token` -> `/oauth2/userinfo` -> refresh |
| OIDC | `tests/oidc/consent-screen.spec.ts` | runnable | asserts `GET /oauth2/consent` responds coherently (renders the form, or redirects on because setup pre-granted scopes); fixme fallback noted inline if the route ever needs an in-flight ticket |

## Project model (`playwright.config.ts`)

The suite shares ONE E2E account + tenant, and bunyip rate-limits login to
**5/min/email**, so projects are serialised (`workers: 1`, `fullyParallel:
false`) and login is spent sparingly:

| Project | Tests | Auth | Runner |
| --- | --- | --- | --- |
| `preflight` | `tests/preflight.setup.ts` | none | aggregates every missing required env var into one error |
| `setup` | `tests/global.setup.ts` | logs in ONCE | drives the hub login (TOTP-aware), captures the bearer + OP cookies + full browser storageState, and drives the OIDC consent Allow so granted scopes exist. Persists to `.auth/`. Depends on `preflight` |
| `auth-ui` | `tests/auth/*.spec.ts` | ANONYMOUS | browser `page`, no stored session; each runnable spec does its own `loginViaHub`. Its logout assertion runs in a fresh context, so it never invalidates the shared session. The ONLY project that spends the login rate limit, so login-bearing flows are combined and the rest are `test.fixme`. Depends on `preflight` |
| `account-ui` | `tests/{account,memberships,billing}/*.spec.ts` | ALREADY AUTHENTICATED | browser `page` loaded with the storageState `setup` saved. Do NOT call `loginViaHub` here. Use `page.request` for API calls (it carries the session cookies). Depends on `setup` |
| `api` | `tests/oidc/*.spec.ts` | request context | the `test`/`oidcTest` fixtures from `lib/fixtures.ts` (bearer, or replayed OP cookies). No browser. Uses the OP host. Depends on `setup` |

**storageState reuse + the 5/min rationale.** `setup` logs in once and saves the
authenticated browser storageState to `.auth/hub-state.json`; `account-ui`
replays it so each of its specs starts logged in WITHOUT a fresh login. A login
per spec would trip the per-email limit within a handful of specs. The only
fresh login each run is `setup`'s (plus `auth-ui`'s single combined round-trip),
which keeps the run comfortably under the cap even with CI retries.

## Run locally

```
cp e2e/.env.example e2e/.env   # then fill in the secrets
just e2e                        # from the repo root
# or, from e2e/:
npm ci
npx playwright install --with-deps chromium
npx playwright test             # or: npm test
npx playwright show-report      # after a run
```

`npx playwright test --headed` (or any `playwright test` flag) passes through.

## Configuration

Set via `e2e/.env` locally (copy from `.env.example`) or Forgejo Actions secrets
in CI. The suite reads only the plain `E2E_*` names; CI selects per environment
and exposes the result on those plain names (see [CI](#ci)). `lib/env.ts`
fail-loud validates every required var via the `preflight` project before any
test runs.

| Var | Req | Purpose |
| --- | --- | --- |
| `E2E_BASE_URL` | yes | hub-web apex the browser projects navigate to. No default (staging `https://a8n.systems`, prod `https://psa.systems`) |
| `E2E_OP_BASE_URL` | rec | OIDC OP + API host (`/oauth2/*`, `/.well-known/*`). Defaults to prepending `api.` to `E2E_BASE_URL`. bunyip serves OP and `/v1` on one host |
| `E2E_API_BASE_URL` | no | `/v1` JSON API host. Defaults to `E2E_OP_BASE_URL` |
| `E2E_EMAIL` / `E2E_PASSWORD` | yes | the dedicated E2E account (2FA enabled) |
| `E2E_TENANT_ID` | yes | UUID of the dedicated E2E tenant the account acts in |
| `E2E_OIDC_CLIENT_ID` | yes | public PKCE client id for the OP token-flow specs |
| `E2E_OIDC_REDIRECT_URI` | yes | redirect_uri registered for that client (must match EXACTLY, or `invalid_redirect_uri`). Only the `code` is captured; the URL is never loaded |
| `E2E_TOTP_SECRET` | yes | base32 TOTP secret for the account; the second factor is computed at runtime |
| `E2E_STRIPE_SECRET_KEY` | no | Stripe test-mode key, used ONLY by teardown to cancel test-mode subscriptions. Unused until BUNYIP-151 |

## Secret layout

Locally: the plain `E2E_*` names above, one environment at a time, in
`e2e/.env`. In CI: Forgejo Actions secrets hold staging and production side by
side; `.forgejo/workflows/e2e.yml` selects per var and exposes the result on the
plain `E2E_*` names, so the suite stays environment-agnostic. Test-only vars use
`E2E_STAGING_*` / `E2E_PRODUCTION_*`; the OP host follows the deployment's own
`OIDC_ISSUER_*` name. Automatic runs resolve to staging; production is
manual-dispatch only. See `dev-docs/e2e.md` for provisioning + rotation sources.

## Blocked specs (`test.fixme`) and their blockers

| Blocker | Specs | Unblocks when |
| --- | --- | --- |
| BUNYIP-149 | (suite coverage umbrella) | n/a - tracks the runnable coverage |
| BUNYIP-150 (mail sink) | `auth/signup`, `auth/password-reset`, `auth/magic-link`, `account/change-email` | a programmatic mailbox can read confirmation/reset/magic links |
| BUNYIP-151 (staging Stripe test mode) | `billing/subscribe`, `billing/cancel`, `billing/billing-portal` | staging Stripe test mode is wired (a test customer/price exists) |
| BUNYIP-152 (2FA enrollment account) | `auth/two-factor` | a disposable account + captured secret exists to test enrollment without disturbing the shared account |
| suite-design (no sub-task) | `account/change-password` | the suite can provision a disposable account whose credential is throwaway |

Billing write specs ALSO carry `test.skip(env.isProductionApex, ...)` so a manual
production dispatch can never start or touch a live subscription. That guard is
independent of the fixme and stays after the fixme is lifted.

## CI

See `dev-docs/e2e.md` for the workflow shape, the deploy-sync / health gate
scripts (`scripts/wait-for-deploy.mjs`, `scripts/health-check.mjs`), the
production-skip safety gate, and how to add a new spec.
