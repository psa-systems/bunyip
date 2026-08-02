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
| Auth | `tests/auth/password-reset.spec.ts` | runnable | register a disposable account, request `/password-reset`, read the token from the Stalwart JMAP sink, set a new password, assert it logs in (BUNYIP-150). Skipped without `E2E_MAIL_SINK_URL` |
| Auth | `tests/auth/magic-link.spec.ts` | runnable | request `/magic-link` for a disposable account, follow the emailed token, assert the new session reads `/v1/auth/memberships` (BUNYIP-150). Skipped without `E2E_MAIL_SINK_URL` |
| Auth | `tests/auth/two-factor.spec.ts` | `test.fixme` | TOTP enrollment; needs a disposable account + captured secret (BUNYIP-152). The 2FA challenge leg is already exercised by every login in `lib/login.ts` |
| Account | `tests/account/profile.spec.ts` | runnable | edit `POST /settings/profile`, reload, assert persisted (non-destructive) |
| Account | `tests/account/sessions.spec.ts` | runnable (read-only) | assert the current session is listed (UI + `GET /v1/users/me/sessions`); never revokes, which would kill the shared session |
| Account | `tests/account/change-password.spec.ts` | `test.fixme` | mutates the shared E2E credential; needs a disposable account (suite-design limit, no sub-task) |
| Account | `tests/account/change-email.spec.ts` | runnable | register a disposable account, request an email change, confirm via the emailed link from the Stalwart JMAP sink, assert the new email (BUNYIP-150). Skipped without `E2E_MAIL_SINK_URL` |
| Memberships | `tests/memberships/memberships-list.spec.ts` | runnable | `/membership` renders; `GET /v1/auth/memberships` reports `active_tenant_id == E2E_TENANT_ID` |
| Billing | `tests/billing/subscribe.spec.ts` | runnable + prod skip | `POST /membership/subscribe` 302s to checkout.stripe.com (BUNYIP-151). Skipped without `E2E_STRIPE_SECRET_KEY` (= staging Stripe test mode provisioned) |
| Billing | `tests/billing/cancel.spec.ts` | `test.fixme` + prod skip | `POST /membership/cancel`; deferred under BUNYIP-151 - needs a setup step that gives the account an active membership, which is webhook-dependent (see the spec). Lands once staging Stripe + the webhook are live |
| Billing | `tests/billing/billing-portal.spec.ts` | runnable + prod skip | read-only redirect assertion on `/checkout/success` (BUNYIP-151). Skipped without `E2E_STRIPE_SECRET_KEY` |
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
| `E2E_STRIPE_SECRET_KEY` | no | Stripe test-mode key (`sk_test_...`). Used by teardown to cancel test-mode subscriptions AND as the gate for the billing specs - when set (the operator provisions it as `E2E_STAGING_STRIPE_SECRET_KEY` alongside staging Stripe test mode), `subscribe`/`billing-portal` run; unset, they skip (BUNYIP-151) |
| `E2E_MAIL_SINK_URL` | no | Staging mail-sink JMAP base URL with the **dedicated** E2E mailbox credentials embedded (e.g. `https://e2e%40a8n.run:APP_PASSWORD@mail.a8n.run`, the Stalwart server). The email-driven specs read token links from this mailbox; unset (e.g. production) makes them skip (BUNYIP-150). See [Mail-sink secret format](#mail-sink-secret-format-bunyip-272) for the exact shape. Do NOT use a personal mailbox (BUNYIP-272) |

## Forgejo Actions secrets and variables

Locally: the plain `E2E_*` names above, one environment at a time, in
`e2e/.env`. In CI: Forgejo Actions secrets hold staging and production side by
side; `.forgejo/workflows/e2e.yml` selects per var and exposes the result on the
plain `E2E_*` names, so the suite stays environment-agnostic. Test-only vars use
`E2E_STAGING_*` / `E2E_PRODUCTION_*`; the OP host follows the deployment's own
`OIDC_ISSUER_*` name. Automatic runs resolve to staging; production is
manual-dispatch only. See `docs/e2e.md` for provisioning + rotation sources.

`e2e.yml` does NOT run on `pull_request` (BUNYIP-425): that event executes the
PR head's workflow, install scripts and specs, so none of these credentials may
be in scope for it. PRs run `.forgejo/workflows/e2e-pr.yml`, which declares only
`E2E_STAGING_BASE_URL` and `OIDC_ISSUER_STAGING`.

The tables below are the authoritative list of every repository-level Forgejo
Actions **secret** and **variable** the workflows (`.forgejo/workflows/*.yml`)
consume. Names and purpose only - VALUES live in the Forgejo secret store and
never in this repo. Set them under the repo's Settings -> Actions -> Secrets /
Variables.

### Build and release (non-E2E)

Consumed by the image-build and release workflows, not the suite.

| Name | Kind | Consumed by | Purpose |
| --- | --- | --- | --- |
| `PSA_SYSTEMS_PRIVATE_PACKAGE_PAT` | secret | `build-api`, `build-web`, `create-release` | Forgejo PAT. Registry push password for the published images (`REGISTRY_PASSWORD`) and the releases-API call in `create-release`. Needs `write:repository` (releases) plus package-write (image push) scope. |
| `PSA_SYSTEMS_PRIVATE_PACKAGE_OWNER` | variable | `build-api`, `build-web` | Registry owner/org path segment for the published images (`REGISTRY_OWNER`). |
| `RUNS_ON_OPENSUSE_BASE_LATEST` | variable | `build-api`, `build-web`, `create-release`, `e2e-pr` | Runner label for jobs that compile nothing on the runner and launch no browser (`e2e-pr` only downloads Chromium) (`runs-on`). |
| `RUNS_ON_OPENSUSE_DEV_LATEST` | variable | `check`, `e2e` | Runner label for jobs the base image cannot serve: only this image carries the C toolchain and OpenSSL headers (`check`, BUNYIP-444) and the Playwright browser system libraries plus the pre-baked browsers (`e2e`, BUNYIP-446) (`runs-on`). |

### E2E (consumed by `e2e.yml`)

`e2e.yml` picks the staging or production value per `inputs.environment` and
exposes it on the plain `E2E_*` name the suite reads (the Configuration table
above describes what each plain name does). All E2E secrets are required EXCEPT
the two marked optional. Production has no mail sink, so there is deliberately no
`E2E_PRODUCTION_MAIL_SINK_URL`.

| Staging secret | Production secret | Req | Purpose (plain name) |
| --- | --- | --- | --- |
| `E2E_STAGING_BASE_URL` | `E2E_PRODUCTION_BASE_URL` | yes | hub-web apex the suite navigates to (`E2E_BASE_URL`) |
| `OIDC_ISSUER_STAGING` | `OIDC_ISSUER_PRODUCTION` | yes | OIDC OP + API host (`E2E_OP_BASE_URL`) |
| `E2E_STAGING_EMAIL` | `E2E_PRODUCTION_EMAIL` | yes | dedicated E2E account login (`E2E_EMAIL`) |
| `E2E_STAGING_PASSWORD` | `E2E_PRODUCTION_PASSWORD` | yes | password for that account (`E2E_PASSWORD`) |
| `E2E_STAGING_TENANT_ID` | `E2E_PRODUCTION_TENANT_ID` | yes | UUID of the E2E tenant (`E2E_TENANT_ID`) |
| `E2E_STAGING_OIDC_CLIENT_ID` | `E2E_PRODUCTION_OIDC_CLIENT_ID` | yes | public PKCE client id (`E2E_OIDC_CLIENT_ID`) |
| `E2E_STAGING_OIDC_REDIRECT_URI` | `E2E_PRODUCTION_OIDC_REDIRECT_URI` | yes | registered redirect_uri, exact match (`E2E_OIDC_REDIRECT_URI`) |
| `E2E_STAGING_TOTP_SECRET` | `E2E_PRODUCTION_TOTP_SECRET` | yes | base32 TOTP secret for the account (`E2E_TOTP_SECRET`) |
| `E2E_STAGING_STRIPE_SECRET_KEY` | `E2E_PRODUCTION_STRIPE_SECRET_KEY` | no | Stripe test-mode key; gates the billing specs (`E2E_STRIPE_SECRET_KEY`, BUNYIP-151) |
| `E2E_STAGING_MAIL_SINK_URL` | (none - staging only) | no | JMAP mail sink; gates the email-driven specs (`E2E_MAIL_SINK_URL`, BUNYIP-150). Production resolves empty, so those specs skip there |

### Mail-sink secret format (BUNYIP-272)

The email-driven specs (`password-reset`, `magic-link`, `change-email`) read
token links over JMAP from a Stalwart mailbox. That mailbox must be a
**dedicated** e2e account, not a personal one: a personal account ties CI to one
person's password rotation and account lifecycle (BUNYIP-272; BUNYIP-150
originally pointed it at `nate@a8n.run`).

The reader takes a single URL secret with the credentials embedded:

```
https://<url-encoded-email>:<application-password>@<jmap-host>
```

- `<url-encoded-email>` - the dedicated mailbox address, URL-encoded so the `@`
  becomes `%40` (e.g. `e2e@a8n.run` -> `e2e%40a8n.run`). Without the encoding the
  URL parser reads the local part as the userinfo and the domain as the host.
- `<application-password>` - an **application password** scoped to that mailbox
  (not the account's primary password). Generated in Stalwart per-account.
- `<jmap-host>` - the Stalwart server host, `mail.a8n.run`. The reader appends
  the JMAP session path itself; give only the base host.

Example (staging): `https://e2e%40a8n.run:xxxxxxxxxxxx@mail.a8n.run`.

Set it as the plain `E2E_MAIL_SINK_URL` locally (in `e2e/.env`) or as the
`E2E_STAGING_MAIL_SINK_URL` Forgejo Actions secret in CI. There is deliberately
no production equivalent (production has no mail sink, so the specs skip there).

Provisioning steps (the account + secret are operator-side; only this doc and
the env plumbing live in the repo):

1. Create the dedicated mailbox on `mail.a8n.run` (e.g. `e2e@a8n.run`). Account
   creation needs a Stalwart admin.
2. Generate an application password scoped to that mailbox.
3. Compose the URL above and set `E2E_STAGING_MAIL_SINK_URL` (CI) /
   `E2E_MAIL_SINK_URL` (local) to it.
4. Re-run the email-driven specs to confirm green.

## Disposable accounts (cleanup)

The email-driven specs (`password-reset`, `magic-link`, `change-email`) register
a throwaway account per run (`lib/accounts.ts`) and self-delete it in a
`finally`. The self-delete calls `DELETE /v1/users/me?purge=1`, which
HARD-deletes the row rather than soft-deleting it, so accounts do not accumulate
on staging (BUNYIP-246). The purge is gated SERVER-side: bunyip-api honours it
only on a non-production deployment whose env sets `BUNYIP_E2E_BOOTSTRAP_ALLOW=true`
(see `docs/e2e.md`). Production ignores the flag and soft-deletes as normal,
and these specs skip there anyway. The same gate enables a bunyip-api background
reaper that hard-deletes any leaked disposable (a crashed run whose `finally`
never ran) older than 6h; it never runs in production.

## Blocked specs (`test.fixme`) and their blockers

| Blocker | Specs | Unblocks when |
| --- | --- | --- |
| BUNYIP-149 | (suite coverage umbrella) | n/a - tracks the runnable coverage |
| BUNYIP-150 (mail sink) | `auth/signup` | a programmatic mailbox can read the confirmation link. The `password-reset`, `magic-link`, and `change-email` specs now run via the Stalwart JMAP sink (`E2E_MAIL_SINK_URL`); `signup` is the remaining follow-up |
| BUNYIP-151 (staging Stripe test mode) | `billing/cancel` | `subscribe` + `billing-portal` are un-fixme'd and gated on `E2E_STRIPE_SECRET_KEY`; `cancel` stays deferred until staging Stripe + the subscription webhook are live (it needs a webhook-propagated active membership to cancel) |
| BUNYIP-152 (2FA enrollment account) | `auth/two-factor` | a disposable account + captured secret exists to test enrollment without disturbing the shared account |
| suite-design (no sub-task) | `account/change-password` | the suite can provision a disposable account whose credential is throwaway |

Billing write specs ALSO carry `test.skip(env.isProductionApex, ...)` so a manual
production dispatch can never start or touch a live subscription. That guard is
independent of the fixme and stays after the fixme is lifted.

## CI

See `docs/e2e.md` for the workflow shape, the deploy-sync / health gate
scripts (`scripts/wait-for-deploy.mjs`, `scripts/health-check.mjs`), the
production-skip safety gate, and how to add a new spec.
