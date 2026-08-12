# E2E suite: structure, provisioning, and CI (BUNYIP-148/149)

How the bunyip Playwright E2E suite is wired, how its secrets are provisioned,
how CI gates a run on a live deploy, and how to add a new spec. The suite runs
against a **deployed** bunyip instance (staging by default), not a CI-built
artifact: it drives the real server-rendered bunyip-web hub and the bunyip-api
`/v1` API + OIDC OP. The operator-facing run/config reference lives in
`e2e/README.md`; this document is the engineering view.

## Suite structure

```
e2e/
  playwright.config.ts        project definitions (preflight/setup/auth-ui/account-ui/api)
  lib/                        shared foundation (DO NOT duplicate in specs)
    env.ts                    fail-loud env access + preflightRequiredEnv()
    api.ts                    route constants, PKCE, discoverOidc, randomToken
    fixtures.ts               `test` (bearer) and `oidcTest` (replayed OP cookies) request fixtures
    login.ts                  loginViaHub/logoutViaHub (TOTP-aware), expectAuthenticated/Anonymous
    auth-state.ts             read/write .auth/token.txt + .auth/op-state.json
    factories.ts              today(), getMemberships(), tagged()
    run.ts                    run id + e2e-<epoch>-<runId>-<n> tagging for teardown
    page-diagnostics.ts       attachPageDiagnostics(): URL trail + request log on failure
  tests/
    preflight.setup.ts        project `preflight`: aggregate missing-env check
    global.setup.ts           project `setup`: one login, capture bearer + OP cookies + storageState + drive consent
    global.teardown.ts        delete this run's records, sweep e2e- residue > 24h
    auth/                     project `auth-ui` (ANONYMOUS browser; specs self-login)
    account/                  project `account-ui` (authenticated browser; storageState replay)
    memberships/             project `account-ui`
    billing/                 project `account-ui` (+ production-skip gate)
    oidc/                    project `api` (request-context fixtures)
  scripts/
    wait-for-deploy.mjs       deploy-sync gate (push/dispatch-staging)
    health-check.mjs          reachability gate (PR gate/dispatch-production)
```

### Project model and the login rate limit

The suite shares ONE E2E account + tenant. bunyip rate-limits login to
**5 logins/min/email**, so `playwright.config.ts` runs serial (`workers: 1`,
`fullyParallel: false`) and spends login sparingly:

- `preflight` -> `setup` -> (`auth-ui`, `account-ui`, `api`). `setup` logs in
  once and writes three artifacts under `e2e/.auth/`:
  - `token.txt`: the bunyip access_token (bearer for the `api`/`test` fixture
    and teardown).
  - `hub-state.json`: the FULL authenticated browser storageState, replayed by
    `account-ui` so its specs start logged in WITHOUT a fresh login.
  - `op-state.json`: the OP-session cookies (notably `bunyip_op_session`),
    replayed by the `oidc` specs via `oidcTest` so `/oauth2/authorize` sees a
    server-validated session and mints a `code` rather than bouncing to /login.
  `setup` also drives the OIDC consent Allow once so the OP session carries
  granted scopes for the token-flow specs.
- `auth-ui` (`tests/auth/*`) runs ANONYMOUS (no storageState) and does its own
  `loginViaHub`. It is the ONLY project that spends the login limit, so its
  runnable coverage is a single combined login + logout round-trip and every
  other auth flow is `test.fixme`. Its logout runs in a fresh context, so it
  never invalidates the shared `account-ui` session.
- `account-ui` (`tests/{account,memberships,billing}/*`) replays
  `hub-state.json` and must NOT call `loginViaHub`. API calls use `page.request`
  (carries the session cookies).
- `api` (`tests/oidc/*`) is request-context only via the `lib/fixtures.ts`
  fixtures, on the OP host.

## Secret layout and provisioning

The suite reads only the plain `E2E_*` names (full table in `e2e/README.md`).
`lib/env.ts` derives the OP/API host by prepending `api.` to `E2E_BASE_URL` when
`E2E_OP_BASE_URL` is unset, and fail-loud validates every required var through
the `preflight` project before any test runs.

### Local

Copy `e2e/.env.example` to `e2e/.env` and fill the plain names for ONE
environment. `.env` is gitignored; `.env.example` is committed.

### CI

Forgejo Actions secrets hold staging and production side by side. The
`.forgejo/workflows/e2e.yml` job `env:` block selects per var and exposes the
result on the plain `E2E_*` names via a Forgejo expression
(`${{ inputs.environment == 'production' && secrets.<PRODUCTION> || secrets.<STAGING> }}`),
so `env.ts` and the gate scripts only ever read the plain names. Test-only vars
use `E2E_STAGING_*` / `E2E_PRODUCTION_*`; the OP host follows the deployment's
own `OIDC_ISSUER_*` variable name where one exists. On `push` the `inputs`
context is empty, so each expression resolves to its staging secret; a manual
dispatch lets the operator pick. None of these reach a `pull_request` run: the
PR gate is a separate workflow that declares only the two base URLs (see
[CI workflow](#ci-workflow)).

### Provisioning the E2E account + tenant

- **Staging:** use the `bunyip-e2e-bootstrap` binary (idempotent), driven by
  `just e2e-bootstrap` (runs `cargo run --bin bunyip-e2e-bootstrap` inside the
  api container against the staging database; requires
  `BUNYIP_E2E_BOOTSTRAP_ALLOW=true` and `BUNYIP_E2E_TEST_USER_PASSWORD` in the
  container env). It seeds the dedicated E2E account(s) + tenant. Pass-through
  flags exist (`--dry-run`, `--cleanup`, `--enable-2fa`). Record the resulting
  `E2E_EMAIL`, `E2E_PASSWORD`, `E2E_TENANT_ID`. For 2FA, prefer `--enable-2fa`
  (BUNYIP-359): choose a base32 secret, export it as `BUNYIP_E2E_TOTP_SECRET` in
  the api-container env, and run `just e2e-bootstrap --enable-2fa`; the bootstrap
  enrolls that PRESET secret and enables 2FA on the seeded accounts, so the
  matching `E2E_TOTP_SECRET` stays STABLE: the account's stored secret is a fixed
  preset (not a per-enrollment random), and the c-01 Postgres is a persistent
  external volume that no deploy or reseed wipes, so one correct enrollment
  holds. The alternative is manual UI enrollment (below), which mints a fresh
  secret you must then re-capture. Note that bunyip consumes a TOTP code the
  moment it accepts it (BUNYIP-428, single use per RFC 6238 section 5.2), so two
  logins on the SAME account inside one 30s step collide: the second sees
  "Invalid verification code". `lib/login.ts` absorbs that by waiting out the
  step and resubmitting a fresh code once; specs that log in repeatedly should
  rely on `loginViaHub` rather than driving the 2FA form directly.

  > **Invariant + recovery.** The account's enrolled secret (from `--enable-2fa`)
  > and `E2E_STAGING_TOTP_SECRET` (the Forgejo Actions secret the suite reads as
  > `E2E_TOTP_SECRET`) must be the byte-identical base32 string: the server
  > verifies against the former, the suite generates codes from the latter. If
  > they differ, EVERY code is rejected and login fails on the FIRST 2FA submit,
  > so both `global.setup` and `login.spec` fail with `TOTP rejected on both
  > attempts, including a fresh code from a new step` (`lib/login.ts`). Forgejo
  > secrets are write-only, so do not try to read one to compare: pick a single
  > base32 value `S`, set the Forgejo `E2E_STAGING_TOTP_SECRET = S`, and re-run
  > `BUNYIP_E2E_TOTP_SECRET=S just e2e-bootstrap --enable-2fa` in the api
  > container; the two are then equal by construction. This is a ONE-TIME fix (the
  > enrollment persists, per the note above). Distinguish it from the single-use
  > collision: a secret mismatch fails the FIRST login every time, whereas a
  > collision only bites a SECOND login in the same 30s step and `lib/login.ts`
  > already recovers it by waiting out the step (BUNYIP-453).

- **Production:** provisioned manually (the bootstrap binary is gated to
  non-production by design). Create the account + tenant by hand, enable 2FA,
  and record the same vars under the `E2E_PRODUCTION_*` secret names.
- **OIDC client:** register a public PKCE client (or reuse the staging app
  client) with a redirect_uri that allows capture-only. Record
  `E2E_OIDC_CLIENT_ID` and the exact registered `E2E_OIDC_REDIRECT_URI`. A
  mismatch makes `/oauth2/authorize` return `invalid_redirect_uri`. If authorize
  bounces the E2E session to `/login` (no code), the OP-session cookie scoping
  is wrong (COOKIE_DOMAIN vs the OP host); see BUNYIP-146.
- **Mail sink (staging only, BUNYIP-150):** staging bunyip-api keeps sending
  through the existing Stalwart relay (`mail.a8n.run`); a mailbox there
  (currently `nate@a8n.run`; a dedicated `e2e@a8n.run` once it can be created)
  receives the E2E mail, and the email-driven specs (`password-reset`,
  `magic-link`, `change-email`) read the token-links from it over Stalwart's
  JMAP API (`https://mail.a8n.run`). Each spec self-registers a throwaway bunyip
  account at a unique plus-subaddress of that mailbox (`<mailbox>+<run-tag>`),
  which Stalwart delivers into the mailbox; the suite reads by recipient,
  extracts the link, and destroys the message. The mailbox address is taken
  from the secret's userinfo, so switching from `nate@` to `e2e@` later is a
  secret change only - no code change. Because the mailbox may be a personal
  one, the reader only ever matches/destroys mail whose `To` is the EXACT
  subaddress, never the base mailbox. Prerequisites: plus-subaddressing enabled
  on the mailbox (or a catch-all). Record the JMAP URL with the mailbox
  credentials embedded as the staging secret `E2E_STAGING_MAIL_SINK_URL` (e.g.
  `https://nate%40a8n.run:password@mail.a8n.run`). Production has no sink, so
  `E2E_MAIL_SINK_URL` resolves empty there and those specs skip. Registration
  needs no email confirmation and each disposable account self-deletes, so no
  shared state is touched. (This replaced an earlier Mailpit-on-c-01 design and
  the plaintext SMTP app change; both were dropped in favour of reusing
  Stalwart.)
- **Disposable-account hard delete + reaper (staging only, BUNYIP-246):** the
  per-spec self-delete calls `DELETE /v1/users/me?purge=1`, which HARD-deletes
  the row instead of soft-deleting it, so disposable accounts do not pile up as
  soft-deleted rows. The purge is honoured ONLY on a non-production deployment
  whose running bunyip-api has `BUNYIP_E2E_BOOTSTRAP_ALLOW=true` set in its
  server env (the same flag the bootstrap binary uses; set it on the staging api
  container, not just for the one-off `just e2e-bootstrap` invocation).
  Production never sets it, so `?purge` is ignored there and the endpoint
  soft-deletes as before. That same gate also enables a background reaper in
  bunyip-api that hourly hard-deletes any disposable row (email matching the
  `+e2e-` subaddress marker) older than 6h, a safety net for a crashed run whose
  `finally` never ran. The reaper is never spawned in production.
- **Registration rate limit (BUNYIP-150 / 196 / 197):** `/v1/auth/register` is
  capped 3/hour/IP as a production anti-abuse control. The deployed-instance
  e2e suite self-provisions disposable accounts from the single CI runner egress
  IP, so registrations accumulate across serial runs in the one-hour window and
  trip a spurious 429. Root-cause fix (`bunyip-api/src/handlers/auth.rs::register`):
  the budget varies by environment, not whether one exists. Production keeps
  `RateLimitConfig::REGISTRATION` (3/hour/IP); staging/dev use
  `REGISTRATION_NON_PROD` (30/hour/IP), which is loose enough for serial e2e runs
  from one egress IP. BUNYIP-426 F7 replaced the earlier
  `if config.is_production()` skip, which left `/v1/auth/register` completely
  unthrottled on the publicly reachable dev-sso stack. Since BUNYIP-426 F7 the
  `RateLimitFloor` middleware also caps every non-exempt endpoint at
  `API_UNAUTH` (20/min/IP) for anonymous callers, so a burst-heavy spec can trip
  that floor even where the per-endpoint cap is generous. No env knob, no
  per-run workaround. NOTE: because the suite tests the
  DEPLOYED instance, this fix only takes effect after the new image is deployed
  to staging, so a PR's own pre-merge e2e run can still 429 against the not-yet-
  redeployed staging; it goes green on the post-merge run.
- **JMAP apiUrl origin (BUNYIP-150):** Stalwart advertises its session `apiUrl`
  as the internal `http://mail.a8n.run:8080/jmap/`, which the CI runner cannot
  reach. `lib/mail-sink.ts:jmapSession` keeps only the apiUrl PATH and forces the
  origin back to the public sink base (the `.well-known/jmap` GET already proved
  443 reachability).
- **change-email verifies first (BUNYIP-150):** `request_email_change`
  (`crates/bunyip-domain/src/services/auth.rs`) changes an UNVERIFIED account's
  email immediately with NO confirmation email; only a VERIFIED account gets the
  emailed `/settings/confirm-email` link. A freshly registered disposable account
  is unverified, so `tests/account/change-email.spec.ts` first verifies it via
  the verify-email flow (over the same sink) so the change takes the
  link-confirmed path it is meant to exercise.
- **Stripe billing (staging only, BUNYIP-151):** the billing specs need staging
  bunyip running Stripe in TEST mode. Operator provisioning:
  1. In a Stripe TEST-mode account, create the membership product + a recurring
     price; note the price id.
  2. Configure the staging bunyip-api with the test-mode secret key
     (`sk_test_...`), the webhook signing secret (`whsec_...`), and the price id
     on the admin UI (`/admin/stripe`, stored encrypted in the DB). BUNYIP-482:
     that page is the only source; there is no env fallback. Point a Stripe
     test-mode webhook endpoint at `https://api.a8n.systems/v1/webhook` (or
     wherever the webhook route is) using that `whsec_`.
  3. Record the same `sk_test_...` as the Forgejo Actions secret
     `E2E_STAGING_STRIPE_SECRET_KEY`. The suite exposes it as `E2E_STRIPE_SECRET_KEY`,
     which both feeds teardown (cancels test-mode subscriptions) AND gates the
     billing specs: `subscribe` + `billing-portal` run when it is set, skip
     otherwise; all billing specs also `test.skip` on the production apex.
  `cancel` stays deferred: it needs an ACTIVE membership to cancel, and
  `/membership/cancel` only engages when `membership_status` is active, which the
  `customer.subscription.created` webhook flips - so a future setup step must
  create a test-mode subscription on the account's customer and wait for the
  webhook. Build it once staging Stripe + the webhook are live and can validate it.

**Rotation source (record per secret).** So each value can be rotated later,
document where it is generated, per environment: the Forgejo Actions secret
store entry itself; the E2E tenant + account (`*_EMAIL` / `*_PASSWORD` /
`*_TENANT_ID`, from bootstrap/manual provisioning); the OIDC client registration
(`*_OIDC_CLIENT_ID` / `*_OIDC_REDIRECT_URI`); and the TOTP enrollment
(`*_TOTP_SECRET`). Keep this here or in the team secret runbook.

## First-time setup runbook

Ordered steps to take the suite from merged-code to a green CI run. None of this
is in-repo: it is account, secret, and Forgejo-admin work. Do the staging set
first; production is the same shape with `E2E_PRODUCTION_*` / `OIDC_ISSUER_PRODUCTION`.

1. **Merge the suite.** Lands `e2e/`, the `just e2e` recipe, and
   `.forgejo/workflows/e2e.yml` + `.forgejo/workflows/e2e-pr.yml`.

2. **Seed the staging E2E account + tenant.** On the c-01 host, from the docker
   repo, run the bootstrap recipe (DEV-378). It runs the `bunyip-e2e-bootstrap`
   binary shipped in the deployed image (BUNYIP-156) as a one-off container, and
   creates `e2e-user@a8n.run` + `e2e-admin@a8n.run` (idempotent):

   ```nu
   # The shared account password. Provide it as BUNYIP_E2E_TEST_USER_PASSWORD.
   # If the infisical CLI is set up on the host and logged into your instance:
   $env.BUNYIP_E2E_TEST_USER_PASSWORD = (infisical secrets get test_user_password --path=/bunyip/e2e --env=staging --plain)
   cd server/c-01/bunyip-api
   just e2e-bootstrap              # seed (also: just e2e-bootstrap --dry-run / --cleanup)
   ```

   About the password and its location:

   - **`/bunyip/e2e/test_user_password` is an Infisical SECRET PATH, not a
     filesystem path.** It is a logical folder + key inside the Infisical
     secrets manager (project -> environment -> folder `/bunyip/e2e` -> key
     `test_user_password`), reached via the Infisical CLI / API / web UI scoped
     to the bunyip project + `staging` env. It is NOT a directory on disk (it is
     unrelated to anything under `/srv/.../bunyip-api/`), so "the directory does
     not exist" is expected and irrelevant.
   - **Nothing creates it for you.** bunyip's core (Group-1) application secrets
     are rendered from the Infisical folder `/bunyip/app` by
     `scripts/sync-secrets.nu` (`just sync-secrets`, see
     [`secrets-infisical.md`](secrets-infisical.md)); the Group-2 runtime-fetch
     secrets live in a third sibling folder `/bunyip/runtime`. This E2E password
     lives in the folder `/bunyip/e2e` and is deliberately outside the sync
     table, so it is provisioned by hand. Moving the c-01 deployment's own secret
     source off sops (`compose-secrets.yml`) and the Forgejo Actions CI secrets
     onto Infisical is
     [BUNYIP-505](https://niceguyit.myjetbrains.com/youtrack/issue/BUNYIP-505).
     The value is the shared password the bootstrap hashes onto BOTH
     accounts, so you CHOOSE it: pick a strong password, seed with it, then store
     it (at that Infisical path and/or your team secret store) AND as the
     `E2E_STAGING_PASSWORD` CI secret in step 5, so the suite logs in with the
     same value.
   - **No infisical CLI on the host?** Read it from the Infisical web UI
     (project -> `/bunyip/e2e` -> `test_user_password` -> reveal) and set
     `$env.BUNYIP_E2E_TEST_USER_PASSWORD = "..."`. Avoid putting the literal in
     shell history / argv; the `$(... --plain)` / signal-via-env forms keep it
     out.
   - The bunyip-repo `just e2e-bootstrap` is DEV-ONLY (it `cargo run`s the seeder
     in a source-mounted container); c-01 runs the deployed image, so use the
     docker-repo recipe above.

   Record the **tenant UUID**, the **email**, and the **password**.

3. **Enroll 2FA on the E2E account(s)** (BUNYIP-152). The suite logs in with 2FA
   on, so this is required, not optional. Preferred (BUNYIP-359): let the
   bootstrap enroll a PRESET secret so it survives re-seeds without rotating the
   Forgejo secret. Choose a base32 secret, then in the api container run
   `BUNYIP_E2E_TOTP_SECRET=<base32> just e2e-bootstrap --enable-2fa` (needs the
   same `APP_ENCRYPTION_KEY` the API uses, which the container already has); set
   `E2E_STAGING_TOTP_SECRET` to that same base32. Manual alternative: log into the
   staging hub as the E2E user, go to `/settings/2fa/setup`, capture the base32
   secret shown at enrollment, verify a code, and record it - but this mints a NEW
   secret each time, so you must re-capture it after every account re-seed.

4. **Pick a public PKCE OIDC client.** There is NO `bunyip-web` OIDC client to
   reuse: bunyip-web is the OP's own hub UI (it sets `bunyip_op_session`
   directly), not a registered relying party. bunyip's OIDC clients are seeded
   by migrations (there is no `clients register` CLI). For staging, **reuse the
   existing `mokosh-apps` public PKCE client** (migration
   `20260603000010_register_mokosh_apps_and_drillmark_oidc_clients.sql`): it is
   already `client_type=public`, `require_pkce=true`, `token_endpoint_auth_method=none`,
   with `allowed_scopes` covering `openid email offline_access` (the set the
   suite requests, `offline_access` for the refresh leg). No registration,
   migration, or deploy needed.

   ```
   E2E_STAGING_OIDC_CLIENT_ID    = b0000000-0000-4000-8000-000000000002
   E2E_STAGING_OIDC_REDIRECT_URI = https://msp.a8n.systems/auth/callback
   ```

   The redirect_uri must match a registered value EXACTLY or `/oauth2/authorize`
   returns `invalid_redirect_uri`, but the request-context specs never load it -
   they read the `code` straight from the redirect `Location` (`maxRedirects: 0`),
   so reusing mokosh's host is fine. The client's `audience` is mokosh's API,
   which is also fine: the OIDC specs only call the OP's own `/oauth2/userinfo`
   with the token, never bunyip `/v1` (that bearer comes from the hub-login
   cookie capture). `global.setup` drives the consent Allow for this
   `(user, client)` pair, so the token-flow specs get a `code` rather than
   bouncing to `/oauth2/consent` (the gate that broke mokosh's headless replay -
   BUNYIP-146).

   `global.setup` is the ONE place a real browser follows that redirect and
   renders mokosh's callback, and rendering it killed the browser in run #2175:
   the next `storageState` call failed with the BUNYIP-148 "Target page, context
   or browser has been closed" signature and took setup, plus all 11 dependent
   specs, down with it. Two guards (BUNYIP-402): the consent drive runs on a
   throwaway page in the same context, so a renderer death on the callback cannot
   reach the page whose session setup persists (cookies are context-scoped, so
   the grant still lands); and the post-consent re-save is wrapped, since both
   artifacts are already written before consent. Stubbing the callback with
   `page.route` does NOT work - Playwright 1.60 applies route handlers only to
   the request that starts a chain, not to the target of a server redirect.

   Sanity-check the row is on the target DB:
   `docker compose ... exec postgres psql -c "select client_id, name, allowed_scopes from oauth_clients where name = 'mokosh-apps';"`

   Production is separate: the seed migration hardcodes `msp.a8n.systems`, so for
   a prod run reuse the prod-seeded client values or register a dedicated client
   via a migration. If you ever want isolation on staging too (own redirect on
   `a8n.systems`, bunyip audience, decoupled from mokosh-apps), register a
   dedicated E2E client via a migration - cleaner long-term, not needed to go
   green now.

5. **Set the Forgejo Actions secrets** (staging shown; add the `E2E_PRODUCTION_*`
   / `OIDC_ISSUER_PRODUCTION` set when provisioning prod):

   ```
   E2E_STAGING_BASE_URL          = https://a8n.systems
   OIDC_ISSUER_STAGING           = https://api.a8n.systems
   E2E_STAGING_EMAIL             = e2e-user@a8n.run
   E2E_STAGING_PASSWORD          = <step 2>
   E2E_STAGING_TENANT_ID         = <tenant UUID, step 2>
   E2E_STAGING_OIDC_CLIENT_ID    = <step 4>
   E2E_STAGING_OIDC_REDIRECT_URI = <step 4>
   E2E_STAGING_TOTP_SECRET       = <base32, step 3>
   # optional, teardown-only, once BUNYIP-151 lands:
   E2E_STAGING_STRIPE_SECRET_KEY = sk_test_...
   ```

6. **Enforce the check.** Forgejo -> repo Settings -> Branch protection on `main`
   -> add `e2e-pr` to the required status checks (not `e2e`: since BUNYIP-425 the
   suite does not run on `pull_request`, so it never reports a PR status). The
   suite itself is a post-merge signal: a push to `main` turns the run red after
   the fact.

7. **Verify.** Open a PR and watch the `e2e-pr` gate pass, then push to `main`
   and watch the `e2e` job run the runnable specs against staging. Locally:
   `cp e2e/.env.example e2e/.env`, fill the same values, then
   `cd e2e && npm ci && npx playwright install chromium && just e2e`.

After this the **runnable** specs pass. The `test.fixme` specs unblock as their
sub-tasks land: BUNYIP-150 (staging mail sink -> signup / password-reset /
magic-link / change-email), BUNYIP-151 (staging Stripe test mode -> billing),
BUNYIP-152 (the 2FA enrollment in step 3 -> two-factor). BUNYIP-149 (bunyip-web
`/healthz`) is for a future web reachability gate, not a spec blocker.

## Deploy gating: the gate scripts

A PR's or push's SHA only matters if staging is actually serving it, so each CI
trigger runs a pre-flight gate before the Playwright suite.

- **`scripts/wait-for-deploy.mjs`** (deploy-sync gate). Polls
  `GET <api>/v1/version` every 15s for up to 10 minutes and compares the
  reported `.commit` short git hash against the commit CI expects staging to be
  serving. Because the OCI image build only fires on a fixed set of paths
  (`src/`, `crates/`, `migrations/`, `Cargo.toml`, etc; keep `BUILD_TRIGGER_PATHS`
  in lock-step with `build-api.yml`'s `on.push.paths`), a docs/CI-only commit
  never republishes the image; the script walks `git log` back to the last
  build-relevant commit and polls for THAT hash instead, so it never times out
  on a SHA staging can never report. On an unrecoverable clone (filtered/shallow
  runner checkout it cannot self-heal) it warns and skips rather than blocking.
  Endpoint: `GET /v1/version` (field `.commit`).
- **`scripts/health-check.mjs`** (reachability gate). One-shot `GET /health`
  with a 30s timeout. A PR's SHA never deploys to staging, so the version-SHA
  gate would always time out for PRs; this just confirms staging is up and the
  suite has something to talk to. The Playwright suite is the actual coverage
  gate. Endpoint: `GET /health`.
- **`scripts/check-bootstrapped.mjs`** (E2E seed readiness, BUNYIP-163). After
  the reachability/deploy gate, probes `GET <api>/e2e-bootstrapped` (15s) and
  writes `bootstrapped=<bool>` to `$GITHUB_OUTPUT`. The bunyip-api endpoint
  returns `{ "bootstrapped": <bool> }` - true iff both seeded accounts
  (`e2e-user@a8n.run` / `e2e-admin@a8n.run`) exist with `deleted_at IS NULL`
  (one indexed count, unauthenticated, always `false` on a production
  `ENVIRONMENT`). e2e.yml gates the "Run E2E suite" step on this output: when
  staging is NOT bootstrapped the suite is skipped and **the job still
  succeeds**. The script fail-opens (any error -> `bootstrapped=false`,
  exit 0), so the gate never blocks. A production dispatch ignores the flag
  (prod is reachability-only). Endpoint: `GET /e2e-bootstrapped`. Re-seed with
  `just e2e-bootstrap`.

All three derive the API host the same way `lib/env.ts` does (explicit
`E2E_API_BASE_URL`, else prepend `api.` to `E2E_BASE_URL`) and treat an empty
secret string as unset.

## CI workflow

Two workflows, split by whether the run may hold credentials (BUNYIP-425).
`.forgejo/workflows/e2e.yml` is the suite and never triggers on
`pull_request`; `.forgejo/workflows/e2e-pr.yml` is the PR gate and holds no
credential. The suite is serialised through a single concurrency group (it
shares one account, and the 5/min login limit means parallel runs would
collide); the PR gate has its own cancel-in-progress group because it never
logs in.

| Workflow | Trigger | Environment | Purpose | Pre-flight gate |
| --- | --- | --- | --- | --- |
| `e2e.yml` | `push` to `main` | staging | post-merge validation against the deployed commit | `wait-for-deploy.mjs` (`/v1/version` `.commit`, poll 15s / 10-min timeout; walks back to the last build-relevant commit on a doc/CI-only merge) |
| `e2e.yml` | `workflow_dispatch` | input (`staging` default / `production`) | manual ad-hoc, and the only way to run the full suite against a PR's code (a maintainer dispatches it after reading the diff) | `staging`: deploy-sync gate; `production`: reachability check (the dispatched SHA is unlikely to be what prod serves) |
| `e2e-pr.yml` | `pull_request` -> `main` | staging URLs only | merge gate: lockfile installs, Playwright installs, staging is reachable. Does NOT run the specs | `health-check.mjs` (`/health`, one-shot 30s, hub probe soft) |

**Why the PR gate runs no specs.** A `pull_request` run executes the workflow
file, the npm lifecycle scripts and the Playwright specs from the PR head, all
of it unreviewed. Every secret in scope for that job is readable by anyone who
can push a branch, so the PR job declares only `E2E_STAGING_BASE_URL` and
`OIDC_ISSUER_STAGING` (which authenticate nothing) and every `npm ci` in
`.forgejo/workflows/` runs `--ignore-scripts`.
`scripts/check-workflow-secrets.nu` enforces both in the `Check` workflow, so
the split cannot regress silently.

**Production safety gate.** Production runs ONLY via manual dispatch. On top of
that, the billing WRITE specs carry `test.skip(env.isProductionApex, ...)` so
even a production dispatch cannot start or touch a live subscription. That guard
is independent of the `test.fixme` blockers and stays after they lift.

**Bootstrap skip (BUNYIP-163).** After the pre-flight gate,
`check-bootstrapped.mjs` decides whether the suite runs: on a staging run the
Playwright suite executes only when `GET /e2e-bootstrapped` reports the seed is
present; otherwise it is skipped and the job still passes. A missing or removed
seed degrades to "no coverage this run", never a hard failure, including for the
PR that might re-enable bootstrapping.

**Required status check (BUNYIP-425).** The `e2e` job no longer runs on
`pull_request`, so it can no longer be a required check on `main`: requiring a
job that never reports would block every PR. The PR-side required check is
`e2e-pr` instead. Updating branch protection (drop `e2e`, add `e2e-pr` to the
required status checks for `main`) is a one-time Forgejo change, done out of
band.

**Runtime + artifacts.** Each run installs Node + Chromium, runs the gate, then
the Playwright suite against the selected deployment. On failure it uploads
`playwright-report/` and `test-results/` (traces on first retry, screenshots +
video on failure, per `playwright.config.ts`) as job artifacts. The suite is
serial with `retries: 2` on CI, so wall time is dominated by the deploy-sync
gate's worst case (up to 10 min) plus the serial spec run.

## Adding a new spec

1. **Pick the project** by auth need, and put the file in the directory that
   project's `testMatch` globs:
   - browser, must log in itself, ANONYMOUS -> `tests/auth/` (`auth-ui`). Keep
     login-bearing specs minimal: every `loginViaHub` spends the 5/min limit.
   - browser, ALREADY authenticated (no `loginViaHub`) -> `tests/account/`,
     `tests/memberships/`, or `tests/billing/` (`account-ui`). Use `page.request`
     for API calls so the session cookies authenticate them.
   - request-context (bearer or replayed OP cookies) -> `tests/oidc/` (`api`),
     importing `test`/`oidcTest` from `../../lib/fixtures`.
2. **Import from `../../lib/...`** (specs live one directory deep). Do not
   duplicate route strings, PKCE, login, env access, or tagging - reuse `lib`.
3. **Stay non-destructive against the shared account.** Mutations that change
   credentials, revoke the active session, or leave untracked residue must
   instead be `test.fixme` with the blocker cited inline, OR target a disposable
   account once one exists. Name created records via `factories.tagged()` so
   teardown's sweep reaps them.
4. **Cite blockers.** Every `test.fixme` names BUNYIP-150/151/152 or the
   suite-design reason inline. Billing write specs also add
   `test.skip(env.isProductionApex, ...)`.
5. **Register the route** in `lib/api.ts` if it is a new `/v1` or OP path, rather
   than hardcoding the string in the spec.
