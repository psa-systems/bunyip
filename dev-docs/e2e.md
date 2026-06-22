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
    health-check.mjs          reachability gate (pull_request/dispatch-production)
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
own `OIDC_ISSUER_*` variable name where one exists. On `push` / `pull_request`
the `inputs` context is empty, so each expression resolves to its staging
secret; a manual dispatch lets the operator pick.

### Provisioning the E2E account + tenant

- **Staging:** use the `bunyip-e2e-bootstrap` binary (idempotent), driven by
  `just e2e-bootstrap` (runs `cargo run --bin bunyip-e2e-bootstrap` inside the
  api container against the staging database; requires
  `BUNYIP_E2E_BOOTSTRAP_ALLOW=true` and `BUNYIP_E2E_TEST_USER_PASSWORD` in the
  container env). It seeds the dedicated E2E account(s) + tenant. Pass-through
  flags exist (`--dry-run`, `--cleanup`). Record the resulting `E2E_EMAIL`,
  `E2E_PASSWORD`, `E2E_TENANT_ID`. Enable 2FA on the account and save the base32
  secret as `E2E_TOTP_SECRET`.
- **Production:** provisioned manually (the bootstrap binary is gated to
  non-production by design). Create the account + tenant by hand, enable 2FA,
  and record the same vars under the `E2E_PRODUCTION_*` secret names.
- **OIDC client:** register a public PKCE client (or reuse the staging app
  client) with a redirect_uri that allows capture-only. Record
  `E2E_OIDC_CLIENT_ID` and the exact registered `E2E_OIDC_REDIRECT_URI`. A
  mismatch makes `/oauth2/authorize` return `invalid_redirect_uri`. If authorize
  bounces the E2E session to `/login` (no code), the OP-session cookie scoping
  is wrong (COOKIE_DOMAIN vs the OP host); see BUNYIP-146.

**Rotation source (record per secret).** So each value can be rotated later,
document where it is generated, per environment: the Forgejo Actions secret
store entry itself; the E2E tenant + account (`*_EMAIL` / `*_PASSWORD` /
`*_TENANT_ID`, from bootstrap/manual provisioning); the OIDC client registration
(`*_OIDC_CLIENT_ID` / `*_OIDC_REDIRECT_URI`); and the TOTP enrollment
(`*_TOTP_SECRET`). Keep this here or in the team secret runbook.

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

Both derive the API host the same way `lib/env.ts` does (explicit
`E2E_API_BASE_URL`, else prepend `api.` to `E2E_BASE_URL`) and treat an empty
secret string as unset.

## CI workflow

`.forgejo/workflows/e2e.yml` runs on three triggers, serialised through a single
concurrency group (the suite shares one account and the 5/min login limit means
parallel runs would collide):

| Trigger | Environment | Purpose | Pre-flight gate |
| --- | --- | --- | --- |
| `push` to `main` | staging | post-merge validation against the deployed commit | `wait-for-deploy.mjs` (`/v1/version` `.commit`, poll 15s / 10-min timeout; walks back to the last build-relevant commit on a doc/CI-only merge) |
| `pull_request` -> `main` | staging | merge gate: every PR passes the suite vs staging | `health-check.mjs` (`/health`, one-shot 30s) |
| `workflow_dispatch` | input (`staging` default / `production`) | manual ad-hoc | `staging`: deploy-sync gate; `production`: reachability check (the dispatched SHA is unlikely to be what prod serves) |

**Production safety gate.** Production runs ONLY via manual dispatch. On top of
that, the billing WRITE specs carry `test.skip(env.isProductionApex, ...)` so
even a production dispatch cannot start or touch a live subscription. That guard
is independent of the `test.fixme` blockers and stays after they lift.

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
