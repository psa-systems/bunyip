# Getting started with Bunyip

This guide covers the developer fast path: clone, run, sign in, click around. Self-hosting instructions live in [self-hosting.md](self-hosting.md).

## Prerequisites

- Docker + Docker Compose v2 (the modern `docker compose` plugin, not the legacy `docker-compose` binary).
- [`just`](https://github.com/casey/just) for the task runner.
- [Nushell `0.112.2`](https://www.nushell.sh/) (used by several `just` recipes, by every script under `scripts/` including the CI guards, and by every `run:` step in `.forgejo/workflows/`).
- No `infisical` CLI is needed. Group-1 secrets are files (`just init-secrets` generates dev throwaways; deployments supply them via the SOPS `compose-secrets.yml`), and the Group-2 integration secrets come from the store `SECRETS_STORAGE` declares (`database` in dev, so they are entered on the admin pages). See [application secrets](secrets-infisical.md).
- The `common` submodule ([psa-systems/common](https://dev.a8n.run/psa-systems/common)), which the root `justfile` imports the shared hook, tree-ownership and release recipes from. Clone with `git clone --recurse-submodules`, or run `git submodule update --init` in an existing clone; without it every `just` command fails to parse.
- No host-side Rust toolchain. All cargo work happens inside the dev container. The one exception is `just create-release`, whose `Cargo.lock` sync shells out to host `cargo` (BUNYIP-629); cut releases from a box that has a toolchain.
- A copy of `.env.example` -> `.env` if you're going to run the SSO overlay (`just dev-sso`). The plain `just dev` recipe does not require a real mokosh-server.

## Run the dev stack

```nu
just dev
```

This brings up two app containers (`dev-bunyip-api-${USER}`, `dev-bunyip-web-${USER}`) plus PostgreSQL on a private network (`dev-bunyip-private-${USER}`). The `${USER}` postfix lets multiple developers share a host without name collisions.

Then visit:

- Front-end: <http://localhost:4400>
- API health: <http://localhost:4401/health>
- OIDC discovery: <http://localhost:4401/.well-known/openid-configuration>

## Sign in

`bunyip-api` is the real backend: PostgreSQL persistence, real password and TOTP crypto, and its own OIDC issuer. There is no mock mode.

**As the default admin.** On first start, when no admin exists, `bunyip-api` creates one from `SETUP_DEFAULT_ADMIN` (`email:password`). The `.env.example` default is `admin@bunyip.local` / `ChangeMeBunyip2026`. Open <http://localhost:4400/login> and sign in with those.

**As a new signup.** Email sending is off in dev (`EMAIL_ENABLED=false`), so the magic link is not delivered. Set `EMAIL_LOG_TOKENS=true` in your `.env` (it logs the full link at DEBUG, and is forced off in production), restart, then:

1. Open <http://localhost:4400/signup>, enter an email, submit.
2. Read the magic link from the api logs: `docker logs dev-bunyip-api-${USER}`, and open it.

After sign-in you land on `/dashboard`, the App Launcher. Tiles drive cross-app OIDC handoff; with no other apps deployed in dev there is nothing to launch.

## SSO and Google sign-in (overlay)

To exercise SSO end to end, bunyip runs behind Traefik with TLS against the other repos in the stack:

```nu
just dev-sso
```

This is a cross-repo setup (bunyip + mokosh-server + mokosh-apps) with its own Nebula topology, OIDC client registration (`just register-dev-clients`), and certificate requirements. The authoritative, step-by-step guide - including the Google sign-in path and every spin-up obstacle - is [dev-sso-three-repo-runbook.md](dev-sso-three-repo-runbook.md). Read it before touching dev-sso infra. Plain `just dev` needs none of it.

## Cross-project domain layout

Staging runs on `a8n.systems`, production on `psa.systems`. In both, `bunyip-web` serves the apex and `bunyip-api` serves `api.<host>`. `bunyip-api` is bunyip's OIDC issuer (`/.well-known/*`, `/oauth2/*`): it signs users in and issues tokens to the apps bunyip fronts. The full three-repo layout (bunyip, mokosh-server, mokosh-apps) and how the pieces wire together is in [dev-sso-three-repo-runbook.md](dev-sso-three-repo-runbook.md).

## Common commands

```nu
just dev               # bring up the dev stack
just dev-stop          # stop it
just dev-clean         # stop + drop volumes (fresh state)
just dev-sso           # SSO overlay (real mokosh-server target)
just dev-logs          # tail the container logs
just check-container   # fmt + clippy + workspace tests, inside the pinned builder (no host toolchain)
just install-hooks     # write the git pre-commit hook (once per fresh clone)
just pre-commit        # what the hook runs: fmt + clippy + build + tests in the dev `api` container
just create-release minor   # bump the workspace version, branch, push, open the release PR
```

`install-hooks`, `pre-commit` and `create-release` come from the `common` submodule and are configured by the variables at the top of the root `justfile`; never copy one back into the justfile, `just check-justfile` fails the hook and CI when a shared recipe is shadowed.

`just check` runs the fuller fmt + clippy + build + docker-builder-stage sequence, but it needs a host toolchain; on a toolchain-less dev box use `just check-container`. Never `cargo build` on the host.

## Where things live

- `bunyip-api/` - the actix-web backend and OIDC issuer. Owns `main.rs`, the wiring, and the migrations in `bunyip-api/migrations/` (they run on startup).
- `bunyip-web/` - the Axum server-rendered front-end (Maud + htmx), the browser-facing BFF. No SPA.
- `crates/bunyip-domain/` - models, repositories, services, the app `Config`, and the email templates.
- `crates/bunyip-oci/`, `crates/bunyip-oidc/` - the OCI-registry and OIDC / OAuth 2.1 verticals.
- `compose.yml` - the production / self-host reference deployment (pulls the published images).
- `compose.dev.yml` - the dev stack (builds from source).
- `compose.dev-sso.yml` - the overlay for testing SSO against a real mokosh-server.
- `docs/` - this folder; developer and operator documentation.

## When something does not work

1. `just dev-stop && just dev` - most dev hiccups clear with a stack restart.
2. `just dev-clean && just dev` - resets volumes (use when the database or auth state is wedged).
3. Check `docker logs dev-bunyip-api-${USER}` for backend errors.
4. Check the browser dev-tools network panel for `4xx` / `5xx` from `/v1/auth/*`.
5. Confirm your `.env` (if using the SSO overlay) matches the mokosh-server it points at.

## Next steps

- Configuration reference (every variable): [configuration.md](configuration.md).
- Self-hosting the published images: [self-hosting.md](self-hosting.md).
- The three-repo SSO topology: [dev-sso-three-repo-runbook.md](dev-sso-three-repo-runbook.md).
- Repository conventions for AI agents: [`CLAUDE.md`](../CLAUDE.md).
