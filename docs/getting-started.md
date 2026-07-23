# Getting started with Bunyip

This guide covers the developer fast path: clone, run, sign in, click around. Self-hosting instructions live in the README under "Self-host".

## Prerequisites

- Docker + Docker Compose v2 (the modern `docker compose` plugin, not the legacy `docker-compose` binary).
- [`just`](https://github.com/casey/just) for the task runner.
- [Nushell `0.112.2`](https://www.nushell.sh/) (used by several `just` recipes).
- No host-side Rust toolchain. All cargo work happens inside the dev container.
- A copy of `.env.example` -> `.env` if you're going to run the SSO overlay (`just dev-sso`). The plain `just dev` recipe does not require a real mokosh-server.

## Run the dev stack

```nu
just dev
```

This brings up two containers (`dev-bunyip-api-${USER}`, `dev-bunyip-web-${USER}`) and a private network (`dev-bunyip-private-${USER}`). The `${USER}` postfix lets multiple developers share a host without name collisions.

Then visit:

- Frontend: <http://localhost:4400>
- API health: <http://localhost:4401/healthz>
- OIDC discovery (against the mock backend, returns 404 in pure-mock mode): <http://localhost:4401/.well-known/openid-configuration>

## Sign in (mock backend)

Out of the box, `just dev` runs `bunyip-api` in mock mode. It serves seeded JSON from `seeds/` and accepts a fixed mock password.

1. Open <http://localhost:4400/signup>, enter any email, click "Send link". You'll see "Check your email" - the mock backend skips actual email delivery and treats the next visit to `/signup/<token>` as the next step (link printed in the api container logs).
2. Or skip signup: open <http://localhost:4400/login>, enter any seeded email (see `seeds/users.json`) and the password `demo` (default; configurable via `MOCK_PASSWORD` env). MFA prompt uses `000000` as the code (configurable via `MOCK_TOTP_CODE` env).
3. After sign-in you land on `/dashboard` - the App Launcher. Tiles drive cross-app OIDC handoff, but with no other apps deployed in dev there's nothing to launch.

## Sign in with SSO (overlay)

If you want bunyip to talk to a real mokosh-server (running locally or behind Traefik), use the `compose.dev-sso.yml` overlay:

```nu
just dev-sso
```

This requires:

1. A mokosh-server reachable at the `BUNYIP_OIDC_ISSUER` URL in your `.env`.
2. A registered OAuth client UUID at `BUNYIP_OIDC_CLIENT_ID` (run `just register-bunyip-client` inside mokosh-server's repo, paste the UUID into bunyip's `.env`).
3. A `BUNYIP_OIDC_REDIRECT_URI` matching the client's registered redirect URI (typically `https://${USER}-bunyip.a8n.run/auth/callback`).

The SSO overlay routes via Traefik with TLS, which is why it needs a real hostname + cert. Plain `just dev` does not.

## Sign in with Google

The login page has a "Continue with Google" button (visible when `BUNYIP_OIDC_ISSUER` is set). It triggers the existing PKCE OIDC flow against mokosh-server with `&idp_hint=google` appended. Mokosh-server's IdP UI decides whether to honor the hint (skip its chooser and go straight to Google) or render the chooser. Either way, end-to-end auth uses the same OIDC code-exchange flow.

For this to work end to end you need:

- mokosh-server's Google OAuth client configured with the right redirect URIs (see `mokosh-server/docs/dev-docs/CHANGELOG.md`).
- The bunyip OAuth client (in mokosh_auth.oauth_clients) registered with `<bunyip-origin>/auth/callback`.

## Cross-project domain layout

Once cutover lands at psa.systems (see [PSA-7](https://niceguyit.myjetbrains.com/youtrack/issue/PSA-7)):

| URL | Service | Notes |
|-----|---------|-------|
| `https://psa.systems` | bunyip-web | SaaS shell / marketing / account mgmt |
| `https://psa.systems/api/*` | bunyip-api | mock backend (M1) |
| `https://msp.psa.systems` | mokosh-clients | actual PSA application |
| `https://msp-api.psa.systems` | mokosh-server | real backend + OIDC issuer |

Staging mirrors this layout on `a8n.systems`. The wildcard certs (`*.a8n.systems`, `*.psa.systems`) are already in Cloudflare.

## Common commands

```nu
just dev               # bring up the dev stack
just dev-down          # stop it
just dev-clean         # stop + drop volumes (fresh state)
just dev-sso           # SSO overlay (real mokosh-server target)
just check             # cargo fmt --check + clippy + check + tests
just fmt               # cargo fmt --all
just create-release minor   # bump Cargo.toml, branch, push, print PR URL
```

All cargo runs inside the dev container; never `cargo build` on the host.

## Where things live

- `bunyip-api/` - Axum mock backend (no DB; reads JSON from `seeds/`).
- `bunyip-web/` - Dioxus WASM SPA served by Caddy in production.
- `crates/bunyip-mocks/` - shared mock-data types between api + web.
- `seeds/` - JSON fixtures the api serves and the web SPA mirrors for fallback rendering.
- `compose.yml` - production / self-host reference deployment (pulls published images).
- `compose.dev.yml` - dev stack (bind-mount source, cargo watch / dx serve).
- `compose.dev-sso.yml` - overlay for testing against a real mokosh-server.
- `docs/dev-docs/CHANGELOG.md` - the May 15 snapshot of M1 architecture + open asks.
- `For AI/` - gitignored AI working context; not part of the codebase.
- `docs/` - this folder; user / operator documentation.

## When something does not work

1. `just dev-down && just dev` - 90% of dev hiccups clear with a stack restart.
2. `just dev-clean && just dev` - resets volumes (use when seeds change or the auth state is wedged).
3. Check `docker logs dev-bunyip-api-${USER}` for backend errors.
4. Check the browser dev tools network panel for `4xx` / `5xx` from `/v1/auth/*`.
5. Confirm your `.env` (if using SSO overlay) matches the mokosh-server it points at.

## Next steps

- For the M1 architecture deep dive: `docs/dev-docs/CHANGELOG.md`.
- For the bunyip / mokosh ownership split: `For AI/bunyip-mokosh-boundaries.md` (local-only).
- For deployment / self-host: README "Self-host" section.
- For YouTrack tickets: filter by Milestone 1 in the PSA Systems project, or look at [PSA-1](https://niceguyit.myjetbrains.com/youtrack/issue/PSA-1).
