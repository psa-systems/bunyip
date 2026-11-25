# Getting started

For a deployment operator who wants to bring bunyip up quickly, sign in, and verify the OIDC OP answers. If you are running bunyip in production, read [Installation](installation.md) and [Configuration](configuration.md) after this page.

## What you need

- Docker and Docker Compose v2 (the modern `docker compose` plugin, not the legacy `docker-compose` binary).
- A copy of this repository, with the `common` submodule checked out: `git clone --recurse-submodules`, or run `git submodule update --init` in an existing clone.
- `just` installed on the host.
- Nushell `0.112.2` for the task recipes and scripts.

No host-side Rust toolchain is required. Builds happen inside containers.

## Bring up the dev stack

```
just dev
```

This starts `bunyip-api`, `bunyip-web` and PostgreSQL on a private per-developer network. The containers carry a `${USER}` suffix so multiple operators can share a host without name collisions. Mail is off by default; a magic link appears in the api log instead of being sent.

Three URLs to know:

- Front end: `http://localhost:4400`
- API health: `http://localhost:4401/health`
- OIDC discovery: `http://localhost:4401/.well-known/openid-configuration`

## Sign in the first time

On first boot, when no admin exists, `bunyip-api` seeds one from `SETUP_DEFAULT_ADMIN` (`email:password`). The development default in `.env.example` is `admin@bunyip.local` / `ChangeMeBunyip2026`. Open `http://localhost:4400/login` and sign in with those credentials.

For a sign-up flow (the normal path for a second operator), set `EMAIL_LOG_TOKENS=true` AND `RUST_LOG=info,bunyip_api=debug,bunyip_core=info,bunyip_domain=debug` in `.env` so the magic link is written to the log (the token-logging calls are at DEBUG in `bunyip_domain`, which the compose default `RUST_LOG` does not enable). Submit `http://localhost:4400/signup`, then read the link from `docker logs dev-bunyip-api-${USER}`.

After sign-in you land on `/dashboard`, the App Launcher. With no other apps deployed in dev there is nothing to launch; the launcher is the handoff surface to downstream RPs in production.

## Check the OIDC OP answers

Fetch discovery:

```
curl http://localhost:4401/.well-known/openid-configuration
```

The response names `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks` and the `grant_types_supported` list. If any of those endpoints return `404`, discovery was served but the routes under it were not mounted; this usually means the api container is still finishing migrations. Wait for `GET /health` to return `{"status":"ok"}` first.

## Next

- [Installation](installation.md) covers a production-shaped deployment: the two public hostnames, the OCI image pin, Group-1 secret files, Infisical for Group-2 secrets.
- [OIDC provider](oidc-provider.md) walks through adding your first downstream relying party.
- [Configuration](configuration.md) is the reference for every environment variable.
