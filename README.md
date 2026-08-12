# bunyip

Bunyip (Australian folklore): A lake-dwelling cryptid of Aboriginal stories. Mascot: a shaggy creature with wide, friendly eyes peering through reeds. Tagline: Surfaces what matters.

Bunyip is the front-facing SaaS / business platform for the Mokosh PSA product. It owns marketing, signup, login (eventually via OIDC against Mokosh Server), organization onboarding, subscription billing UI, and platform admin.

## Status

Pre-MVP. The current iteration ships a fully-wired frontend backed by seeded JSON data; every interactive element works, but state mutations land in an in-memory mock store rather than a real database. Real backend functionality (auth crypto, OIDC issuance, Stripe, persistence) is post-MVP and will live in Mokosh Server, not in Bunyip.

See [`For AI/bunyip-mvp-plan.md`](For%20AI/bunyip-mvp-plan.md) for the full MVP scope and [`For AI/bunyip-progress.md`](For%20AI/bunyip-progress.md) for live progress.

## Architecture (target)

| Domain                | Service                                                              |
| --------------------- | -------------------------------------------------------------------- |
| `a8n.systems`         | Bunyip (this repo): SaaS / business / billing                        |
| `msp.a8n.systems`     | Mokosh Client: actual PSA application                                |
| `api.a8n.systems`     | Mokosh Server: headless API + OIDC issuer (post-MVP)                 |

Stack:

- Rust + Axum (thin backend; serves the SPA + mock JSON endpoints)
- Rust + Dioxus (frontend; no Node.js dev server)
- `parking_lot::RwLock` + JSON seeds for the in-memory mock store (MVP only; real persistence moves to Mokosh Server later)

## Quickstart (dev)

Requires Docker / Podman with Compose.

```nu
docker compose --file compose.dev.yml up --detach
```

Then visit:

- Frontend: <http://localhost:4400>
- API health: <http://localhost:8080/healthz>
- OIDC discovery: <http://localhost:8080/.well-known/openid-configuration>

State resets on container restart. This is intentional for the MVP demo loop.

## Self-host (production)

`compose.yml` is the reference deployment. It runs the published OCI images (no build-from-source) behind an edge Caddy that terminates TLS and routes traffic.

### Topology

The Dioxus SPA loads its OIDC config at runtime from a same-origin `/config.json` (see [OIDC runtime config](#oidc-runtime-config) below) and, when the issuer is left unset, derives it from the host as `msp-api.<window.location.host>` (see [`bunyip-web/src/stores/config.rs`](bunyip-web/src/stores/config.rs)). So a deployment needs two DNS names pointing at the host:

- `${BUNYIP_HOST}` - serves the SPA (e.g. `bunyip.example.com`)
- `msp-api.${BUNYIP_HOST}` - serves the API / OIDC issuer (e.g. `msp-api.bunyip.example.com`)

The edge Caddy ([`oci-build/Caddyfile`](oci-build/Caddyfile)) issues Let's Encrypt certs for both, proxying the apex to the `web` container and the `msp-api.` subdomain to the `api` container.

### OIDC runtime config

The `bunyip-web` SPA is environment-agnostic: one image serves any deployment. At container start its entrypoint ([`bunyip-web/oci-build/entrypoint.sh`](bunyip-web/oci-build/entrypoint.sh)) writes a same-origin `/config.json` from the container's environment, and Caddy serves it with `Cache-Control: no-store`. The SPA fetches it once at boot before any auth UI renders. Changing a value and restarting the container reconfigures OIDC with **no rebuild**.

Set these on the `web` service (all OIDC values are public by design - a public client + PKCE):

| Env var | Required | Fallback when unset |
| --- | --- | --- |
| `BUNYIP_OIDC_CLIENT_ID` | yes (for SSO) | none |
| `BUNYIP_OIDC_ISSUER` | no | host-derived `https://msp-api.<host>` |
| `BUNYIP_OIDC_REDIRECT_URI` | no | `<window.location.origin>/auth/callback` |
| `BUNYIP_OIDC_SCOPES` | no | `openid email offline_access` |

```json
// GET /config.json
{
  "issuer": "https://msp-api.bunyip.example.com",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "redirect_uri": "",
  "scopes": "openid email offline_access"
}
```

The `dx serve` dev loop (`just dev-sso`) runs a different dev server that cannot serve a root `/config.json`, so under hot-reload the SPA uses the host-derived issuer/redirect and does not receive `client_id`. For end-to-end SSO testing locally, run the production image.

### Deploy

The images live in the private `dev.a8n.run/psa-systems-private` registry, so authenticate before pulling:

```nu
docker login dev.a8n.run
cp .env.example .env
# Edit .env: set BUNYIP_HOST, COOKIE_SECRET (64+ random chars), CADDY_ACME_EMAIL.
just init-secrets            # or: just sync-secrets --env prod  (Infisical-backed hosts)
docker compose up --detach
```

Group-1 startup secrets are files, never environment variables: `compose.yml` mounts each one from `./secrets/<name>` at `/run/secrets/<name>` and the api reads it through the `{NAME}_FILE` convention, so `docker inspect` never shows a value. `just init-secrets` ([`scripts/init-secrets.nu`](scripts/init-secrets.nu)) generates them locally, which is the right choice for a self-host that keeps its own values. A deployment whose values live in Infisical runs `just sync-secrets` ([`scripts/sync-secrets.nu`](scripts/sync-secrets.nu)) instead: it renders the same files from the `/bunyip/app` folder, atomically and at mode 0400, and never becomes a runtime dependency of the containers. Group-2 integration secrets (SMTP first) are the exception: the app fetches them from Infisical at runtime (`/bunyip/runtime`), still gracefully so Infisical is never a boot dependency. Both tiers, the key-to-file mapping, source precedence, and the rotation flow are in [`docs/secrets-infisical.md`](docs/secrets-infisical.md).

bunyip-api and bunyip-web are released as a **matched pair**: both images carry the same workspace version and are promoted together. bunyip-web decodes bunyip-api's responses, so the two only interoperate across a bounded skew. Since BUNYIP-506 the response models tolerate one release of skew (an unknown field or enum value degrades to a neutral render instead of failing the decode), which is what makes a rolling restart safe; two or more releases apart is not supported, and a rename that has completed its expand/contract cycle will not decode. Bump `BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` to the same release tag in the same operator action.

`BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` are required (BUNYIP-237): compose refuses to start without them. Set both to a pinned release tag, e.g. `dev.a8n.run/psa-systems-private/bunyip-api:v0.4.1`. The previous `:latest` default could leave the LB serving two different builds during a rolling restart; pinning a release tag makes the deploy reproducible. Bump both vars on a deliberate operator action when promoting a new release.

### Update checking

The instance reports its version and whether a newer release is published:

```nu
http get https://msp-api.${BUNYIP_HOST}/version
```

```json
{
  "version": "0.1.0",
  "revision": "<git sha>",
  "update": {
    "enabled": true,
    "current": "0.1.0",
    "latest": "0.2.0",
    "update_available": true,
    "checked_at": "2026-05-22T12:00:00+00:00"
  }
}
```

The check polls `BUNYIP_UPDATE_CHECK_URL` (defaults to the public Forgejo `releases/latest` endpoint) at most once an hour and caches the result. Set the URL to an empty string to disable checking (`update.enabled` becomes `false`).

### Applying an update

Updates are never automatic; the operator decides when to apply one:

```nu
docker compose pull
docker compose up --detach
```

Pinned-tag deployments bump the tag in `.env` first, then run the same two commands.

### Architectures

Images publish for `linux/amd64` by default. To publish a multi-arch manifest, set the CI variable `BUNYIP_BUILD_PLATFORMS` to `linux/amd64,linux/arm64`. Both Dockerfiles are arch-portable; arm64 builds run under emulation unless a native arm64 runner is available.

### Without Docker (Linux x86_64)

Every release publishes binary tarballs to the `psa-systems-private/bunyip` [Generic Packages registry](https://dev.a8n.run/psa-systems-private/-/packages) (same org as the OCI images) for operators who want to run Bunyip without Docker:

- `bunyip-api-vX.Y.Z-x86_64-linux-musl.tar.gz` - statically-linked `bunyip-api` + `seeds/`. Runs on any Linux distribution (musl-static, no glibc dependency).
- `bunyip-web-vX.Y.Z-static.tar.gz` - the built `public/` directory (WASM bundle + assets). Serve with any static web server.
- `SHA256SUMS` - checksums for the two tarballs.

The registry is private, so download requires a Forgejo token with `read:package` scope (the same kind of token you already use for `docker login dev.a8n.run`):

```nu
let tag = "v0.1.1"
let base = $"https://dev.a8n.run/api/packages/psa-systems-private/generic/bunyip/($tag)"
let token = "<forgejo token, read:package scope>"
let auth = {Authorization: $"token ($token)"}
http get --headers $auth $"($base)/SHA256SUMS" | save SHA256SUMS
http get --headers $auth $"($base)/bunyip-api-($tag)-x86_64-linux-musl.tar.gz" | save $"bunyip-api-($tag)-x86_64-linux-musl.tar.gz"
http get --headers $auth $"($base)/bunyip-web-($tag)-static.tar.gz" | save $"bunyip-web-($tag)-static.tar.gz"
sha256sum --check SHA256SUMS
tar --extract --gzip --file $"bunyip-api-($tag)-x86_64-linux-musl.tar.gz"
tar --extract --gzip --file $"bunyip-web-($tag)-static.tar.gz"
```

Run the API directly; configure it with the same env vars used in `compose.yml` (`BUNYIP_PUBLIC_BASE_URL`, `COOKIE_SECRET`, `BUNYIP_SEEDS_DIR`, etc.):

```nu
cd $"bunyip-api-($tag)-x86_64-linux-musl"
$env.COOKIE_SECRET = "<64+ random chars>"
$env.BUNYIP_PUBLIC_BASE_URL = "https://bunyip.example.com"
$env.BUNYIP_SEEDS_DIR = "./seeds"
./bunyip-api
```

Serve the SPA bundle from any static host (Caddy, nginx, GitHub Pages, etc.). The entrypoint that writes `/config.json` from env is Docker-only, so for the binary path either set `BUNYIP_OIDC_*` via a hand-written `public/config.json` before serving, or rely on the host-derived defaults documented in [OIDC runtime config](#oidc-runtime-config).

Only `x86_64-linux-musl` ships today. ARM64 binaries are gated on the same native runner that gates multi-arch OCI images (see [Architectures](#architectures)).

## Seeded demo accounts

All accounts accept `MOCK_PASSWORD` (default `demo`). When MFA is enabled, TOTP step accepts `MOCK_TOTP_CODE` (default `000000`) or any 6-digit code.

| Email                       | Role           | Org membership                       | Subscription tier  | Purpose                       |
| --------------------------- | -------------- | ------------------------------------ | ------------------ | ----------------------------- |
| `admin@a8n.systems`         | platform admin | -                                    | -                  | Access to `/admin/*`          |
| `owner@example.com`         | member         | Owner of "Example MSP"               | early_adopter      | Primary demo account          |
| `pastdue@example.com`       | member         | Owner of "Acme Tech"                 | past_due           | Dunning banner demo           |
| `member@example.com`        | member         | Member of "Example MSP"              | inherits org tier  | Member-permission demo        |
| `lifetime@a8n.systems`      | member         | Owner of "Lifetime LLC"              | lifetime           | Lifetime-tier UI              |

## Documentation

Project context, plans, audits, and architecture decisions live in [`For AI/`](For%20AI/):

- [`bunyip-mvp-plan.md`](For%20AI/bunyip-mvp-plan.md) - approved MVP plan
- [`bunyip-progress.md`](For%20AI/bunyip-progress.md) - live progress tracker
- [`bunyip-mokosh-boundaries.md`](For%20AI/bunyip-mokosh-boundaries.md) - ownership map for the Bunyip / Mokosh split
- [`bunyip-mokosh-branch-audit.md`](For%20AI/bunyip-mokosh-branch-audit.md) - audit of Mokosh repo state and unmerged branches
- [`bunyip-component-harvest.md`](For%20AI/bunyip-component-harvest.md) - what to pull from neighboring repos
- [`bunyip-feature-sso-port-notes.md`](For%20AI/bunyip-feature-sso-port-notes.md) - integration map for the eventual `feature-sso` work
- [`bunyip-superprompt.md`](For%20AI/bunyip-superprompt.md) - the original product brief

## Contributing

- Work happens in `feat/` / `fix/` / `chore/<short-descriptive-name>` branches off `main`.
- Merge target is `main` (via PR).
- Dev container naming follows `dev-bunyip-<service>-${USER}` and network `dev-bunyip-private-${USER}`; the production stack (`compose.yml`) drops the `dev-` prefix.
- Releases: `just create-release <major|minor|hotfix>` bumps the workspace version and opens a release PR; merging it tags `vX.Y.Z` and publishes the images (see [`.forgejo/workflows/create-release.yml`](.forgejo/workflows/create-release.yml)).
- CI secrets + variables: the workflows under [`.forgejo/workflows/`](.forgejo/workflows/) read a fixed set of repository-level Forgejo Actions secrets and variables (the registry/release PAT, the runner label, and the staging/production E2E sets). The authoritative list of names and what each is for is in [`e2e/README.md`](e2e/README.md#forgejo-actions-secrets-and-variables); values are never recorded in the repo.
