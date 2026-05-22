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

The Dioxus SPA resolves its backend at runtime as `msp-api.<window.location.host>` (see [`bunyip-web/src/stores/config.rs`](bunyip-web/src/stores/config.rs)). So a deployment needs two DNS names pointing at the host:

- `${BUNYIP_HOST}` - serves the SPA (e.g. `bunyip.example.com`)
- `msp-api.${BUNYIP_HOST}` - serves the API / OIDC issuer (e.g. `msp-api.bunyip.example.com`)

The edge Caddy ([`oci-build/Caddyfile`](oci-build/Caddyfile)) issues Let's Encrypt certs for both, proxying the apex to the `web` container and the `msp-api.` subdomain to the `api` container.

### Deploy

```nu
cp .env.example .env
# Edit .env: set BUNYIP_HOST, COOKIE_SECRET (48+ random chars), CADDY_ACME_EMAIL.
docker compose up --detach
```

Pin a specific release instead of `:latest` by setting `BUNYIP_API_IMAGE` / `BUNYIP_WEB_IMAGE` to a tagged image (e.g. `dev.a8n.run/psa-systems/bunyip-api:v0.2.0`).

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

- Work happens in `migrate/<short-descriptive-name>` branches.
- Merge target is `chore/initial-setup` (no `main` exists yet).
- Container naming follows `dev-bunyip-<service>-${USER}` and network `dev-bunyip-private-${USER}`.
