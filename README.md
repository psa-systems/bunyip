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
