# Bunyip

**The PSA Systems SaaS platform** - signup, subscription billing, platform admin, and an OpenID Connect provider for the Mokosh PSA product.

_Surfaces what matters._

<!--
BUNYIP-587 records the one-minute walkthrough GIF and drops it at docs/assets/bunyip-walkthrough.gif.
When it lands, replace this comment with:
![Bunyip walkthrough](docs/assets/bunyip-walkthrough.gif)
-->

## Try it

Live staging: **<https://a8n.systems>**. Sign up with a throwaway email and click through the product.

> Staging shows features **in development**, not a polished demo. State is **wiped on every deploy** - accounts, organizations, and data are throwaway. Do not reuse a real password.

## What it is

Two Rust services in one Cargo workspace:

- **bunyip-web** (port 4400) - the browser-facing front-end. Axum server-rendered HTML (Maud + htmx), no SPA. It is a BFF: it talks to bunyip-api over `/v1` and renders the pages.
- **bunyip-api** (port 4401) - the backend and the OIDC / OAuth 2.1 issuer (`/.well-known/*`, `/oauth2/*`). Real PostgreSQL persistence, at-rest encryption, Stripe billing, email.

Domain code lives in `crates/bunyip-{domain,oci,oidc}`; the generic, domain-free kernel is the `dunite-core` git dependency. Dependency direction is strictly downward: `bunyip-api -> bunyip-oci/oidc -> bunyip-domain -> dunite-core`.

## Run it locally

Requires Docker or Podman with Compose.

```nu
just dev
```

Then:

- Front-end: <http://localhost:4400>
- API health: <http://localhost:4401/health>
- OIDC discovery: <http://localhost:4401/.well-known/openid-configuration>

Full dev setup, including SSO against Mokosh, is in [docs/getting-started.md](docs/getting-started.md).

## Self-host

`compose.yml` is the reference deployment: the published `bunyip-api` and `bunyip-web` images plus PostgreSQL, behind a Traefik edge that terminates TLS. The two images are released as a matched pair and pinned together (`BUNYIP_API_IMAGE` / `BUNYIP_WEB_IMAGE`); startup secrets are files provided through the `{NAME}_FILE` convention, never plain environment variables.

The full self-host guide - topology, deploy, update checking, and applying updates - is in **[docs/self-hosting.md](docs/self-hosting.md)**.

- Every configuration variable and where its value comes from: [docs/configuration.md](docs/configuration.md)
- Secrets, the two-tier model, and Infisical: [docs/secrets-infisical.md](docs/secrets-infisical.md)

## Documentation

Operator and developer docs live in [`docs/`](docs/):

- [getting-started.md](docs/getting-started.md) - local dev stack and sign-in
- [configuration.md](docs/configuration.md) - the full environment-variable and in-app-settings reference
- [self-hosting.md](docs/self-hosting.md) - deploy, update, and run the released images
- [secrets-infisical.md](docs/secrets-infisical.md) - secret sourcing and rotation

Contributor-facing conventions for AI agents working in this repository are in [CLAUDE.md](CLAUDE.md).

## Contributing

- Work happens in `feat/` / `fix/` / `chore/<short-descriptive-name>` branches off `main`; the merge target is `main` via PR.
- `just check` runs fmt + clippy + build + the docker builder stage; dev boxes without a local Rust toolchain use `just check-container`.
- Dev container names follow `dev-bunyip-<service>-${USER}` on network `dev-bunyip-private-${USER}`; the production stack (`compose.yml`) drops the `dev-` prefix.
- Releases: `just create-release <major|minor|hotfix>` bumps the workspace version and opens a release PR; merging it tags `vX.Y.Z` and publishes the images (see [`.forgejo/workflows/create-release.yml`](.forgejo/workflows/create-release.yml)).
- CI reads a fixed set of repository-level Forgejo Actions secrets and variables; the authoritative list is in [`e2e/README.md`](e2e/README.md#forgejo-actions-secrets-and-variables), and values are never recorded in the repo.
