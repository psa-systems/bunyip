# CLAUDE.md

Guidance for AI agents working in this repository.

## What this is

bunyip is the PSA Systems SaaS platform: a Cargo **workspace** with two server
apps plus the domain it owns.

```
bunyip/
├── bunyip-web/             bunyip-web - Axum SSR frontend (Maud + htmx). The browser-facing BFF.
├── bunyip-api/             bunyip-api - actix-web backend binary (wiring + main.rs + migrations).
└── crates/
    ├── bunyip-domain         models, repositories, business services, app Config, email templates.
    ├── bunyip-oci          OCI registry vertical.        (depends on bunyip-domain)
    ├── bunyip-oidc         OIDC / OAuth 2.1 vertical.    (depends on bunyip-domain)
    └── web-kit             branding-free SSR building blocks (Maud + htmx), shared with other front-ends.
```

bunyip **owns all domain-specific code**. The generic, domain-free kernel
(errors, responses, validation, request_id/security_headers middleware, and the
generic jwt/encryption/password services) is `dunite-core`, consumed as a
**git dependency** from the Forgejo repo
`https://dev.a8n.run/psa-systems/dunite`. The dunite repo is anonymously
readable, so builds need no token (an optional `DUNITE_GIT_TOKEN` / buildkit
secret `dunite_token` is honoured for mirrors that require auth). Nothing in
dunite is bunyip-specific; nothing domain-specific lives in dunite.

All four dunite crates are pinned by `rev` (not `branch = "main"`), so moving
bunyip onto a newer dunite is an explicit one-line manifest diff in a bunyip PR
rather than a silent lockfile change (BUNYIP-426 F6). Bumping means editing the
`rev` in `crates/bunyip-{domain,oci,oidc}/Cargo.toml` and re-running
`cargo update --package dunite-core --package dunite-download --package dunite-oci --package dunite-oidc`.

Dependency direction (strictly downward): `bunyip-api -> bunyip-oci/oidc -> bunyip-domain -> dunite-core (git)`. `bunyip-web` is a standalone binary (talks to bunyip-api over /v1).

Ports: bunyip-api listens on `APP_PORT=4401`; bunyip-web on `4400`. bunyip-api
is also bunyip's OIDC issuer (it serves `/.well-known/*` + `/oauth2/*`).

## Build / dev

`just` drives everything (see `justfile`):

- `just dev` / `just dev-detach` - full local stack (postgres + api + web) via `compose.dev.yml`.
- `just dev-sso` - Traefik-routed stack on `*.a8n.run` (layers `compose.dev-sso.yml` on top). Cross-repo (bunyip + mokosh-server + mokosh-apps), Nebula topology, OIDC client registration, and every spin-up obstacle are documented in `docs/dev-sso-three-repo-runbook.md` - read it before touching dev-sso infra or onboarding a dev box.
- `just check` - fmt + clippy + build + docker builder stage. `just test`, `just typecheck`, `just lint`, `just fmt`.
- `just build-docker` - both production images (`build-docker-export` extracts the api static binary). `just migrate` / `migrate-revert`.
- `just create-release <major|minor|hotfix>` - bump `[workspace.package].version`, push the branch, open the release PR.
  Comes from `common.just`; `release_layout := "virtual-workspace"` in the root justfile is what selects the `[workspace.package]` bump and the `cargo update --workspace --offline` lock sync (workspace-scoped, so external dependencies including the dunite git dep are left where they are, per BUNYIP-426 F6).
  That `cargo` call runs on the HOST, so unlike the recipe it replaced it needs a host toolchain; moving it back into a container is BUNYIP-629.

Production runs the published images via `compose.yml` (api + web + postgres,
images under `dev.a8n.run/psa-systems-private/{bunyip-api,bunyip-web}`).

## The `common` submodule

The task runner's shared half is `psa-systems/common`, vendored as the `common`
submodule and imported by the root `justfile` (`import 'common/common.just'`).
It owns `pre-commit` and its two variants, `check-tree-ownership`,
`ensure-bind-sources`, `install-hooks`, `create-release` and its layout
variants, and `check-justfile`; the root justfile configures them through
variables (`app`, `compose_service`, `dev_bind_sources`, `pre_commit_prepare`,
`clippy_args`, `compile_args`, `test_args`, `release_layout`) and must never
redefine one. Two of those variables carry the `./secrets/oidc` bind source the
api service mounts. `dev_bind_sources := "secrets/oidc target bunyip-web/node_modules"`
is what stops the daemon materializing a path as root while it resolves a
mount, which `check-tree-ownership` then fails every commit in the clone on
(DEV-371): `secrets/oidc` is the api's bind source (BUNYIP-658), and `target`
and `bunyip-web/node_modules` are the mount points of the `cargo-target` and
`web-node-modules` named volumes that `compose.dev.yml` nests under the
`.:/app` bind (BUNYIP-659). `ensure-bind-sources` creates each host-owned and
repairs an empty root-owned one, and common runs it ahead of the prepare step
in both pre-commit variants.
`pre_commit_prepare := "ensure-oidc-keys"` then generates the Ed25519 keypair
into it on the host, the part that is bunyip-specific. `check-justfile` fails
the hook and the `Check` workflow when a common-owned recipe is redefined
locally, which is the whole point of adopting it: a forked recipe silently stops
receiving shared fixes. A fresh clone needs `git submodule update --init` or
the import is a parse error, and CI checks out with `submodules: true`. Bumping
common means updating the submodule and committing the new gitlink. The release
CI half is the same split: `.forgejo/workflows/create-release.yml` is a caller
stub for `psa-systems/common/.forgejo/workflows/create-release.yml@main`, which
builds the changelog with `git log --oneline --first-parent` (one line per
merged PR, not one per branch commit) and reads the org-level `FORGEJO_PAT`
through `secrets: inherit`. `.forgejo/workflows/check.yml` stays private: it
carries ~20 repo-specific guard steps (migrations, workflow shell and secrets,
serde compatibility, brand/price/copy/theme literals, CSS currency, cache
mounts and keys, publish triggers) plus the Nushell shell contract and the
api-image builder stage, none of which the reusable check workflow can express.

## Toolchain / checks on toolchain-less dev boxes

The canonical Rust toolchain is pinned in `rust-toolchain.toml` (currently
1.98.1, matching the `ghcr.io/niceguyit/rust-builder-*:*-rust1.98.1-*`
images and CI). Bumping it means fixing any newly-promoted clippy/rustfmt
lints in the same PR so `just check` stays green everywhere.

Dev boxes have **no local Rust toolchain**, so run `just check-container`. It
wraps fmt + clippy + workspace tests (`--all-targets`: unit, integration, and
doc tests) in the pinned rust-builder image with named cache volumes for the
cargo registry and target dir (so repeated runs stay incremental).

The image's rustup honours `rust-toolchain.toml`, so the pin (not the image
default) decides the compiler version. CI (`.forgejo/workflows/check.yml`)
runs the same fmt/clippy/build/test sequence on every PR and push to main.

## Critical conventions

A new convention adds one index line here and its full text in [`docs/invariants/`](docs/invariants/).

### Build, CI and repo tooling

- [sqlx](docs/invariants/build-ci.md#sqlx): Only bunyip-oidc uses `sqlx::query!`; build with `SQLX_OFFLINE=true` and commit a regenerated `.sqlx/`.
- [Migrations](docs/invariants/build-ci.md#migrations-bunyip-293) (BUNYIP-293): Committed migrations are immutable: fix forward with a new file, never edit one on `main`.
- [Images](docs/invariants/build-ci.md#images-bunyip-389-bunyip-558-bunyip-426-bunyip-534) (BUNYIP-389/558/426/534/519): Pinned per-binary cargo-chef images, locked cache mounts.
- [Workflow shell](docs/invariants/build-ci.md#workflow-shell-bunyip-489) (BUNYIP-489): Every workflow job runs `nu {0}` via `defaults.run.shell`; no Bash steps.
- [Scripts are Nushell](docs/invariants/build-ci.md#scripts-are-nushell-bunyip-490) (BUNYIP-490): Every `scripts/` file is a Nushell script; no `.sh` or POSIX shebang.
- [Conformance](docs/invariants/build-ci.md#conformance): Follow `../governance/`; version metadata is version + hash + date.
- [Forgejo org](docs/invariants/build-ci.md#forgejo-org): Repo lives in `psa-systems`; images publish to `psa-systems-private`.
- [No em-dashes](docs/invariants/build-ci.md#no-em-dashes): No em-dash in any output or artifact.

### Configuration, secrets and feature flags

- [Feature flags](docs/invariants/config.md#feature-flags-bunyip-493-bunyip-487) (BUNYIP-493, BUNYIP-487): Surface switches are `tier_config` columns; off means invisible.
- [At-rest encryption](docs/invariants/config.md#at-rest-encryption-bunyip-483-bunyip-491) (BUNYIP-483, BUNYIP-491): One `APP_ENCRYPTION_KEY` key set protects every encrypted column.
- [Startup config validation](docs/invariants/config.md#startup-config-validation-bunyip-537) (BUNYIP-537): Classify every env var in `ENV_INVENTORY`; report all failures, never `panic!`.
- [Configuration providers](docs/invariants/config.md#configuration-providers-bunyip-643-bunyip-537-bunyip-644) (BUNYIP-643/537/644/645): Resolve `database` > `file` > `environment` via `ConfigStack`.
- [Secret sourcing (two tiers)](docs/invariants/config.md#secret-sourcing-two-tiers-bunyip-38-bunyip-542-bunyip-642) (BUNYIP-38/542/642): Group-1 secrets are files; Group-2 use `SECRETS_STORAGE`.
- [Settings archive](docs/invariants/config.md#settings-archive-bunyip-714) (BUNYIP-714): Settings move as one passphrase-encrypted file; import replaces, never merges.

### Branding and email

- [Email templates](docs/invariants/branding.md#email-templates): Email subjects take the product name from the branding record, not `APP_NAME`.
- [Branding](docs/invariants/branding.md#branding-bunyip-561) (BUNYIP-561): Product copy lives in the one `branding` row; empty means omitted, never a literal.
- [Brand assets and the palette](docs/invariants/branding.md#brand-assets-and-the-palette-bunyip-560-bunyip-553) (BUNYIP-560/553/605/568): Brand images and palette live on the branding record.

### Performance and caching

- [Rate limiting](docs/invariants/performance.md#rate-limiting-bunyip-426-bunyip-413-bunyip-645-bunyip-556) (BUNYIP-426/413/645/556): `RateLimitFloor` caps every api route from a cached snapshot.
- [One verification per request](docs/invariants/performance.md#one-verification-per-request-bunyip-557-bunyip-564) (BUNYIP-557/564/229): Verify tokens once via `verify_once`; reuse the row.
- [BFF chrome fetches](docs/invariants/performance.md#bff-chrome-fetches-bunyip-518-bunyip-555-bunyip-667) (BUNYIP-518/555/667/682/683/635): Read per-render payloads via `TtlCache` on `AppState`.
- [Response compression](docs/invariants/performance.md#response-compression-bunyip-559) (BUNYIP-559): api `Compress` wraps the primary stack; streamed responses call `mark_uncompressed`.
- [Static assets and the first-load payload](docs/invariants/performance.md#static-assets-and-the-first-load-payload-bunyip-560) (BUNYIP-560/554/605): Version every `/assets` reference via `asset()`.
- [BFF response compression](docs/invariants/performance.md#bff-response-compression-bunyip-554) (BUNYIP-554): bunyip-web's compression predicate exempts archive content types.
- [Database pool sizing](docs/invariants/performance.md#database-pool-sizing-bunyip-559) (BUNYIP-559): Pools are 10, measured; raise only on acquire timeouts, with PostgreSQL's limit.
- [Argon2 off the workers](docs/invariants/performance.md#argon2-off-the-workers-bunyip-553) (BUNYIP-553): Request-path Argon2 runs on the blocking pool via `argon2_offload`.

### API and web boundary

- [Mailer relay](docs/invariants/api-web.md#mailer-relay-bunyip-602-bunyip-603-bunyip-604) (BUNYIP-602/603/604): `POST /v1/mailer/send` is the suite's send-only relay, authed by machine client.
- [Unknown hosts](docs/invariants/api-web.md#unknown-hosts-dev-741-bunyip-686) (DEV-741, BUNYIP-686): Unknown hosts get a 404 plus timed redirect to the apex, never a 301/302.
- [Wire compatibility](docs/invariants/api-web.md#wire-compatibility-bunyip-506) (BUNYIP-506): Response fields take `#[serde(default)]`; renames go expand/contract.
- [Cookies](docs/invariants/api-web.md#cookies-bunyip-426) (BUNYIP-426): `Secure` comes from `Config::cookies_secure(&req)`, never `is_production()`.
- [Single-use tokens](docs/invariants/api-web.md#single-use-tokens-bunyip-426) (BUNYIP-426): Consume with a guarded `UPDATE ... used_at IS NULL` and branch on the result.
- [OCI errors log their cause](docs/invariants/api-web.md#oci-errors-log-their-cause-bunyip-565) (BUNYIP-565): Every `OciError::Internal` goes through `errors::context`, which logs first.

### UI

- [Scrollbars](docs/invariants/ui.md#scrollbars-bunyip-848-bunyip-509-yotun-208) (BUNYIP-848, BUNYIP-509, YOTUN-208): Thumb-only scrollbars that hide at rest; never `scrollbar-width: none`.
- [Committed CSS is current](docs/invariants/ui.md#committed-css-is-current-bunyip-598-bunyip-566) (BUNYIP-598, BUNYIP-566): Committed `styles.css` must equal a rebuild; crates need `@source`.
- [UI copy](docs/invariants/ui.md#ui-copy-bunyip-551-bunyip-624) (BUNYIP-551, BUNYIP-624): Title Case section names, `…` ellipses, terse empty states, no issue keys in copy.
- [Prices and deadlines in copy](docs/invariants/ui.md#prices-and-deadlines-in-copy-bunyip-590) (BUNYIP-590): Prices and deadlines come from live data, never literals.
- [Password inputs](docs/invariants/ui.md#password-inputs-bunyip-282-bunyip-575-bunyip-596-bunyip-597) (BUNYIP-282/575/596/597): Password forms use `password_field` plus the submit guard.
- [Authenticated navigation](docs/invariants/ui.md#authenticated-navigation-bunyip-547-bunyip-630) (BUNYIP-547, BUNYIP-630): Nav comes from `shell_nav_sections()` so it renders below `md`.
- [Theme tokens](docs/invariants/ui.md#theme-tokens-bunyip-549-bunyip-568) (BUNYIP-549, BUNYIP-568): Paint every surface from semantic tokens; the shell has no color literal.
- [A button's `extra` never fights its variant](docs/invariants/ui.md#a-buttons-extra-never-fights-its-variant-bunyip-656) (BUNYIP-656): New color or size means a new variant or size, not `extra`.
- [Amber contrast](docs/invariants/ui.md#amber-contrast-bunyip-548) (BUNYIP-548): Amber text uses the measured shades and meets AA over the tinted composite.
- [Fetched list states](docs/invariants/ui.md#fetched-list-states-bunyip-461-bunyip-546-bunyip-635) (BUNYIP-461/546/635): Fetched lists show unreachable, empty and populated distinctly.
- [Toast dismissal](docs/invariants/ui.md#toast-dismissal-bunyip-610-bunyip-98) (BUNYIP-610, BUNYIP-98): Error toasts wait for a click; others auto-dismiss scaled to message length.
