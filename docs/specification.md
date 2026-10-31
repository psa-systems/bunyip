# Bunyip Specification

This is the normative requirement set for the Bunyip workspace. Each numbered statement has a stable id
`SPEC-<section>.<n>` (for example `SPEC-2.1.3`), uses "must" / "must not", names its trigger, the required
observable outcome, and the required failure behavior. Where a requirement and the code disagree, fix the
requirement or the code in a follow-up: this document, not an older summary, prose comment, or README, is the
source of truth going forward. A requirement is cited at its implementing or enforcing site with a short
`// SPEC-<id>: <why, if non-obvious>` comment in the file's own comment syntax; the comment never restates the
requirement text.

Sections 1 and 2 below are written at requirement level. Sections 3 to 14 are a heading skeleton only: each is
populated by its own tracked issue (see `docs/ROADMAP.md`) and carries no body until then. Section numbers are
fixed so parallel work does not conflict; do not renumber a section to insert or remove one.

## 1. Purpose and non-goals

Bunyip is a SaaS account, billing, and distribution platform: operator and member account management, Stripe
subscription billing, a platform admin area, an OpenID Connect / OAuth 2.1 provider for first-party relying-party
products, a read-only authenticated OCI registry front, authenticated application downloads with a catalog of
hosted applications, and a mailer relay plus a host-secret/host-config read API for registered machine clients. The
functional detail for each of these areas is normative in sections 7 to 12 of this document (populated by the
sibling issues listed in `docs/ROADMAP.md`), not here; this section fixes the boundary of what Bunyip is and is
not, so later sections do not have to re-derive it.

- `SPEC-1.1` Bunyip must not host, or embed a runtime for, the first-party products that consume its OIDC
  provider (mokosh-apps, drillmark, lets-chat, and any other registered relying party): those are deployed and run
  as separate services, and bunyip's own binaries (`bunyip-api`, `bunyip-web`) must contain no code path that
  starts, proxies application traffic for, or serves the UI of a relying party.
- `SPEC-1.2` The OCI listener must reject every image push: `POST`, `PUT`, `PATCH`, and `DELETE` under `/v2/` must
  return an error response rather than accepting, storing, or forwarding a manifest or blob upload.
- `SPEC-1.3` Bunyip's OIDC provider must not implement, and must not expose an endpoint for, dynamic client
  registration (RFC 7591) or token introspection (RFC 7662); every OAuth client is provisioned out of band (seed
  migration or the `machine-client` subcommand), and a request to an introspection or registration path must fall
  through to the normal unmatched-route handling rather than a dedicated handler.
- `SPEC-1.4` Bunyip must not persist its own copy of invoices or payment history: a request for billing history
  (invoices, payments) must be served by a live read against Stripe at request time, not from a local table, so a
  change made directly in Stripe is reflected on the next request with no local cache to invalidate.
- `SPEC-1.5` Bunyip must treat PostgreSQL, reached only from `bunyip-api`, as its sole system of record: no other
  workspace member (`bunyip-web`, or a library crate consumed by either binary) may open its own database
  connection; a feature that needs persisted state must read or write it through a `bunyip-api` `/v1/*` call.

## 2. Architecture and process model

### 2.1 Workspace members and binaries

`Cargo.toml` is the single workspace manifest: `[workspace.package]` fixes one version, edition, author, license,
and repository for every member, and `[workspace.dependencies]` pins one shared version of `tokio`, `serde`,
`uuid`, `chrono`, `tracing`, `tracing-subscriber`, and a handful of small crates so the members cannot drift onto
different point releases of the same dependency.

- `SPEC-2.1.1` The workspace must declare exactly six members: the two binary crates `bunyip-api` and `bunyip-web`,
  and the four library crates `crates/bunyip-domain`, `crates/bunyip-oci`, `crates/bunyip-oidc`, and
  `crates/web-kit`. Adding a seventh workspace member, or removing one of the six, is an architecture change that
  must update this section in the same change.
- `SPEC-2.1.2` The dependency direction must be strictly downward and acyclic: `bunyip-api` depends on
  `bunyip-oci` and `bunyip-oidc`; `bunyip-oci`, `bunyip-oidc`, and `bunyip-web` depend on `bunyip-domain`;
  `bunyip-domain`, `bunyip-oci`, and `bunyip-oidc` depend on the `dunite-*` crates (git dependencies of
  `https://dev.a8n.run/psa-systems/dunite`, pinned by commit `rev`, never `branch`). `bunyip-api` also takes four
  `dunite-*` crates as its own direct dependencies, not only transitively through `bunyip-oci`/`bunyip-oidc`/
  `bunyip-domain` (`bunyip-api/Cargo.toml`): `dunite-core` for the Origin/Referer CSRF guard
  (`dunite_core::middleware::OriginGuard`, wired in `main.rs`), `dunite-image-upload` for upload content
  validation, `dunite-update-check` for the self-hosted update checker, and `dunite-events` for its own event
  emission. `bunyip-web`'s dependency on
  `bunyip-domain` is for shared response DTOs and CIDR-parsing types only (`bunyip-web/Cargo.toml`, BUNYIP-761):
  it must not call a `bunyip-domain` repository, service, or anything else that opens a database connection
  (`SPEC-1.5`). No `dunite-*` crate may depend on anything in `crates/` or either binary crate.
  `[workspace.lints.clippy] too_many_arguments = "allow"` is the one workspace-wide lint relaxation; no other lint
  may be silenced at the workspace level.
- `SPEC-2.1.3` `bunyip-api/Cargo.toml` must declare exactly four `[[bin]]` targets: `bunyip-api`
  (`src/main.rs`, the server described in `SPEC-2.2`), `bunyip-e2e-bootstrap`, `seed`, and `gen-demo-seed`. Only
  the first binds a network listener or touches application traffic; the other three are one-shot CLI tools
  invoked by an operator or by the e2e suite, never started as a long-running service.
- `SPEC-2.1.4` `bunyip-web/Cargo.toml` must declare exactly one `[[bin]]` target, `bunyip-web`
  (`src/main.rs`, described in `SPEC-2.3`).
- `SPEC-2.1.5` Every workspace member's build must use the exact Rust toolchain pinned in `rust-toolchain.toml`
  (`[toolchain] channel`, with the `clippy` and `rustfmt` components); a build invoked without that pin available
  must fail toolchain resolution rather than silently compiling with a different installed channel.

### 2.2 `bunyip-api` process model

`bunyip-api` (`bunyip-api/src/main.rs`) is a single OS process built on `tokio` and `actix-web`.

- `SPEC-2.2.1` On every invocation, `bunyip-api` must load configuration (`Config::from_env`) before doing
  anything else observable (opening a database connection, binding a listener): a missing or malformed required
  environment variable must be reported as one logged error line per failing variable and the process must exit
  with a non-zero status without binding any listener.
- `SPEC-2.2.2` When invoked with a first positional command-line argument, `bunyip-api` must treat that argument
  as a maintenance subcommand name, dispatch it (`run_subcommand`), run it to completion against the already-open
  database pool, and exit without binding either HTTP listener in `SPEC-2.2.4`. An argument that does not match
  one of the known subcommand names (`secrets-status`, `secrets-migrate`, `secrets-purge`, `config-status`,
  `machine-client`, `reconcile-duplicate-prices`, `settings-export`, `settings-import`, `mirzam-backfill`,
  `reencrypt-secrets`) must return an error that names all of the known subcommands, rather than starting the
  server or silently ignoring the argument.
- `SPEC-2.2.3` When invoked with no subcommand argument, `bunyip-api` must, in order: reconcile legacy migration
  checksums, ensure the `bunyip_app` database role shell exists, run every pending migration under
  `bunyip-api/migrations` via `sqlx::migrate!`, and only then provision the full `bunyip_app` RLS role (when
  `BUNYIP_APP_PASSWORD` is set) and proceed to serve traffic. A migration failure must abort startup (non-zero
  exit) before any listener binds.
- `SPEC-2.2.4` `bunyip-api` must run at most two `actix_web::HttpServer` instances inside the one process: a
  primary server bound to `server_addr()` (`HOST_IP:APP_PORT`) that always starts, and a second OCI registry
  server bound to `HOST_IP:OCI_REGISTRY_PORT` that starts only when `config.oci.enabled` is true and a Forgejo
  registry client is configured (`FORGEJO_BASE_URL` and `FORGEJO_API_TOKEN` both set). When the OCI server does
  not start, `bunyip-api` must log that it is disabled and continue serving on the primary server alone; when it
  does start, the process must await both servers (`tokio::try_join!`) so that either one exiting ends the
  process.
- `SPEC-2.2.5` The primary server's middleware stack must wrap every request, outermost first, in this order:
  auto-ban, the rate-limit floor, CORS, the CSRF origin guard, the request-id tag, security headers, the access
  logger, request tracing, then response compression innermost. The OCI server's stack is request tracing, the
  access logger, security headers, the request-id tag, then the registry's `WWW-Authenticate` middleware; it
  registers no CORS or CSRF layer because it carries no cookie-authenticated or browser-originated route.
  `APP_PORT` has no code default of `4401`: an unset `APP_PORT` resolves to `4000` in `Config::from_env`; the
  reference `compose.yml` deployment is what sets `APP_PORT=4401` in its environment. `OCI_REGISTRY_PORT`
  defaults to `18081` in code when unset.

### 2.3 `bunyip-web` process model

`bunyip-web` (`bunyip-web/src/main.rs`) is a single OS process built on `tokio` and `axum`; it is the only
component the browser talks to directly.

- `SPEC-2.3.1` On startup, before binding its listener, `bunyip-web` must load its configuration from the
  environment, perform one blocking fetch of the branding record and the feature-flag snapshot from `bunyip-api`,
  and install both into process-wide state, so the first response it serves already reflects the current brand
  and flags rather than a compiled-in placeholder. A failure of either startup fetch must be logged and must not
  abort the process: it falls back to an unbranded default (branding) or every flag off (feature flags), and a
  background refresh task retries on an interval.
- `SPEC-2.3.2` `bunyip-web` must run exactly one HTTP listener, bound to `BUNYIP_BIND_ADDR` (default
  `0.0.0.0:4400` when unset), serving one `axum::Router` built in `main()`; it must not open a second listener or
  a second `axum::serve` call in the same process.
- `SPEC-2.3.3` Every `bunyip-api` call `bunyip-web` makes on behalf of a browser request must forward the
  inbound `Cookie` header to `bunyip-api` and relay any `Set-Cookie` response header back to the browser
  unmodified, and must add an `X-Forwarded-For` header carrying the end-user address resolved from the inbound
  connection (honoring `bunyip-web`'s own `TRUSTED_PROXY_CIDR`), so a cookie-session or audit record on
  `bunyip-api` attributes to the real client rather than to the `bunyip-web` container.
- `SPEC-2.3.4` The router's outermost-to-innermost middleware order must be: compression, the CSP header layer,
  client-IP resolution, the CSRF origin check, then the unknown-host gate; any route not matched by an explicit
  `.route()` or `.nest_service()` registration must fall through to the branded 404 handler rather than axum's
  default 404.

### 2.4 Runtime data flow and listeners

- `SPEC-2.4.1` A browser must never call `bunyip-api` directly: every authenticated or data-bearing request from
  the browser goes to `bunyip-web`, which is the only member permitted to originate a `/v1/*` or `/oauth2/*` or
  `/.well-known/*` call to `bunyip-api` on the browser's behalf (`SPEC-2.3.3`). A first-party relying-party
  product (a separate deployment, not a workspace member) is the one exception: it calls `bunyip-api`'s
  `/.well-known/*` and `/oauth2/*` endpoints directly as an OIDC relying party, while its own login and consent UI
  is still served by `bunyip-web`'s `/oauth2/consent` page.
- `SPEC-2.4.2` The three listeners this workspace's binaries bind, and their configuration source, must be:
  `bunyip-web` on `BUNYIP_BIND_ADDR` (code default `0.0.0.0:4400`); `bunyip-api`'s primary server on
  `HOST_IP:APP_PORT` (code default `0.0.0.0:4000`, overridden to `4401` by the reference `compose.yml`); and
  `bunyip-api`'s OCI registry server on `HOST_IP:OCI_REGISTRY_PORT` (code default `18081`), bound only under the
  condition in `SPEC-2.2.4`.

## 3. CI, scripts and end-to-end tests

## 4. Data model and migrations

## 5. OIDC provider crate

## 6. OCI registry crate

## 7. Domain crate core (root, models, repositories, middleware)

## 8. Domain crate services

## 9. API application core (root, binaries, routes)

## 10. API handlers

## 11. Web application core (root, api client, routes, skin, views, assets, image build)

## 12. Web handlers

## 13. Shared web UI crate

## 14. Workspace build, packaging and deployment
