# Bunyip Specification

This is the normative requirement set for the Bunyip workspace. Each numbered statement has a stable id
`SPEC-<section>.<n>` (for example `SPEC-2.1.3`), uses "must" / "must not", names its trigger, the required
observable outcome, and the required failure behavior. Where a requirement and the code disagree, fix the
requirement or the code in a follow-up: this document, not an older summary, prose comment, or README, is the
source of truth going forward. A requirement is cited at its implementing or enforcing site with a short
`// SPEC-<id>: <why, if non-obvious>` comment in the file's own comment syntax; the comment never restates the
requirement text.

Section numbers are fixed so parallel work does not conflict; do not renumber a section to insert or remove one.
Section ownership and the plan behind the numbering are in `docs/ROADMAP.md`.

## 1. Purpose and non-goals

Bunyip is a SaaS account, billing, and distribution platform: operator and member account management, Stripe
subscription billing, a platform admin area, an OpenID Connect / OAuth 2.1 provider for first-party relying-party
products, a read-only authenticated OCI registry front, authenticated application downloads with a catalog of
hosted applications, and a mailer relay plus a host-secret/host-config read API for registered machine clients. The
functional detail for each of these areas is normative in sections 5 to 13 of this document, not here; this section fixes the boundary of what Bunyip is and is
not, so later sections do not have to re-derive it.

- `SPEC-1.1` Bunyip must not host, or embed a runtime for, the first-party products that consume its OIDC
  provider (any registered first-party relying-party product): those are deployed and run
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
  the shared kernel repository, pinned by commit `rev`, never `branch`). `bunyip-api` also takes four
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
  logger, request tracing, then response compression innermost. The OCI server's stack is the registry's
  `WWW-Authenticate` middleware, the request-id tag, security headers, the access logger, then request tracing
  innermost; it registers no CORS or CSRF layer because it carries no cookie-authenticated or browser-originated
  route.
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

### 3.1 Scheduled dependency audit workflow

- `SPEC-3.1.1` The Audit workflow must run on the cron schedule `17 6 * * 1` (Mondays 06:17 UTC) and on manual
  `workflow_dispatch`, and on no other trigger, so an advisory published against an unchanged `Cargo.lock` is still
  found.
- `SPEC-3.1.2` The Audit workflow's single job must run on the runner label `vars.RUNS_ON_OPENSUSE_BASE_HEAVY` and
  must declare `defaults.run.shell: nu {0}`, because the audit installs or builds `cargo-audit` and needs a C
  toolchain.
- `SPEC-3.1.3` Before auditing, the job must restore a `Swatinem/rust-cache` cache with `shared-key: audit` and
  `cache-on-failure: true`, so weekly runs share one `CARGO_HOME` and the `cargo-audit` install is not repaid.
- `SPEC-3.1.4` The job's audit step must run `./scripts/check-dependency-audit.nu --self-test` and then
  `./scripts/check-dependency-audit.nu`, in that order; a non-zero exit from either must fail the job, so a guard that
  stopped parsing cannot pass vacuously.

### 3.2 API image build workflow

- `SPEC-3.2.1` The Build API image workflow must trigger on `workflow_dispatch` (inputs `dry_run`, a boolean defaulting
  to `true`, and `simulate_tag`, a string defaulting to the empty string) and on `push` to branches `main` and
  `feature-*` or tags `v*`, and the `push` trigger must carry the shared `paths` filter: `bunyip-api/**`,
  `bunyip-web/**`, `crates/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/**`, `.sqlx/**`,
  `.dockerignore`, `oci-build/**`, `.forgejo/workflows/build-api.yml` and `.forgejo/workflows/build-web.yml`.
- `SPEC-3.2.2` The workflow must use concurrency group `${{ github.workflow }}-${{ github.ref }}` with
  `cancel-in-progress` true for branch refs and false when `github.ref` starts with `refs/tags/`, so a tag build is
  never cancelled and the registry never lacks a released version.
- `SPEC-3.2.3` The job must run on `vars.RUNS_ON_OPENSUSE_BASE_HEAVY` with `permissions` `contents: read` and
  `packages: write`, must declare `defaults.run.shell: nu {0}`, must check out with `fetch-depth: 0`, and must export
  `CARGO_BUILD_JOBS` from the runner through the shared build-parallelism action before building.
- `SPEC-3.2.4` The `resolve` step must derive the publish mode from the trigger and never from `git describe`:
  `dry-run` when the event is `workflow_dispatch`, `release` when `github.ref_type` is `tag`, otherwise `latest`, so a
  release commit's main push and tag push publish disjoint tags and never race on `latest`.
- `SPEC-3.2.5` The `resolve` step must set `dry_run` true only when the event is `workflow_dispatch` and
  `inputs.dry_run` is not the string `false`; a `push` event must always publish for real.
- `SPEC-3.2.6` The `resolve` step must call `oci-build/get-tags.nu` with `--mode`, `--ref-name`, `--simulate-tag` and
  `--json`, and must append `mode`, `train`, `tag`, `describe` and `dry_run` to `$GITHUB_OUTPUT` for later steps.
- `SPEC-3.2.7` Before the build, the job must run `./scripts/check-build-cache-health.nu --preflight`, so an
  unusable `type=gha` cache backend fails the job instead of producing a silently cold build.
- `SPEC-3.2.8` The job must set `IMAGE_REGISTRY` to `<registry provider>/<owner>` and `REGISTRY_USER` to the owner
  taken from the repository variable naming the private package owner, and must run `docker login` with the
  repository secret holding the private-package token as the password before building.
- `SPEC-3.2.9` The build step must run `docker buildx build --progress=plain` with context `.` and Dockerfile
  `bunyip-api/oci-build/Dockerfile`, tag `<IMAGE_REGISTRY>/bunyip-api:<resolved tag>`, `--cache-from
  type=gha,scope=bunyip-api`, and build arguments `GIT_COMMIT` (`git rev-parse --short HEAD`), `GIT_TAG` (`git
  describe --tags --always --dirty`), `BUILD_DATE` (UTC, `%Y-%m-%dT%H:%M:%SZ`) and `CARGO_BUILD_JOBS`.
- `SPEC-3.2.10` In dry-run the build step must pass `--load` and no `--cache-to`; otherwise it must pass `--push` and
  `--cache-to type=gha,scope=bunyip-api,mode=max,ignore-error=true`, and must print a line starting `[dry-run] WOULD
  build and push` in dry-run or `Building and pushing` otherwise.
- `SPEC-3.2.11` The build step must tee the full buildx progress stream (stdout and stderr) to `buildx-api.log`, and a
  non-zero buildx exit must fail the step.
- `SPEC-3.2.12` After the build, the job must run `./scripts/check-build-cache-health.nu --self-test` and then
  `./scripts/check-build-cache-health.nu --log buildx-api.log`; cache-health findings must be warnings only and must
  not fail the publish.
- `SPEC-3.2.13` The job must print the pushed image reference with the prefix `Image pushed to`, or `[dry-run] WOULD
  push image to` in dry-run, and must end with the job-metrics report step under `if: always()` so a failing job still
  reports.

### 3.3 Web image build workflow

- `SPEC-3.3.1` The Build Web image workflow's `workflow_dispatch` inputs, `push` branches, tags and `paths` filter,
  concurrency group and tag-build non-cancellation, runner label, permissions and default shell must be identical to
  those required of the API workflow in `SPEC-3.2.1`, `SPEC-3.2.2` and `SPEC-3.2.3`, so both images build for a merge
  or neither does.
- `SPEC-3.3.2` Before any Docker step, the job must read `bunyip-web/Cargo.toml` and, when its `dependencies` table
  has no `axum` key, must print three `error:` lines and exit 1 with no image built or pushed, so a pre-pivot tree can
  never publish; otherwise it must print that the tree is Axum SSR.
- `SPEC-3.3.3` The job's mode resolution, `dry_run` rule, tag resolution through `oci-build/get-tags.nu`, cache
  preflight, registry login and environment variables must be identical to `SPEC-3.2.4` through `SPEC-3.2.8`, with the
  buildx builder named `build-web`.
- `SPEC-3.3.4` The build step must run `docker buildx build --progress=plain` with context `.` and Dockerfile
  `bunyip-web/oci-build/Dockerfile`, tag `<IMAGE_REGISTRY>/bunyip-web:<resolved tag>`, `--cache-from
  type=gha,scope=bunyip-web`, the same four build arguments as `SPEC-3.2.9`, the dry-run and push argument rules of
  `SPEC-3.2.10`, and must tee the progress stream to `buildx-web.log`.
- `SPEC-3.3.5` After the build, the job must run the cache-health self-test and then
  `./scripts/check-build-cache-health.nu --log buildx-web.log` as a non-failing report, print the image reference as
  `SPEC-3.2.13` requires, and end with the job-metrics report step under `if: always()`.

### 3.4 Check workflow: triggers and the cargo job

- `SPEC-3.4.1` The Check workflow must trigger on `push` to `main` only when a changed path matches `bunyip-api/**`,
  `bunyip-web/**`, `crates/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml`, `.sqlx/**`,
  `scripts/**` or `.forgejo/workflows/**`, and on every `pull_request` to `main` with no `paths` or `paths-ignore`
  filter, so a required check always reports.
- `SPEC-3.4.2` The workflow must use concurrency group `${{ github.workflow }}-${{ github.ref }}` with
  `cancel-in-progress: true`.
- `SPEC-3.4.3` The `cargo` job must run on `vars.RUNS_ON_OPENSUSE_BASE_HEAVY` with `defaults.run.shell: nu {0}`, must
  set `SQLX_OFFLINE` to `true`, `CARGO_PROFILE_DEV_DEBUG` to `line-tables-only` and `CARGO_INCREMENTAL` to `0`, and must
  check out with `submodules: true` so the root justfile's `import` resolves.
- `SPEC-3.4.4` Right after checkout, the `cargo` job must run the shared `classify-diff` action with step id
  `classify-diff`; outside a `pull_request` event its result must be treated as `code`.
- `SPEC-3.4.5` Clippy, the `Cargo.lock` sync check, the unit tests and the docker builder stage must run only when
  `steps.classify-diff.outputs.result == 'code'`, and `cargo fmt` must run unless that result is `non-code`.
- `SPEC-3.4.6` The commands must be exactly `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo check --workspace --all-targets --locked` and `cargo test --workspace --all-targets`, so binary
  crate tests run and a stale lockfile fails.
- `SPEC-3.4.7` The job must cache `~/.cargo/bin/cargo-binstall` under key `cargo-binstall-1.14.3-linux-musl`, and the
  install step must download the pinned release tarball `1.14.3` (linux x86_64 musl) only when
  `$HOME/.cargo/bin/cargo-binstall` does not exist, must run the binary with `--help` to prove it executes, and must
  append the bin directory to `$GITHUB_PATH` in both the download and the already-present branch.
- `SPEC-3.4.8` The dependency-audit step must not be gated on the classifier and must run
  `./scripts/check-dependency-audit.nu --self-test` and then `./scripts/check-dependency-audit.nu`.
- `SPEC-3.4.9` The docker builder-stage step must first remove any prior `bunyip-api-builder:check` image, ignoring
  the removal's failure, and must then run `docker build --provenance=false` with build argument
  `CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS`, file `bunyip-api/oci-build/Dockerfile`, `--target builder`, tag
  `bunyip-api-builder:check` and context `.`, so a re-run does not collide with a leftover tag.
- `SPEC-3.4.10` The last build step of the `cargo` job must run `just check-tree-ownership`, so a root-owned file left
  by any earlier container step fails the job, and the job must end with the job-metrics report under `if: always()`.

### 3.5 Check workflow: guards job

- `SPEC-3.5.1` The `guards` job must run on `vars.RUNS_ON_OPENSUSE_BASE_MEDIUM` with `defaults.run.shell: nu {0}` and
  `timeout-minutes: 15`, and must check out with `fetch-depth: 0` and `submodules: true`.
- `SPEC-3.5.2` The job must run, in this order and ungated by the classifier, `just --summary`, `just
  check-justfile`, `just check-migration-versions`, `just check-migration-immutability` and `just check-workflows`.
- `SPEC-3.5.3` For each of the guards `check-workflow-shell`, `check-serde-compat`, `check-env-parity`,
  `check-compose-env-parity`, `check-argon2-offload`, `check-scrollbars`, `check-css-current`, `check-ui-copy`,
  `check-price-literals`, `check-em-dash`, `check-brand-literals`, `check-theme-colors`, `check-doc-surface`,
  `check-claude-md`, `check-cache-mount-sharing`, `check-build-cache-keys` and `check-publish-triggers`, the job must
  run `./scripts/<guard>.nu --self-test` first and `./scripts/<guard>.nu` second.
- `SPEC-3.5.4` The job must run `./scripts/check-runner-labels.nu`, `./scripts/check-security-invariants.nu`,
  `./scripts/check-no-stripe-env.nu`, `./scripts/check-no-retired-env.nu` and `./scripts/check-no-bash.nu` without a
  `--self-test` step.
- `SPEC-3.5.5` Any non-zero guard exit must fail the job, no guard step may be conditional, and the job must end with
  the job-metrics report under `if: always()`.

### 3.6 Check workflow: secrets scan job

- `SPEC-3.6.1` The `secrets` job must run on `vars.RUNS_ON_OPENSUSE_BASE_MEDIUM` with `defaults.run.shell: nu {0}`,
  and must check out with `fetch-depth: 0` and `persist-credentials: false`, so the scan sees full history and the
  checkout leaves no credential in the working tree.
- `SPEC-3.6.2` The job's scan step must call the shared `check-secrets` composite action with a
  `kingfisher_skip_regex` input.
- `SPEC-3.6.3` The `kingfisher_skip_regex` must suppress only whole-token fixture and dev-default values (`($pg_pass)`,
  `CHANGE_ME`, `devpassword`, `nobody`, `pw`, `[rs]k_live_abcdefgh1234`, `rk_test_abcdefgh5678`,
  `sk_live_MIDDLEsecretMATERIAL1234`) and one unanchored substring, the base64 body of the synthetic Ed25519 private key
  used by the OIDC provider's logout-token test, so no other secret-shaped value is suppressed.

### 3.7 Release-on-merge workflow

- `SPEC-3.7.1` The Create release workflow must trigger only on `pull_request_target` of type `closed` against
  `main`, so the workflow definition that runs is always the copy on `main` that a pull request cannot edit.
- `SPEC-3.7.2` The `create-release` job must run only when `github.event.pull_request.merged == true` and the pull
  request head ref starts with `release/v`; a closed-unmerged pull request or a merged non-release pull request must
  release nothing.
- `SPEC-3.7.3` The job must be a pure reusable-workflow caller (`uses:` the shared `create-release.yml@main`) with
  `runs-on: ${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` and `secrets: inherit`, must declare no `defaults` and no steps,
  and must never check out pull request code, so a `pull_request_target` run holding the release token cannot execute
  pull request content.
- `SPEC-3.7.4` The `uses:` line and the `secrets: inherit` line must each carry a trailing `# secret-scope-ok:`
  marker stating why the mutable ref and the inherited secrets are accepted (`SPEC-3.18.4`, `SPEC-3.18.5`).

### 3.8 Renovate workflow

- `SPEC-3.8.1` The Renovate workflow must trigger on the cron schedule `0 2 * * 6` (Saturdays 02:00 UTC) and on manual
  `workflow_dispatch`.
- `SPEC-3.8.2` The `renovate` job must be a reusable-workflow caller pinned to a full 40-hex commit SHA, with
  `runs-on: ${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` and `with.target_repository: ${{ github.repository }}`.
- `SPEC-3.8.3` The job must pass exactly five secrets by name, not `secrets: inherit`, each from the same-named
  repository secret: `RENOVATE_CI_TOKEN`, the public-GitHub read token, the two private-package tokens and the Forgejo
  personal access token.

### 3.9 Credential-free pull request E2E gate

- `SPEC-3.9.1` The workflow in `e2e-pr.yml` must be named `E2E`, trigger only on `pull_request` against `main`, and
  hold the jobs `classify-diff` (display name `Classify diff`) and `e2e-pr` (display name `PR gate`), so the published
  check is `E2E / PR gate`.
- `SPEC-3.9.2` The workflow must use concurrency group `e2e-pr-${{ github.ref }}` with `cancel-in-progress: true`, a
  group separate from the full suite's.
- `SPEC-3.9.3` The `classify-diff` job must run on `vars.RUNS_ON_OPENSUSE_BASE_MEDIUM`, check out the repository, run
  the shared `classify-diff` action and expose its `result` as the job output `result`.
- `SPEC-3.9.4` The `PR gate` job must declare `needs: classify-diff` and a job-level `if` requiring
  `needs.classify-diff.outputs.result == 'code'`, so a docs-only or comment-only diff reports the job as skipped
  instead of dropping the workflow; it must not use a trigger-level path filter.
- `SPEC-3.9.5` The `PR gate` job's `env` must hold exactly `E2E_BASE_URL` from `secrets.E2E_STAGING_BASE_URL` and
  `E2E_OP_BASE_URL` from `secrets.OIDC_ISSUER_STAGING`, and no other secret, because the job executes unreviewed pull
  request code.
- `SPEC-3.9.6` The `PR gate` job must run, with working directory `e2e` and shell `nu {0}`, `corepack npm ci
  --ignore-scripts`, then `corepack npx playwright install chromium`, then `node24 scripts/health-check.mjs` with
  `E2E_HUB_SOFT` set to `true`, and must not run the Playwright suite.

### 3.10 Deployed-instance E2E workflow

- `SPEC-3.10.1` The workflow in `e2e.yml` must be named `E2E` and trigger only on `push` to `main` and on
  `workflow_dispatch` with a choice input `environment` (`staging` or `production`, default `staging`); it must have no
  `pull_request` trigger.
- `SPEC-3.10.2` The workflow must use the single concurrency group `e2e-bunyip` with `cancel-in-progress: false`, so
  every trigger is serialised and no run is cancelled, because the suite shares one login rate-limited per email.
- `SPEC-3.10.3` The job `e2e` (display name `deployment`) must run on `vars.RUNS_ON_OPENSUSE_BASE_HEAVY`, with
  `defaults.run.shell: nu {0}` and working directory `e2e`, and must check out with `fetch-depth: 0` so
  `wait-for-deploy.mjs` can walk `git log`.
- `SPEC-3.10.4` The job `env` must expose `E2E_BASE_URL`, `E2E_OP_BASE_URL`, `E2E_EMAIL`, `E2E_PASSWORD`,
  `E2E_TENANT_ID`, `E2E_OIDC_CLIENT_ID`, `E2E_OIDC_REDIRECT_URI`, `E2E_TOTP_SECRET` and `E2E_STRIPE_SECRET_KEY`, each
  from the `E2E_PRODUCTION_*` secret (the OP host from `OIDC_ISSUER_PRODUCTION`) when `inputs.environment ==
  'production'` and from the staging secret otherwise, and `E2E_MAIL_SINK_URL` as the empty string on production and
  `secrets.E2E_STAGING_MAIL_SINK_URL` otherwise.
- `SPEC-3.10.5` The job must install dependencies with `corepack npm ci --ignore-scripts`, because dependency
  lifecycle scripts would run with the full secret environment, and must run `corepack npx playwright install
  chromium` without `--with-deps`.
- `SPEC-3.10.6` On a `push` event or a staging dispatch the job must run `node24 scripts/wait-for-deploy.mjs`, and on
  a production dispatch it must instead run `node24 scripts/health-check.mjs` without `E2E_HUB_SOFT`, so a
  production hub that is not live fails the run.
- `SPEC-3.10.7` The job must run `node24 scripts/check-bootstrapped.mjs` as step `bootstrap_check`; it must run
  `corepack npx playwright test` only when `steps.bootstrap_check.outputs.bootstrapped == 'true'` or the event is a
  production dispatch, and otherwise must print a note that the suite was skipped and still succeed.
- `SPEC-3.10.8` On job failure the job must upload an artifact named `playwright-report` containing
  `e2e/playwright-report/` and `e2e/test-results/` with `retention-days: 14` and `if-no-files-found: ignore`, and must
  end with the job-metrics report under `if: always()`.

### 3.11 Publish tag resolver (`oci-build/get-tags.nu`)

- `SPEC-3.11.1` `get-tags.nu` must accept `--mode` (`release`, `latest` or `dry-run`), `--ref-name` (default empty),
  `--simulate-tag` (default empty) and `--json`, and must return the record `{mode, train, tag, describe}`.
- `SPEC-3.11.2` Mode `release` must resolve train `release` with version `--ref-name`; mode `latest` must resolve train
  `latest`; mode `dry-run` must resolve train `release` with version `--simulate-tag` when it is non-empty and train
  `latest` otherwise.
- `SPEC-3.11.3` Any other `--mode` value must fail with the error message `[get-tags] Unknown mode: '<mode>'.
  Expected release|latest|dry-run.`.
- `SPEC-3.11.4` A `release` train with an empty version must fail with the error message `[get-tags] release train
  requires a non-empty version (--ref-name for a tag build, or --simulate-tag for a dry-run).`.
- `SPEC-3.11.5` The `tag` field must be the version for train `release` and the literal `latest` for train `latest`,
  and `describe` must be the output of `git describe --tags --always`, used for diagnostics only and never to choose
  the train.
- `SPEC-3.11.6` With `--json` the script must emit the record as raw JSON on stdout; without it, as a record, so it can
  be consumed as a module.
- `SPEC-3.11.7` The script must log its inputs and the resolved train and tag at `info` level.

### 3.12 Dependency audit guard (`scripts/check-dependency-audit.nu`)

- `SPEC-3.12.1` The guard must run from the repository root and must exit 1 with `FAILED: run this from the repository
  root.` when `Cargo.lock` is absent.
- `SPEC-3.12.2` With no `--runner`, the guard must run `cargo audit --json`; if `cargo audit --version` fails it must
  install `cargo-audit` at version requirement `^0.22` with `cargo binstall --no-confirm --locked` when `cargo binstall
  --version` succeeds and with `cargo install --locked --version ^0.22 cargo-audit` otherwise, and an install failure
  must print the install's stdout and stderr and exit 1.
- `SPEC-3.12.3` With `--runner <command>`, the guard must run the runner words followed by `sh -c` of one script that
  installs `cargo-audit` when `command -v cargo-audit` fails and then runs `cargo audit --json`, so install and audit
  share one container; a failed install must print the marker `cargo-audit-bootstrap-failed` on stderr and exit 90.
- `SPEC-3.12.4` The guard must parse the JSON report starting at the first `{` of stdout. A missing JSON object,
  non-JSON text or a report without a `vulnerabilities` key must fail the run with exit 1, naming which of three
  failures it was (`bootstrap` when exit code is 90 or stderr holds the marker, `empty` when stdout is blank, otherwise
  `parse`), printing "Nothing was audited.", and printing the stdout excerpt.
- `SPEC-3.12.5` The stdout excerpt must be `(empty)` for blank stdout, the whole text up to 2000 characters, and
  otherwise the first 2000 characters followed by a line stating how many characters arrived and that the output was
  truncated.
- `SPEC-3.12.6` Each reported vulnerability must fail the run unless an `EXCEPTIONS` row with the same advisory id
  exists whose `review_by` date is today or later; the failure line must name the advisory id, crate, version, title
  and patched versions (`none published` when empty).
- `SPEC-3.12.7` A `review_by` date must stay valid through the end of its own calendar day: the comparison must use
  today's date, not the current timestamp.
- `SPEC-3.12.8` An `EXCEPTIONS` row whose advisory id is not in the report must fail the run as stale, and a row whose
  `review_by` is before today must fail the run as expired, naming its issue.
- `SPEC-3.12.9` An `EXCEPTIONS` row must fail the run as malformed when its `id` does not match `^RUSTSEC-\d{4}-\d{4}$`,
  its `issue` does not match `^BUNYIP-\d+$`, or its `review_by` is not a readable date, and no other check may proceed
  until every row is well-formed.
- `SPEC-3.12.10` Warnings in the report (`unmaintained`, `unsound`, `yanked`, `notice`) must be printed in full and must
  not fail the run; a run with no uncovered vulnerability must print `OK` with the accepted-exception and warning counts
  and exit 0.
- `SPEC-3.12.11` `--self-test` must exit 1 with `SELF-TEST FAILED` unless the guard rejects an uncovered vulnerability,
  an expired, stale, untracked, undated or malformed exception and an unreadable report, accepts a covered finding, an
  exception due today and a warnings-only report, keeps the bootstrap and audit in one runner invocation, classifies
  bootstrap, empty and parse failures correctly, and bounds an oversized stdout.

### 3.13 Buildkit cache health signal (`scripts/check-build-cache-health.nu`)

- `SPEC-3.13.1` The script must require exactly one of `--preflight`, `--log <path>` or `--self-test`; with none it
  must print an error on stderr and exit 2.
- `SPEC-3.13.2` `--preflight` must exit 1 with an error naming the missing variables when `ACTIONS_RUNTIME_TOKEN` is
  empty or when both `ACTIONS_CACHE_URL` and `ACTIONS_RESULTS_URL` are empty, and must otherwise print that the cache
  credentials are present and exit 0.
- `SPEC-3.13.3` `--log` must read the captured buildx log and emit each finding as a `::warning::cache health: ...`
  line, and must exit 0 whatever it finds, because the published image is still correct.
- `SPEC-3.13.4` `--log` must warn when the log never contains `importing cache manifest`, when an `ERROR` line matches
  `blob sha256:<hex>: not found` (counted as evicted blobs), when any other `#<n> ERROR` line is present (a swallowed
  error, quoting up to the first three), and when the `COPY` of `recipe.json` step is `CACHED` while the `cargo chef
  cook` step is `DONE`.
- `SPEC-3.13.5` When the log file is missing or unreadable, `--log` must print `::warning::build log <path> is missing
  or unreadable; cache health could not be assessed.` and return exit 0.
- `SPEC-3.13.6` When `--log` finds nothing it must print one line stating the manifest was imported with no evicted
  blobs and the dependency layer reused.
- `SPEC-3.13.7` `--self-test` must exit 1 with `self-test FAILED` unless a healthy warm log yields no warning and each
  of the poisoned-cook, cold, evicted-blob, first-build and failed-export logs yields exactly one warning.

### 3.14 Dockerfile cache gates (`check-cache-mount-sharing.nu`, `check-build-cache-keys.nu`)

- `SPEC-3.14.1` `check-cache-mount-sharing.nu` must scan every git-tracked file whose basename contains `Dockerfile`,
  and must report a problem and exit 1 for any non-comment `--mount=type=cache` option string that lacks a non-empty
  `id=` or lacks `sharing=locked`, naming the file, line and the missing parts.
- `SPEC-3.14.2` `check-cache-mount-sharing.nu` must ignore comment lines and mounts of other types (`secret`, `bind`),
  must treat `sharing=shared` as missing the lock, and must report a missing or unreadable Dockerfile as a problem.
- `SPEC-3.14.3` `check-build-cache-keys.nu` must, per Dockerfile stage, fail with exit 1 when an `ENV` assigning
  `BUILD_DATE`, `GIT_COMMIT`, `GIT_TAG`, `SOURCE_DATE_EPOCH`, `VCS_REF` or `BUILD_ID` precedes, in the same stage, a
  `RUN` containing `cargo chef cook`, `bun install` or `cargo install cargo-chef`, naming the `ENV` line, stage and
  `RUN` line.
- `SPEC-3.14.4` `check-build-cache-keys.nu` must join backslash continuation lines before matching, restart the
  volatile set at every `FROM`, ignore comment lines, match the variable name exactly (an `ENV` of a name that merely
  contains `BUILD_DATE` is not volatile), and report a missing or unreadable Dockerfile as a problem.
- `SPEC-3.14.5` Both scripts must print the number of Dockerfiles checked on success, and `--self-test` must exit 1
  with `self-test FAILED` unless each of its compliant and violating fixtures is classified as expected.

### 3.15 Publish trigger parity guard (`scripts/check-publish-triggers.nu`)

- `SPEC-3.15.1` The guard must compare the `on.push` keys `branches`, `tags` and `paths` of
  `.forgejo/workflows/build-api.yml` and `.forgejo/workflows/build-web.yml` as order-insensitive sets, treating an
  absent key as an empty list, and must report each differing key with the entries present on only one side.
- `SPEC-3.15.2` A workflow that is missing, unreadable or has no `on.push` trigger must be reported as a problem and
  no further comparison may run.
- `SPEC-3.15.3` The guard must read `BUILD_TRIGGER_PATHS` from `e2e/scripts/wait-for-deploy.mjs` and must report a
  problem when it is absent or when its entries, after stripping a trailing `/**`, differ from the shared `paths`
  filter, naming the missing and unexpected entries.
- `SPEC-3.15.4` Any problem must print `error:` lines and exit 1; success must print the count of workflows and exit 0.
  `--self-test` must exit 1 unless matching filters in a different order pass and a missing path, differing branches,
  differing tags, a missing push trigger, a missing workflow, a drifted deploy gate, an extra deploy-gate path and a
  missing deploy gate each fail.

### 3.16 Runner label guard (`scripts/check-runner-labels.nu`)

- `SPEC-3.16.1` The guard must take an optional workflows directory (default `.forgejo/workflows`) and must exit 2
  when `check.yml` is not a file there.
- `SPEC-3.16.2` The guard must exit 1 unless `check.yml` contains the exact text `runs-on: ${{
  vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}`.
- `SPEC-3.16.3` The guard must exit 1 for any non-comment line under the workflows directory naming
  `RUNS_ON_OPENSUSE_BASE_LATEST` or `RUNS_ON_OPENSUSE_DEV_LATEST`.
- `SPEC-3.16.4` The guard must exit 1 for any non-comment line that installs `gcc`, `clang`, `binutils`,
  `libopenssl-devel`, `openssl-devel` or `build-essential` with `zypper`, `apt-get`, `dnf` or `yum`, and for any
  non-comment line naming a Playwright browser system library package (`libgtk-3-0`, `libgobject-2_0-0`,
  `libglib-2_0-0`, `mozilla-nss`, `mozilla-nspr`, `libatk-1_0-0`, `libasound2`, `libgbm1`, `libxkbcommon0`).
- `SPEC-3.16.5` The guard must exit 1 for any `runs-on:` line whose nearest preceding non-blank line is not a comment,
  so every runner label states why it is correct.

### 3.17 Nushell-only guards (`check-workflow-shell.nu`, `check-no-bash.nu`)

- `SPEC-3.17.1` `check-workflow-shell.nu` must parse every `*.yml` and `*.yaml` file under its directory argument
  (default `.forgejo/workflows`) and must report a file that is not valid YAML, or declares no jobs, as a problem.
- `SPEC-3.17.2` For every job that has no `uses:` key, the guard must require `defaults.run.shell` to equal `nu {0}`
  exactly, and must report any step whose own `shell:` does not start with `nu`; a reusable-workflow caller job is
  exempt because it cannot carry `defaults`.
- `SPEC-3.17.3` The guard must exit 2 when the directory does not exist or holds no workflow file, exit 1 with an
  `error:` line per problem otherwise, and `--self-test` must exit 1 unless a job without the default and a step with
  `shell: bash` are rejected and a converted job and a reusable-workflow caller are accepted.
- `SPEC-3.17.4` `check-no-bash.nu` must exit 1 for any git-tracked file under its directory argument (default
  `scripts`) that has the extension `sh` or whose first line is a shebang naming `sh`, `bash`, `dash`, `zsh` or `ksh`,
  printing the path and, for a shebang, the line number.

### 3.18 Workflow secret-scope guard (`scripts/check-workflow-secrets.nu` and fixtures)

- `SPEC-3.18.1` The guard must exit 2 when the workflows directory (default `.forgejo/workflows`) or its `e2e.yml` is
  missing, and must exit 1 when `e2e.yml` declares a `pull_request:` trigger (a line indented at most four spaces).
- `SPEC-3.18.2` For every workflow file declaring a `pull_request:` trigger, the guard must exit 1 for each
  `secrets.<NAME>` reference, comments excluded, whose name is not `E2E_STAGING_BASE_URL` or `OIDC_ISSUER_STAGING`.
- `SPEC-3.18.3` The guard must exit 1 for any line under the workflows directory containing `npm ci` that lacks
  `--ignore-scripts`.
- `SPEC-3.18.4` The guard must exit 1 for any `secrets: inherit` line that lacks the marker `secret-scope-ok:` on the
  same line.
- `SPEC-3.18.5` The guard must exit 1 for any `uses:` of another repository's `.forgejo` or `.github` workflow file
  whose ref is not a 40-hex commit SHA and whose line lacks the marker `secret-scope-ok:`; local calls and action
  references are out of scope.
- `SPEC-3.18.6` The guard must match `pull_request:` and not `pull_request_target:`, because a `pull_request_target`
  run uses the base branch's workflow copy that a pull request cannot edit.
- `SPEC-3.18.7` The negative fixture directory `scripts/fixtures/workflow-secrets-bad` must hold an `e2e.yml` without a
  `pull_request` trigger, so the guard is not stopped by the missing-file exit, and a PR-triggered
  `pr-with-secret.yml` referencing `secrets.PAT`, so the guard run against that directory must exit non-zero.

### 3.19 Security invariant guard (`scripts/check-security-invariants.nu`)

- `SPEC-3.19.1` The guard must exit 1 when any line under `bunyip-api/src` or `crates` contains `let secure =
  config.is_production()`, because the cookie `Secure` attribute must derive from the transport.
- `SPEC-3.19.2` The guard must exit 1 when any line under `bunyip-web/src` contains `use_secure_cookies`.
- `SPEC-3.19.3` The guard must exit 1 when any `crates/*/Cargo.toml` line matches `dunite.*branch *=`, because the
  shared kernel must be pinned by `rev`.
- `SPEC-3.19.4` The guard must exit 1 when `bunyip-api/src/handlers/billing.rs` holds a non-comment line containing
  `find_by_email`, because the billing set-up endpoint must not reveal whether an email is registered.
- `SPEC-3.19.5` For `bunyip-api/oci-build/Dockerfile` and `bunyip-web/oci-build/Dockerfile`, every `FROM` reference
  other than `scratch` must contain `@sha256:`, or be a bare name that is a stage defined by `FROM ... AS <name>` in the
  same file; any other reference must be reported and exit 1.
- `SPEC-3.19.6` On any failure the guard must print each hit as `file:line:text` on stderr and exit 1; on success it
  must print that all invariants hold.

### 3.20 Retired and forbidden environment name guards (`check-no-stripe-env.nu`, `check-no-retired-env.nu`)

- `SPEC-3.20.1` `check-no-stripe-env.nu` must exit 1 for every match of `[A-Z0-9_]*STRIPE_[A-Z0-9_]+` in a git-tracked
  file, reporting the file, line and name, except matches containing `E2E_` and the four names `STRIPE_SECRET_KEY`,
  `STRIPE_SECRET_KEY_FILE`, `STRIPE_WEBHOOK_SECRET` and `STRIPE_WEBHOOK_SECRET_FILE`.
- `SPEC-3.20.2` `check-no-stripe-env.nu` must skip files under `bunyip-api/migrations/` and `e2e/` and the scripts
  matching `scripts/check-no-*-env.nu`, and a tracked file that cannot be read or decoded must be treated as having no
  matches.
- `SPEC-3.20.3` `check-no-retired-env.nu` must exit 1, naming the file, line and matched text, for any match in a
  git-tracked file of `(TOTP|STRIPE)_(ENCRYPTION_KEY(_PREV|_FILE)?|KEY_VERSION)`,
  `BUNYIP_OIDC_(CLIENT_ID|REDIRECT_URI|SCOPES)` or `BRAND_THEME_(CSS|COLOR_LIGHT|COLOR_DARK)`, and must print the
  remedy text for each family that matched.
- `SPEC-3.20.4` `check-no-retired-env.nu` must skip files under `bunyip-api/migrations/` and the scripts matching
  `scripts/check-no-*-env.nu`.

### 3.21 Environment documentation parity guards (`check-env-parity.nu`, `check-compose-env-parity.nu`)

- `SPEC-3.21.1` `check-env-parity.nu` must collect every `var("NAME")` argument in `bunyip-web/src/config.rs` and must
  exit 1 with an error when none is found.
- `SPEC-3.21.2` `check-env-parity.nu` must exit 1, with one error line per name, for each collected name that has no
  `NAME=` or `# NAME=` line at the start of a line of `.env.example`.
- `SPEC-3.21.3` `check-compose-env-parity.nu` must exit 1 unless each of `compose.yml`, `compose.dev.yml` and
  `compose.dev-sso.yml` contains an indented `APP_URL:` line and an indented `BUNYIP_WEB_ORIGIN:` line anywhere in the
  file.
- `SPEC-3.21.4` `check-compose-env-parity.nu` must exit 1 unless `compose.yml` also contains an indented line for each
  of `SUPPORT_INBOX_EMAIL`, `SUPPORT_IMAP_POLL_SECS`, `INFISICAL_ENABLED`, `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`,
  `INFISICAL_ENVIRONMENT`, `INFISICAL_SECRET_PATH`, `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET`.
- `SPEC-3.21.5` For both guards, `--self-test` must exit 1 unless the real tree passes and a tree with one required
  name renamed fails.

### 3.22 Configuration documentation drift guard (`scripts/check-doc-surface.nu`)

- `SPEC-3.22.1` The guard must read the quoted names inside `WRITTEN_ENV_INVENTORY` in
  `crates/bunyip-domain/src/config.rs`, the quoted names inside `SYSTEM_LEVEL_ENV_KEYS` in
  `crates/bunyip-domain/src/sys_config.rs`, and the quoted names in the `GovernedSecret::name` match arms in
  `config.rs`, and must exit 1 with an error naming the source when any of the three sets is empty.
- `SPEC-3.22.2` The guard must compare the inventory names with the backtick-quoted names in the first column of the
  `## Required` and `## Feature-gating` tables, the `## Defaulted` list and the `## bunyip-web` paragraph of
  `docs/configuration.md`; the system-level keys with the first column of the `## The configuration boundary` table;
  and the governed secrets with the first column of the ``## `SECRETS_STORAGE` `` table.
- `SPEC-3.22.3` On any difference in either direction the guard must print one `error:` line per set naming the names
  present on only one side and exit 1.
- `SPEC-3.22.4` A documented name must contain an underscore, with the single exception of `ENVIRONMENT`, so prose words
  in backticks are not mistaken for variables.
- `SPEC-3.22.5` `--self-test` must exit 1 unless the real tree matches and an injected extra name in the inventory, in
  the system-level keys and in the governed-secret table are each reported.

### 3.23 CLAUDE.md index guard (`scripts/check-claude-md.nu`)

- `SPEC-3.23.1` The guard must report a problem and exit 1 when `CLAUDE.md` is absent, larger than 20000 bytes, or has a
  line outside a fenced code block longer than 400 characters.
- `SPEC-3.23.2` For every Markdown link on an unfenced `CLAUDE.md` line whose target starts with `docs/`, the guard
  must report a problem when the file does not exist and, when an `#anchor` is present, when the target is not a file or
  no heading in it slugs to that anchor (lowercase, punctuation dropped, spaces to hyphens, repeats suffixed `-1`,
  `-2`).
- `SPEC-3.23.3` The guard must report each non-private recipe marked `[group: 'release']` in `common/common.just` whose
  name appears neither in `CLAUDE.md` nor in a `docs/` file that `CLAUDE.md` links, and must report nothing for this
  check when `common/common.just` or `CLAUDE.md` does not exist.
- `SPEC-3.23.4` `--self-test` must exit 1 unless a resolving link passes and a missing file, a missing anchor, a long
  line, an oversized file and a release recipe named in no doc fail, while a long line inside a fence and a private
  release recipe pass.

### 3.24 Committed Tailwind output guard (`scripts/check-css-current.nu`)

- `SPEC-3.24.1` The guard must read the `@source "<path>"` lines of `bunyip-web/input.css`, resolve them against
  `bunyip-web/`, and exit 1 for every directory `crates/<name>/src` that holds a Rust file containing `class="` and is
  neither named by an `@source` path nor under one.
- `SPEC-3.24.2` The guard must exit 1 with an explanatory error when `bunyip-web/input.css` is unreadable, and when a
  `crates/*/src/**/*.rs` file is not readable as UTF-8, instead of reporting nothing declared.
- `SPEC-3.24.3` The guard must build the stylesheet to a temporary path with `bun install --frozen-lockfile` and `bun
  run build:css --output <path>` in `bunyip-web/` when `bun` is on `PATH`, and otherwise inside the pinned builder
  image with the repository bind-mounted and the output directory mounted at `/out`; when neither `bun` nor `docker` is
  available it must exit 1 with an error and must never install a toolchain.
- `SPEC-3.24.4` A failing build command must print its exit code, stdout and stderr and exit 1.
- `SPEC-3.24.5` The guard must compare the fresh output with `bunyip-web/assets/styles.css` byte for byte, and must
  exit 1 printing both byte lengths and SHA-256 digests when they differ, when the fresh build produced no output, or
  when the committed file is unreadable.
- `SPEC-3.24.6` The guard must hash the committed stylesheet before and after the build and must exit 1 with a message
  that the guard rewrote it if the digests differ.
- `SPEC-3.24.7` `--self-test` must exit 1 unless a declared markup crate and an ancestor `@source` pass, an undeclared
  crate and a new undeclared crate are reported, and an equal, different, truncated, missing and not-produced
  stylesheet are classified correctly.

### 3.25 Scrollbar contract guard (`scripts/check-scrollbars.nu`)

- `SPEC-3.25.1` The guard must scan `bunyip-web/input.css` and `bunyip-web/assets/styles.css` with comments removed and
  must report a problem for `scrollbar-width: none`, a `::-webkit-scrollbar*` rule containing `display: none`, and
  `scrollbar-gutter: stable`, anywhere including the Firefox block.
- `SPEC-3.25.2` The guard must report a problem for any `scrollbar-width` or `scrollbar-color` declaration outside the
  `@supports not selector(::-webkit-scrollbar)` block, because Chromium then ignores the WebKit scrollbar rules.
- `SPEC-3.25.3` The guard must report a problem for any rule on `::-webkit-scrollbar`, `-track`, `-track-piece` or
  `-corner` (including pseudo-class variants) that declares a `background`, `background-color` or `background-image`
  other than `transparent`, `#0000`, `#00000000` or `none`.
- `SPEC-3.25.4` Each stylesheet must contain a `::-webkit-scrollbar` rule with `width: 14px` and with `height: 14px`, a
  `::-webkit-scrollbar-track` background of `transparent`, a `::-webkit-scrollbar-thumb` background of
  `hsl(var(--<token>) / var(--sb-alpha))`, an `@property --sb-alpha` rule with syntax `"<number>"`, `inherits: true` and
  `initial-value: 1`, and the Firefox `@supports not selector(::-webkit-scrollbar)` block with `scrollbar-width: thin`
  and a `scrollbar-color` of that thumb color over a transparent track; each missing item must be reported.
- `SPEC-3.25.5` `bunyip-web/assets/js/app.js` must declare `SCROLLBAR_IDLE_MS` exactly once (`var`, `let` or `const`,
  digits with optional `_`) with a value from 5000 to 7000 inclusive; a missing, repeated or out-of-range declaration
  must be reported.
- `SPEC-3.25.6` An unreadable stylesheet or script must be reported as a problem, any problem must exit 1, and
  `--self-test` must exit 1 unless every compliant and violating fixture is classified as expected.

### 3.26 Theme token guard (`scripts/check-theme-colors.nu`)

- `SPEC-3.26.1` The guard must exit 1 when `bunyip-web/assets/js/*.js` matches no file, and must report each
  `<prefix>-<scale>-<number>` utility in those files, where prefix is one of `bg`, `text`, `border`, `from`, `via`,
  `to`, `ring`, `fill`, `stroke`, `divide`, `placeholder`, `caret`, `accent`, `outline`, `decoration`, `shadow` and scale
  is a stock Tailwind scale other than `teal`, `indigo`, `violet` and `amber`; whole-line `//` comments are skipped.
- `SPEC-3.26.2` The guard must report any hex colour (`#` plus 3 to 8 hex digits at a word boundary) or any `rgb`,
  `rgba`, `hsl`, `hsla`, `oklch`, `oklab` function call in `bunyip-web/src/views/layout.rs`,
  `bunyip-web/src/config.rs` and `crates/web-kit/src/shell.rs`, scanning each file only up to its first `#[cfg(test)]`
  line and skipping whole-line `//` comments.
- `SPEC-3.26.3` For `bunyip-web/input.css`, the guard must locate the `@theme inline` block by brace depth, and must
  report any `--color-*` line inside it holding a bare hex literal, except as the fallback of `var(--skin-*, <hex>)` or on
  a line containing `theme-literal-ok:`; a missing block must be reported.
- `SPEC-3.26.4` For `bunyip-web/input.css`, the guard must report every theme-block token declared as `--<token>: <h> <s>%
  <l>%;` outside the `@theme inline` block that has no `hsl(var(--<token>))` reader anywhere in the file.
- `SPEC-3.26.5` An unreadable input must be reported as a problem, any problem must exit 1, and `--self-test` must exit
  1 unless each compliant and violating fixture and an unreadable file in all three checks are classified as expected.

### 3.27 User-facing copy guard (`scripts/check-ui-copy.nu`)

- `SPEC-3.27.1` The guard must scan `{bunyip-web/src,crates/web-kit/src}/**/*.rs` and `bunyip-web/assets/js/**/*.js`,
  must exit 1 when neither glob matches a file, and in Rust files must scan only double-quoted string literals and stop
  at the first `#[cfg(test)]` line; JavaScript files scan single- and double-quoted literals with no such stop.
- `SPEC-3.27.2` The guard must skip whole-line `//` comments and must report, with file, line and the literal, a string
  literal containing three dots `...`, an ASCII emoticon (`:` or `;`, optional `-`, then one of `(`, `)`, `D`, `P`, `p`, at
  a word edge) or an issue key `(BUNYIP|PMS|MAPPS|LC|SF|SFT|DEV|GOV|AUDIT|PSA|A8N|ROCI|CLAUDE)-<digits>`.
- `SPEC-3.27.3` The issue-key rule must not apply to a literal on a line matching a log, assertion, `panic!`, `expect(`,
  `unreachable!` or attribute shape, nor to literals inside a multi-line `tracing::` / `info!`-family / `assert*!` /
  `panic!` invocation up to the line holding its closing `);`.
- `SPEC-3.27.4` An unreadable file must be reported as a problem, any problem must exit 1, and `--self-test` must exit 1
  unless each compliant and violating fixture, and an unreadable file, are classified as expected.

### 3.28 Compiled-in price and brand guards (`check-price-literals.nu`, `check-brand-literals.nu`)

- `SPEC-3.28.1` `check-price-literals.nu` must scan `{bunyip-web/src,crates/web-kit/src}/**/*.rs`, must exit 1 when the
  glob matches no file, and must join all double-quoted literals on a line before matching so copy split across
  fragments is caught.
- `SPEC-3.28.2` `check-price-literals.nu` must report a joined literal matching a price per period (`$`, euro or pound
  sign, digits, then `/`, `per` or `a`, then `month`, `mo`, `year` or `yr`) or `within <N> day(s)|month(s)`, skipping
  whole-line `//` comments and any line containing `price-literal-ok:`.
- `SPEC-3.28.3` `check-brand-literals.nu` must scan `bunyip-web/src/{views,handlers,skin}/**/*.rs`,
  `bunyip-web/src/skin/docs/**/*.md` and `crates/web-kit/src/**/*.rs`, must exit 1 when none matches, and must report any
  line, comments included, containing the case-sensitive standalone word `Bunyip` not followed by `-`, `_` or a digit,
  except a line containing `brand-literal-ok:`.
- `SPEC-3.28.4` For both guards an unreadable file must be reported as a problem, any problem must exit 1, and
  `--self-test` must exit 1 unless each compliant and violating fixture and an unreadable file are classified as expected.

### 3.29 Em-dash guard (`scripts/check-em-dash.nu`)

- `SPEC-3.29.1` The guard must exit 1 with an error when `git ls-files` returns no file, and must otherwise scan every
  tracked path that is a regular file for the character U+2014, built from its codepoint so the script itself does not
  contain it.
- `SPEC-3.29.2` Every line holding U+2014 must be reported as `<path>:<line>: contains an em-dash` and the guard must
  exit 1; the two committed migrations `20260417000040_create_oidc_clients.sql` and `20260417000042_create_oidc_tokens.sql`
  under `bunyip-api/migrations/` are the only exempt paths.
- `SPEC-3.29.3` A file containing a NUL byte must be skipped and counted; a file that cannot be opened or is not valid
  UTF-8 must be reported as an error naming the path and must exit 1.
- `SPEC-3.29.4` On success the guard must print the numbers of files checked and skipped; `--self-test` must exit 1
  unless a hyphen passes, an em-dash is caught, an undecodable file fails naming its path and a binary file is skipped.

### 3.30 Response-model compatibility guard (`scripts/check-serde-compat.nu`)

- `SPEC-3.30.1` The guard must read `bunyip-web/src/api/types.rs` (or the path argument), scan it up to the first
  `mod tests` line, and for each `pub struct` preceded by a `#[derive(...)]` containing `Deserialize` collect every
  `pub <field>:` not preceded by a `#[serde(...)]` attribute containing `default`.
- `SPEC-3.30.2` The guard must exit 1 for a collected field absent from `ESSENTIAL_FIELDS` and for an
  `ESSENTIAL_FIELDS` entry that is not a collected field, so the table lists exactly the fields that stay required.
- `SPEC-3.30.3` The guard must exit 1 with `file not found` when the types file does not exist.
- `SPEC-3.30.4` Each `ESSENTIAL_FIELDS` entry must name a `Struct.field` and a reason a default would be wrong; the
  guard governs response structs only, so request structs in `bunyip-api` keep their required inputs.
- `SPEC-3.30.5` `--self-test` must exit 1 unless an undeclared undefaulted field and a stale entry fail, and a declared
  field, both `#[serde(default)]` spellings, a `Serialize`-only struct pass and a missing file fails.

### 3.31 Argon2 offload guard (`scripts/check-argon2-offload.nu`)

- `SPEC-3.31.1` The guard must scan every git-tracked `*.rs` file and exit 1 for a match of
  `self.password.hash(` or `self.password.verify(` in any file.
- `SPEC-3.31.2` The guard must exit 1 for `PasswordService::new` in any file not in `ALLOW_CONSTRUCT`, and for a call of
  `.hash(` or `.verify(` on `password_service`, `password_svc` or `hasher` in any file not in `ALLOW_DIRECT_CALL`.
- `SPEC-3.31.3` The guard must exit 1 for `Argon2::new(` or `Argon2::default(` in any file not in `ALLOW_RAW_ARGON2`.
- `SPEC-3.31.4` The guard must exit 1 for `Self::hash_code_argon2(` or `Self::verify_code_against_hash(` in any file
  except `crates/bunyip-domain/src/services/totp.rs`, and must require exactly 2 such call sites in that file and exit 1
  also when the file is missing.
- `SPEC-3.31.5` Each hit must be printed as `error: <file>:<line>: <text>`, and `--self-test` must exit 1 unless each of
  six violating snippets is detected and a call through `argon2_offload` is accepted.

### 3.32 Configuration documentation generator (`scripts/config-docs.nu`)

- `SPEC-3.32.1` `config-docs.nu` must provide the subcommands `generate`, `check`, `since <version>`, `release-notes
  <version>` and `self-test`; with none it must print a usage line.
- `SPEC-3.32.2` The script must read the variable names and classes (`required`, `required_in_production`, `gating`,
  `defaulted`) from the `EnvVarSpec::<class>("NAME"` entries of `WRITTEN_ENV_INVENTORY` in
  `crates/bunyip-domain/src/config.rs`, and must fail with an error when the definition, its `\n];` terminator or every
  entry is missing.
- `SPEC-3.32.3` The script must merge them with `crates/bunyip-domain/config/variables.toml` (`[[variable]]` with `since`,
  `required`, `deprecated`; `[[removed]]` tombstones; `[[change]]` records) and must report as errors an inventory name
  with no `[[variable]]` row, a `[[variable]]` row no longer in the inventory, a duplicated name, and any release field
  that is not `vX.Y.Z`.
- `SPEC-3.32.4` Each `[[change]]` record must use a group in `Added`, `Changed`, `Deprecated` or `Removed`, a `breaking`
  of `wont-start`, `feature-off` or empty, and variables that exist in the catalog; an `Added`, `Deprecated` or
  `Removed` record must match a fact-derived entry, and only `Changed` records may add entries; violations must be
  reported as errors.
- `SPEC-3.32.5` A fact-derived `Added` entry for a required variable whose `since` is not `v0.1.0` must be marked
  `wont-start`; in the releases covered by the Recently-added window (the unreleased versions and the latest 5 release
  tags), every marked entry must carry a non-empty action and an issue id matching `^[A-Z]+-\d+$`, and a `feature-off`
  entry must name its `feature`.
- `SPEC-3.32.6` `generate` must exit 1 listing the fact errors if any, must otherwise rewrite only the text between the
  `<!-- BEGIN GENERATED: recently-added (just config-docs) -->` / `END` markers and the `all-variables` markers of
  `docs/configuration.md` (failing with an error naming the markers to add when either pair is missing or out of
  order), and must leave the file unchanged and print `is current` when the result equals the file.
- `SPEC-3.32.7` `check` must exit 1 listing every disagreement between `docs/configuration.md` and the facts: a
  malformed, missing, duplicated or unknown row in the All-variables list, a wrong anchor, Required, Added-in or
  Classification cell, a Recently-added entry not recorded by the facts, a wrong Required or Breaking mark, a missing
  issue or feature, a wrong anchor, and a covered entry missing from the Recently-added section.
- `SPEC-3.32.8` `since <version>` must list, newest first, every entry released after that version with its change
  kind, requirement, level, issue and action (JSON with `--json`), and a count line of won't-start and feature-off
  entries; with no entries it must print `No configuration changes after <version>.`.
- `SPEC-3.32.9` `release-notes <version>` must print a `## Configuration changes` block with a link to the
  documentation at tag `--ref` (default the version) and the Breaking entries, or a no-changes line.
- `SPEC-3.32.10` `self-test` must exit 1 unless a generated document passes, regeneration is idempotent, and a missing
  row, a wrong `since` and a missing Breaking mark are each reported.

### 3.33 Development secrets bootstrap (`scripts/init-secrets.nu`)

- `SPEC-3.33.1` The script must create `./secrets` and `./secrets/oidc` with mode 700, and must never overwrite a
  non-empty secret file; for such a file it must print `kept <path>`.
- `SPEC-3.33.2` For `jwt_secret`, `webhook_signing_secret`, `app_encryption_key` and `postgres_password` it must use the
  value of `JWT_SECRET`, `BUNYIP_WEBHOOK_SIGNING_SECRET`, `APP_ENCRYPTION_KEY` and `POSTGRES_PASSWORD` from `./.env`
  when set, and otherwise generate `openssl rand -hex 32`; a `.env` value that is empty, starts with `dev-only-`,
  starts with `admin@bunyip.local:`, or equals `devpassword` or `changeme` must count as not set.
- `SPEC-3.33.3` `postgres_password` must never be left empty; `database_url` must be taken from `DATABASE_URL` in
  `.env` when set, and otherwise derived as `postgres://<user>:<password>@postgres:5432/<db>` from the password file with
  `POSTGRES_USER` and `POSTGRES_DB` defaulting to `bunyip`.
- `SPEC-3.33.4` The script must create `bunyip_app_password`, `app_database_url`, `setup_default_admin`,
  `forgejo_api_token`, `update_check_token` and `mailer_webhook_secret` from the matching `.env` variable when set and as
  an empty file otherwise, and must create no Stripe secret file.
- `SPEC-3.33.5` Secret files must be written byte-exact (no trailing newline) with mode 600.
- `SPEC-3.33.6` The script must ensure `./secrets/oidc/dev-2026.pem` and `dev-2026.pub.pem`: keep an existing key,
  otherwise move a legacy `./secrets/dev-2026.pem` (and public key) into `./secrets/oidc/`, otherwise generate an
  ed25519 key pair with `openssl`, each file mode 600.
- `SPEC-3.33.7` The script must tell the operator to edit both `postgres_password` and `database_url` when rotating, and
  must say when the password was generated.

### 3.34 Test-account purge (`scripts/purge-staging-test-accounts.nu`)

- `SPEC-3.34.1` The script must exit 2 with an error when neither `--database-url` nor `$env.DATABASE_URL` is set and
  when `--pattern` is empty; `--pattern` has no default.
- `SPEC-3.34.2` Unless `--commit` is given the script must be read-only: it must print the target host (credentials
  removed), the pattern, the matched rows and count of `users` whose `email` is `LIKE` the pattern and whose `role` is
  not `admin`, then print `DRY RUN: no rows deleted` and exit 0.
- `SPEC-3.34.3` The database password must be removed from the connection string and passed only as `PGPASSWORD` to
  the `psql` child, and the pattern must be passed as a `psql` variable, with the SQL fed on stdin.
- `SPEC-3.34.4` With `--commit` and without `--i-know-this-is-not-prod` the script must print a refusal and exit 3; with
  zero matched rows it must print `nothing to delete; exiting.` and exit 0.
- `SPEC-3.34.5` With `--commit` the script must require the interactive confirmation phrase `purge test accounts`; an
  unavailable terminal or a different phrase must exit 3 with no rows deleted.
- `SPEC-3.34.6` The delete must run in one transaction with `ON_ERROR_STOP=1`: resolve the matched ids once into a
  temporary table, delete their `audit_logs` rows by `actor_id`, delete their `admin_notifications` rows by `user_id`,
  null `admin_notifications.read_by` for them, then delete from `users`, never touching admin-role rows or encryption
  keys.

### 3.35 Database reconcile script and geo-dataset refresh

- `SPEC-3.35.1` `scripts/reconcile-sqlx-checksums.sql` must be run with `psql --single-transaction --set
  ON_ERROR_STOP=on`, so a failure in any block rolls back the whole script.
- `SPEC-3.35.2` For each of the 11 listed migration versions the script must set `_sqlx_migrations.checksum` to the
  recorded SHA-384 value for that version, and where the edited migration changes the schema it must apply that change
  idempotently (guarded by `pg_constraint` or `information_schema` lookups, `ADD COLUMN IF NOT EXISTS`).
- `SPEC-3.35.3` Before adding a `UNIQUE` or `CHECK` constraint over existing rows the script must raise an exception
  naming the offending count when duplicate `email_change_requests.token_hash` values, or `oauth_clients` rows with
  `refresh_idle_ttl_seconds` outside 3600 to 7776000, exist.
- `SPEC-3.35.4` The script must finish by counting the 11 versions in `_sqlx_migrations` and raising an exception
  stating how many are missing if the count is not 11.
- `SPEC-3.35.5` `scripts/refresh-ip2-datasets.nu` must exit 1 with a message when `IP2LOCATION_TOKEN` is empty or when
  `curl` or `unzip` is not on `PATH`, and must read `DATASET_DIR` (default `/data`) and `DATASETS` (default `PX11 DB11`).
- `SPEC-3.35.6` For dataset `PX11` it must install `IP2PROXY-LITE-PX11.BIN` and for `DB11` `IP2LOCATION-LITE-DB11.BIN`
  into `DATASET_DIR`; an unknown id must be reported on stderr and counted as a failure.
- `SPEC-3.35.7` Each dataset must be downloaded with the token passed to `curl` on stdin as a config, never on the
  command line, and must fail with a message when the download fails, when the archive fails `unzip -tq`, or when it
  holds no `.BIN` entry.
- `SPEC-3.35.8` Each dataset must be extracted to a temporary directory, staged in `DATASET_DIR` under a name carrying
  the process id, and renamed into place, so a reader never sees a partial file.
- `SPEC-3.35.9` The script must remove its temporary directory when done, and must exit 1 with `one or more datasets
  failed` if any dataset failed or an error was raised.

### 3.36 E2E configuration and project model

- `SPEC-3.36.1` `e2e/lib/env.ts` must load `e2e/.env` through dotenv without overriding variables already set in the
  process environment, and `E2E_BASE_URL` must be required: a missing or blank value must throw an error naming
  `E2E_BASE_URL` at import time.
- `SPEC-3.36.2` The accessors `email`, `password`, `tenantId`, `oidcClientId`, `oidcRedirectUri` and `totpSecret` must
  read `E2E_EMAIL`, `E2E_PASSWORD`, `E2E_TENANT_ID`, `E2E_OIDC_CLIENT_ID`, `E2E_OIDC_REDIRECT_URI` and `E2E_TOTP_SECRET`
  at access time, trim them, and throw an error naming the variable when it is missing or blank.
- `SPEC-3.36.3` The base URLs must have trailing slashes removed. `opBaseURL` must be `E2E_OP_BASE_URL` when set, else
  `https://api.<hub host>` derived from `E2E_BASE_URL` when the hub host does not already start with `api.`, else the hub
  URL; `apiBaseURL` must be `E2E_API_BASE_URL` when set, else `opBaseURL`.
- `SPEC-3.36.4` `stripeSecretKey` and `mailSinkURL` must be optional (undefined when unset or blank), and
  `isProductionApex` must be true only when the hub host equals the production apex host, so billing write specs skip on
  production.
- `SPEC-3.36.5` `preflightRequiredEnv` must throw one error listing every missing variable of `E2E_BASE_URL`,
  `E2E_EMAIL`, `E2E_PASSWORD`, `E2E_TENANT_ID`, `E2E_OIDC_CLIENT_ID`, `E2E_OIDC_REDIRECT_URI` and `E2E_TOTP_SECRET` with
  its purpose, and return normally when none is missing.
- `SPEC-3.36.6` `playwright.config.ts` must run one worker with `fullyParallel: false`, a 60 s test timeout, a 15 s
  expect timeout, `retries: 2` only when `CI` is set, `forbidOnly` when `CI` is set, `channel: 'chromium'` and Chromium
  args `--disable-dev-shm-usage`, `--disable-gpu` and `--no-sandbox`, with trace on first retry and screenshot and video
  retained on failure.
- `SPEC-3.36.7` The configuration must define the projects `preflight` (`preflight.setup.ts`), `setup` (`global.setup.ts`,
  depends on `preflight`, `retries: 0`), `auth-ui` (`tests/auth/*.spec.ts`, depends on `preflight`, `retries: 0`,
  anonymous), `account-ui` (`tests/(account|memberships|billing)/*.spec.ts`, depends on `setup`, replays storage state
  `./.auth/hub-state.json`) and `api` (`tests/oidc/*.spec.ts`, depends on `setup` and `account-ui`, base URL
  `opBaseURL`), and a global teardown at `./tests/global.teardown.ts`.
- `SPEC-3.36.8` `e2e/.env.example` must document every `E2E_*` variable the suite reads (`E2E_BASE_URL`,
  `E2E_OP_BASE_URL`, `E2E_API_BASE_URL`, `E2E_EMAIL`, `E2E_PASSWORD`, `E2E_TENANT_ID`, `E2E_OIDC_CLIENT_ID`,
  `E2E_OIDC_REDIRECT_URI`, `E2E_TOTP_SECRET`, `E2E_STRIPE_SECRET_KEY`, `E2E_MAIL_SINK_URL`), and `e2e/.gitignore` must
  exclude `node_modules/`, `.auth/`, `playwright-report/`, `blob-report/`, `test-results/`, `playwright/.cache/` and
  `.env`.
- `SPEC-3.36.9` `e2e/package.json` must pin `@playwright/test` to `1.60.0` and be an ES module package, and
  `e2e/package-lock.json` must lock the same versions; `e2e/tsconfig.json` must compile in strict mode with no emit.
  These two JSON files and the lockfile cannot hold comments and are cited by name only.

### 3.37 E2E gate scripts

- `SPEC-3.37.1` `wait-for-deploy.mjs` must exit 1 with an error when `E2E_BASE_URL` is empty, and when neither
  `GITHUB_SHA` nor `E2E_EXPECT_SHA` is set. It must take the OP host from `E2E_OP_BASE_URL`, else `https://api.<hub
  host>`, else the hub URL, with trailing slashes removed.
- `SPEC-3.37.2` The script must resolve the expected commit as the most recent commit at or before the head commit that
  touched any `BUILD_TRIGGER_PATHS` entry (`git log -1 --format=%H <head> -- <paths>`), unshallowing the clone and then
  refetching without a filter when the first query finds nothing.
- `SPEC-3.37.3` When no expected commit can be resolved the script must print a loud warning stating the commit the
  deployment is serving, and exit 0 without polling.
- `SPEC-3.37.4` The script must poll `<op host>/v1/version` every 15 s for at most 10 minutes and exit 0 as soon as the
  reported `commit` is non-empty and a prefix of the expected commit; on timeout it must print `Timed out after 10m` and
  exit 1.
- `SPEC-3.37.5` `BUILD_TRIGGER_PATHS` must equal the shared push `paths` filter of the two build workflows with each
  trailing `/**` removed (`SPEC-3.15.3`).
- `SPEC-3.37.6` `health-check.mjs` must exit 1 when `E2E_BASE_URL` is empty, must hard-probe `<op host>/health` with a 30 s
  timeout and exit 1 on a non-2xx status or a network error, and must then probe `<hub>/healthz`.
- `SPEC-3.37.7` The hub probe must treat a response as live only when it is 2xx and its JSON body has `status` equal to
  `ok`; otherwise, and on a network error, it must exit 1 unless the probe is soft, in which case it must print a warning
  and continue. The probe is soft when the hub host is the production apex host or `E2E_HUB_SOFT` equals `true`.
- `SPEC-3.37.8` `check-bootstrapped.mjs` must request `<op host>/e2e-bootstrapped` with a 15 s timeout, append
  `bootstrapped=<true|false>` to `$GITHUB_OUTPUT`, report `true` only for an HTTP success whose JSON `bootstrapped` is
  exactly `true`, and report `false` and print a warning on a non-success status, a network or parse error, or no
  configured URL.
- `SPEC-3.37.9` `check-bootstrapped.mjs` must always exit 0.

### 3.38 E2E authentication helpers

- `SPEC-3.38.1` `loginViaHub` must disable `window.EventSource` before any page script runs (`blockLiveReload`), then
  open `/login`, and submit the form `form[action="/login"]` with `E2E_EMAIL` and `E2E_PASSWORD` set through the DOM, and
  `setInputValue` must retry the set up to 5 times and throw an error when the value does not stick.
- `SPEC-3.38.2` `loginViaHub` must treat the login as successful only when the browser path leaves `/login` and its
  sub-paths; when it sees a rendered rate-limit message (`too many` or `rate limit`) it must wait the stated number of
  seconds plus 1 s (default 5 s, capped at 60 s before the cushion) and resubmit, up to 4 attempts.
- `SPEC-3.38.3` On a rejection that is not a rate limit, or after the last attempt, `loginViaHub` must throw an error
  naming the current path and the rendered error text, or stating that no message was rendered.
- `SPEC-3.38.4` When the flow reaches `/login/2fa` (or `/login/mfa`), the helper must submit the current TOTP code from
  `E2E_TOTP_SECRET`, and on a rejection must wait for the next 30 s step and submit a fresh code once, throwing after
  two rejections.
- `SPEC-3.38.5` When the rendered 2FA error matches `unexpected error` or `try again later` the helper must throw an
  error stating the server returned an error and not a code rejection, without retrying.
- `SPEC-3.38.6` `logoutViaHub` must open the profile menu and click the button named exactly `Log out` inside it;
  `expectAuthenticated` must assert `GET /v1/users/me` returns 200, `expectAnonymous` must assert 401 or 403, and
  `expectAtLoginScreen` must poll up to 30 s for a path under `/login`.
- `SPEC-3.38.7` `readToken` must throw when `.auth/token.txt` is missing or blank, and `readOpStorageState` must throw
  when `.auth/op-state.json` is missing or holds no cookies, each stating that the `setup` project must run first.
- `SPEC-3.38.8` The `test` fixture must attach `Authorization: Bearer <token from .auth/token.txt>` to the request
  context for the project's base URL, and the `oidcTest` fixture must create a request context for `opBaseURL` with the
  stored OP cookies and no bearer; both must dispose the context after use.
- `SPEC-3.38.9` `bunyipWebPostHeaders` must return `{ Origin: <origin of E2E_BASE_URL> }` for state-changing POSTs to
  the web front end; `routes` must define the API paths under `/v1` and the root-mounted OIDC discovery and JWKS paths,
  `makePkce` must return an S256 pair with a base64url verifier, and `discoverOidc` must throw when discovery does not
  return success.

### 3.39 E2E disposable accounts, mail sink and run tagging

- `SPEC-3.39.1` `runSuffix` must return `e2e-<run start epoch ms>-<run id>-<counter>` with a counter starting at 1;
  the run id must be the first defined of `GITEA_RUN_ID`, `GITHUB_RUN_ID`, `E2E_RUN_ID`, else the run-start epoch,
  reduced to alphanumerics and at most 24 characters.
- `SPEC-3.39.2` `isOwnedByThisRun` must be true only for a name carrying a tag whose run id equals the current run id,
  `createdAtMs` must return the embedded epoch or null, and `isStale` must be true only when the embedded epoch is more
  than 24 hours old.
- `SPEC-3.39.3` `tagged(prefix)` must return `<prefix>-<runSuffix>`, and `today()` the current UTC date as `YYYY-MM-DD`.
- `SPEC-3.39.4` `registerDisposable` must fetch the register challenge, throw when it is not successful or returns no
  token, wait 2.1 s, then register a new account with a run-tagged plus-subaddress email, the constant password
  `E2e-Disposable-Passw0rd!` and the challenge token, and throw an error with the status and body when registration is
  not successful.
- `SPEC-3.39.5` The challenge fetch must retry only on HTTP 429, at most 3 retries, waiting the `Retry-After` seconds
  (else `2^attempt` seconds) capped at 10 s and logging a warning per wait, and must throw an error with the final
  headers and body after the last attempt.
- `SPEC-3.39.6` `deleteMe` must `DELETE /v1/users/me?purge=1` and `softDeleteMe` must `DELETE /v1/users/me`, both with
  the account password in the body; a thrown request error must be logged as a warning and not rethrown.
- `SPEC-3.39.7` `subaddress(tag)` must insert `+<tag>` before the `@` of the mail-sink mailbox, `sinkConnection` must
  throw when `E2E_MAIL_SINK_URL` is unset or carries no mailbox user, and credentials must be sent only as a Basic
  `Authorization` header with the userinfo removed from the base URL.
- `SPEC-3.39.8` `waitForLink` must poll the sink's JMAP service (default every 2 s for 30 s) for a message whose `To`
  header equals the exact subaddress and whose text or HTML body matches the link pattern, return the first match,
  destroy that message, and ignore every other message; the JMAP API origin must be forced back to the configured
  sink base.
- `SPEC-3.39.9` `waitForLink` must keep polling after a transient JMAP error and, on timeout, throw an error naming the
  address, the pattern, the timeout and the last poll error; `tokenFromLink` must throw when the link has no `token`.
- `SPEC-3.39.10` `attachPageDiagnostics` must record main-frame navigations and request URLs, and `snapshot(label)` must
  return the current URL and the last 30 of each.

## 4. Data model and migrations

The schema below is the final state after every file in `bunyip-api/migrations/` has been applied in version order.
Migrations are immutable and cannot hold citations; every requirement here is enforced by the named migration files.
All tables live in the default schema; all `id UUID` keys default to `gen_random_uuid()`; all `*_at TIMESTAMPTZ` columns
named `created_at`/`updated_at` default to `NOW()` unless stated; no migration creates a trigger, function, custom type
or extension, so no behavior below is implemented by a trigger and enumerations are `CHECK` constraints or plain text.

### 4.1 Migration mechanics

- `SPEC-4.1.1` Migrations must be applied by `sqlx::migrate!("./migrations")` at `bunyip-api` startup, ordered by the
  14-digit numeric version before the first underscore of the file name, and each version must be unique and greater
  than every earlier one.
- `SPEC-4.1.2` A committed migration must not be edited in place; a changed body changes its sqlx checksum and the
  startup then fails with `migration <version> was previously applied but has been modified`. Changes must ship as new
  forward-only files.
- `SPEC-4.1.3` The version `20241230000008` must remain an unused gap (its deleted seed file is not replaced), and
  trailing three-digit indexes may repeat across different dates without conflict.
- `SPEC-4.1.4` Before the migrator runs, startup must reconcile recorded checksums only for the allow-listed versions
  edited in place earlier, guarded by the pre-edit checksum so it is a no-op on any other drift.
- `SPEC-4.1.5` Before the migrator runs, startup must add the missing `application_entitlements_source_check`
  constraint to a database that applied the pre-edit `20260605000010` and has not yet applied `20260802000010`, so that
  migration's `DROP` then `ADD` succeeds; it must do nothing on virgin, fresh and fully migrated databases.
- `SPEC-4.1.6` Both startup reconcilers must test each relation with `to_regclass` before reading it, because they run
  before the migrator on a database that may have no tables.
- `SPEC-4.1.7` The shared `check-migration-versions` recipe must fail the check when two migrations share a version or are out of
  order.

### 4.2 users

- `SPEC-4.2.1` The `users` table must have these columns: `id UUID PK`; `email VARCHAR(255) NOT NULL`;
  `email_verified BOOLEAN NOT NULL DEFAULT FALSE`; `password_hash VARCHAR(255)` (NULL for passwordless accounts);
  `role VARCHAR(50) NOT NULL DEFAULT 'subscriber'`; `stripe_customer_id VARCHAR(255) UNIQUE`;
  `membership_status VARCHAR(50) NOT NULL DEFAULT 'none'`; `membership_tier VARCHAR(50) NOT NULL DEFAULT 'standard'`;
  `membership_override_by UUID REFERENCES users(id)`; `price_locked BOOLEAN NOT NULL DEFAULT FALSE`;
  `locked_price_id VARCHAR(255)`; `locked_price_amount INTEGER`; `grace_period_start TIMESTAMPTZ`;
  `grace_period_end TIMESTAMPTZ`; `trial_ends_at TIMESTAMPTZ`; `lifetime_member BOOLEAN NOT NULL DEFAULT FALSE`;
  `has_used_trial BOOLEAN NOT NULL DEFAULT FALSE`; `stripe_payment_method_id VARCHAR(255)`;
  `two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE`; `is_super_admin BOOLEAN NOT NULL DEFAULT FALSE`;
  `last_login_at TIMESTAMPTZ`; `deleted_at TIMESTAMPTZ`; `created_at` and `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.
- `SPEC-4.2.2` The `users` table must have the profile columns `first_name`, `last_name` and `phone`, each `TEXT`
  nullable with a `CHECK` that the value is NULL or at most 64 characters long.
- `SPEC-4.2.3` The `users` table must have `last_login_country TEXT` (NULL or at most 64 characters),
  `login_location_alerts BOOLEAN NOT NULL DEFAULT TRUE` and `avatar_updated_at TIMESTAMPTZ` (NULL when no avatar).
- `SPEC-4.2.4` The database must enforce email uniqueness case-insensitively and permanently: a unique index
  `users_email_unique` on `LOWER(email)` with no `WHERE` predicate, so a soft-deleted account keeps its email reserved.
  The earlier `users_email_key` constraint and the `users_email_unique_active` partial index must not exist.
- `SPEC-4.2.5` The `users` table must have non-unique indexes `idx_users_email (email)`,
  `idx_users_stripe_customer_id`, `idx_users_membership_status`, `idx_users_deleted_at`, `idx_users_lifetime_member`,
  and the partial index `idx_users_trial_ends_at (trial_ends_at) WHERE trial_ends_at IS NOT NULL`.
- `SPEC-4.2.6` The `users` table must not have columns named `subscription_status`, `subscription_tier` or
  `subscription_override_by`; they exist only under their `membership_*` names, and the earlier 2024 `membership_tier`
  column and its index were dropped before the rename reused that name.
- `SPEC-4.2.7` The `users` table must not have row level security enabled.
- `SPEC-4.2.8` The migration chain must mark exactly one account as super admin when it is applied: the oldest
  non-deleted user with role `admin`, if any exists.
- `SPEC-4.2.9` The migration chain must leave every stored `users.email` lowercased and, when two rows collided
  case-insensitively, must keep the oldest and rename the others to `<email>.dup-<id>`.

### 4.3 Credential and token tables

- `SPEC-4.3.1` The tables `password_reset_tokens` and `email_verification_tokens` must each have `id UUID PK`,
  `user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`, `token_hash VARCHAR(255) NOT NULL UNIQUE`,
  `expires_at TIMESTAMPTZ NOT NULL`, `used_at TIMESTAMPTZ`, `created_at` default `NOW()` and `ip_address INET`; both
  must have an index on `user_id`, and `password_reset_tokens` must also have non-unique indexes on `token_hash` and
  `expires_at`.
- `SPEC-4.3.2` The table `magic_link_tokens` must have `id`, `email VARCHAR(255) NOT NULL`,
  `token_hash VARCHAR(255) NOT NULL UNIQUE`, `expires_at NOT NULL`, `used_at`, `created_at` default `NOW()` and
  `ip_address INET`, with no foreign key, and non-unique indexes on `email`, `token_hash` and `expires_at`.
- `SPEC-4.3.3` The table `email_change_requests` must have `id`, `user_id NOT NULL REFERENCES users(id) ON DELETE
  CASCADE`, `new_email VARCHAR(255) NOT NULL`, `token_hash VARCHAR(255) NOT NULL UNIQUE`, `expires_at NOT NULL`,
  `confirmed_at`, `canceled_at`, `ip_address INET` and `created_at`; indexes on `user_id`, `token_hash` and `expires_at`.
- `SPEC-4.3.4` The legacy hub table `refresh_tokens` must have `id`, `user_id NOT NULL REFERENCES users(id) ON DELETE
  CASCADE`, `token_hash VARCHAR(255) NOT NULL UNIQUE`, `device_info VARCHAR(500)`, `ip_address INET`,
  `expires_at NOT NULL`, `created_at`, `last_used_at`, `revoked_at` and
  `op_session_id UUID NULL REFERENCES op_sessions(id) ON DELETE CASCADE` (NULL means the legacy absolute-TTL behavior);
  indexes on `user_id`, `token_hash` and `expires_at`.
- `SPEC-4.3.5` The table `user_totp` must have `id`, `user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE
  CASCADE`, `encrypted_secret BYTEA NOT NULL`, `nonce BYTEA NOT NULL`, `verified BOOLEAN NOT NULL DEFAULT FALSE`,
  `enabled_at`, `created_at`, `updated_at`, `key_version SMALLINT NOT NULL DEFAULT 1`, `last_used_step BIGINT`, the
  staged-replacement columns `pending_encrypted_secret BYTEA`, `pending_nonce BYTEA`, `pending_key_version SMALLINT`
  and `pending_created_at TIMESTAMPTZ`, and the setup-binding columns `setup_token_hash TEXT` and
  `setup_token_expires_at TIMESTAMPTZ`; an index on `user_id`.
- `SPEC-4.3.6` The table `recovery_codes` must have `id`, `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`,
  `code_hash TEXT NOT NULL`, `used_at` and `created_at`; an index on `user_id` and the partial lookup index
  `idx_recovery_codes_lookup (user_id, code_hash) WHERE used_at IS NULL`.
- `SPEC-4.3.7` The table `trusted_devices` must have `id`, `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`,
  `token_hash VARCHAR(255) NOT NULL UNIQUE`, `label VARCHAR(500)`, `ip_address INET`, `created_at`, `last_used_at`,
  `expires_at NOT NULL` and `revoked_at`; indexes on `user_id` and `token_hash`.
- `SPEC-4.3.8` The table `login_approval_codes` must have `id`, `user_id NOT NULL REFERENCES users(id) ON DELETE
  CASCADE`, `code_hash VARCHAR(255) NOT NULL`, `country VARCHAR(64)`, `ip_address INET`, `device_hash VARCHAR(255)`,
  `device_info TEXT`, `attempts INTEGER NOT NULL DEFAULT 0`, `expires_at NOT NULL`, `used_at`, `created_at` and
  `challenge_jti VARCHAR(255)`; indexes on `user_id`, `expires_at` and `(user_id, challenge_jti)`.
- `SPEC-4.3.9` The table `login_devices` must have `id`, `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`,
  `device_hash VARCHAR(255) NOT NULL`, `user_agent TEXT`, `first_seen_at` and `last_seen_at` (both `NOT NULL DEFAULT
  NOW()`), a `UNIQUE (user_id, device_hash)` constraint and an index on `user_id`.
- `SPEC-4.3.10` The table `admin_invites` must have `id`, `email TEXT NOT NULL`, `token_hash TEXT NOT NULL UNIQUE`,
  `invited_by UUID NOT NULL REFERENCES users(id)`, `role TEXT NOT NULL DEFAULT 'admin'`, `expires_at NOT NULL`,
  `accepted_at`, `revoked_at` and `created_at`; indexes on `email`, `token_hash` and `invited_by`.

### 4.4 Row level security

- `SPEC-4.4.1` Row level security must be both `ENABLE`d and `FORCE`d on exactly these tables: `trusted_devices`,
  `user_totp`, `recovery_codes`, `application_entitlements` and `email_change_requests`.
- `SPEC-4.4.2` Each of those tables must have one policy `user_isolation` with identical `USING` and `WITH CHECK`
  expressions `user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid`, so with the setting unset or
  empty a read returns no rows and a write is rejected rather than raising a cast error.
- `SPEC-4.4.3` The migrations must not create or alter database roles; the unprivileged `bunyip_app` role must be
  provisioned by deployment, and the migration owner role must bypass row level security.

### 4.5 Database role grants

- `SPEC-4.5.1` The role `bunyip_app` must be granted `SELECT, INSERT, DELETE` on `rate_limit_history`,
  `SELECT, INSERT, UPDATE, DELETE` on `rate_limit_traffic`, and `SELECT, UPDATE` on each of `mirzam_config` and
  `mokosh_config`; no other migration grants anything to it.
- `SPEC-4.5.2` The migrations that grant to `bunyip_app` must fail when that role does not exist.

### 4.6 applications

- `SPEC-4.6.1` The `applications` table must have: `id`; `name VARCHAR(255) NOT NULL UNIQUE`;
  `slug VARCHAR(100) NOT NULL UNIQUE`; `display_name VARCHAR(255) NOT NULL`; `description TEXT`;
  `icon_url VARCHAR(500)`; `is_active BOOLEAN NOT NULL DEFAULT TRUE`; `maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE`;
  `maintenance_message TEXT`; `container_name VARCHAR(255) NOT NULL`; `health_check_url VARCHAR(500)`;
  `version VARCHAR(50)`; `source_code_url VARCHAR(500)`; `subdomain VARCHAR(100)`; `webhook_url VARCHAR(500)`;
  `sort_order INTEGER NOT NULL DEFAULT 0`; `is_hosted BOOLEAN NOT NULL DEFAULT TRUE`;
  `requires_entitlement BOOLEAN NOT NULL DEFAULT FALSE`; `release_notes_url TEXT`;
  `group_id UUID REFERENCES application_groups(id) ON DELETE SET NULL`; `created_at`; `updated_at`.
- `SPEC-4.6.2` The `applications` table must have the download-proxy columns `forgejo_owner TEXT`, `forgejo_repo TEXT`,
  `pinned_release_tag TEXT`, `forgejo_package TEXT` and
  `artifact_source TEXT NOT NULL DEFAULT 'release' CHECK (artifact_source IN ('release', 'generic_package'))`.
- `SPEC-4.6.3` The `applications` table must have the registry-proxy columns `oci_image_owner TEXT`,
  `oci_image_name TEXT` and `pinned_image_tag TEXT`.
- `SPEC-4.6.4` The `applications` table must have the indexes `idx_applications_slug`, `idx_applications_is_active`,
  `idx_applications_is_hosted`, `idx_applications_group_id`, and two partial indexes on `id`:
  `applications_downloadable_idx WHERE forgejo_owner, forgejo_repo and pinned_release_tag are all NOT NULL` and
  `applications_pullable_idx WHERE oci_image_owner, oci_image_name and pinned_image_tag are all NOT NULL`.
- `SPEC-4.6.5` The migration chain must leave `sort_order` dense: after the chain, rows are numbered 1..N ordered by
  the previous `sort_order` then `display_name`.
- `SPEC-4.6.6` The table `application_groups` must have `id`, `name TEXT NOT NULL UNIQUE`, `slug TEXT NOT NULL UNIQUE`,
  `display_name TEXT NOT NULL`, `description TEXT`, `icon_url TEXT`, `sort_order INTEGER NOT NULL DEFAULT 0`,
  `created_at` and `updated_at`.
- `SPEC-4.6.7` The table `application_versions` must have `id`, `application_id UUID NOT NULL REFERENCES
  applications(id) ON DELETE CASCADE`, `version_tag TEXT NOT NULL`, `artifact_digest TEXT`,
  `published_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `release_notes_url TEXT`, `yanked BOOLEAN NOT NULL DEFAULT false`,
  `UNIQUE (application_id, version_tag)` and an index on `application_id`.
- `SPEC-4.6.8` The migration chain must seed one `application_versions` row for every distinct non-NULL
  `pinned_image_tag` and `pinned_release_tag` of each application present when it ran, ignoring duplicates.
- `SPEC-4.6.9` The table `application_docs` must have `id`, `application_id UUID NOT NULL REFERENCES applications(id)
  ON DELETE CASCADE`, `slug TEXT NOT NULL`, `title TEXT NOT NULL`, `body TEXT NOT NULL`,
  `sort_order INT NOT NULL DEFAULT 0`, `created_at`, `updated_at`, `UNIQUE (application_id, slug)` and an index on
  `(application_id, sort_order)`.

### 4.7 Entitlements

- `SPEC-4.7.1` The table `application_entitlements` must have `user_id UUID NOT NULL REFERENCES users(id) ON DELETE
  CASCADE`, `application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE`,
  `granted_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `granted_by UUID REFERENCES users(id) ON DELETE SET NULL`,
  `source TEXT NOT NULL`, `revoked_at TIMESTAMPTZ` and `PRIMARY KEY (user_id, application_id)`.
- `SPEC-4.7.2` `application_entitlements.source` must be constrained by `application_entitlements_source_check` to
  `admin`, `stripe`, `backfill` or `seed`.
- `SPEC-4.7.3` The table `application_entitlements` must have partial indexes
  `idx_application_entitlements_active (user_id, application_id) WHERE revoked_at IS NULL` and
  `idx_application_entitlements_by_app (application_id) WHERE revoked_at IS NULL`.
- `SPEC-4.7.4` The table `stripe_price_entitlements` must have `stripe_price_id TEXT NOT NULL`,
  `application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE`, `created_at` (default `now()`),
  `PRIMARY KEY (stripe_price_id, application_id)` and an index on `stripe_price_id`.
- `SPEC-4.7.5` The migration that created `application_entitlements` must have granted every active application, with
  source `backfill`, to each non-deleted non-admin user who was a lifetime member, held an unexpired trial, or had
  status `active` or `grace_period`, ignoring existing pairs.

### 4.8 Download and registry proxy bookkeeping

- `SPEC-4.8.1` The table `download_cache` must have `id`, `application_id NOT NULL REFERENCES applications(id) ON
  DELETE CASCADE`, `version TEXT NOT NULL` (renamed from `release_tag`), `asset_name TEXT NOT NULL`,
  `content_sha256 TEXT NOT NULL`, `size_bytes BIGINT NOT NULL`, `content_type TEXT NOT NULL`, `created_at`,
  `last_accessed_at` (both `NOT NULL DEFAULT NOW()`), `UNIQUE (application_id, version, asset_name)` (the constraint
  keeps its old column order) and indexes on `last_accessed_at` and `content_sha256`.
- `SPEC-4.8.2` The table `download_daily_counts` must have `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`,
  `day DATE NOT NULL`, `count INTEGER NOT NULL DEFAULT 0` and `PRIMARY KEY (user_id, day)`, with days on the UTC
  boundary.
- `SPEC-4.8.3` The table `oci_blob_cache` must have `content_digest TEXT PRIMARY KEY` (the full `sha256:<hex>`
  string, also the on-disk file name), `size_bytes BIGINT NOT NULL`, `media_type TEXT`, `created_at`,
  `last_accessed_at` (both `NOT NULL DEFAULT NOW()`) and an index `oci_blob_cache_lru_idx (last_accessed_at)`.
- `SPEC-4.8.4` The table `oci_pull_daily_counts` must have `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`,
  `day_utc DATE NOT NULL`, `count INTEGER NOT NULL DEFAULT 0` and `PRIMARY KEY (user_id, day_utc)`.

### 4.9 Audit and notifications

- `SPEC-4.9.1` The table `audit_logs` must have `id`, `actor_id UUID REFERENCES users(id)`, `actor_email VARCHAR(255)`,
  `actor_role VARCHAR(50)`, `actor_ip_address INET`, `action VARCHAR(100) NOT NULL`, `resource_type VARCHAR(100)`,
  `resource_id UUID`, `old_values JSONB`, `new_values JSONB`, `metadata JSONB`,
  `is_admin_action BOOLEAN NOT NULL DEFAULT FALSE`, `severity VARCHAR(20) NOT NULL DEFAULT 'info'` and `created_at`;
  with indexes on `actor_id`, `action`, `resource_type`, `is_admin_action`, `created_at` and `severity`.
- `SPEC-4.9.2` The table `admin_notifications` must have `id`, `type VARCHAR(100) NOT NULL`,
  `title VARCHAR(255) NOT NULL`, `message TEXT NOT NULL`, `metadata JSONB`, `user_id UUID REFERENCES users(id)`,
  `is_read BOOLEAN NOT NULL DEFAULT FALSE`, `read_by UUID REFERENCES users(id)`, `read_at` and `created_at`; with
  indexes on `type`, `is_read` and `created_at`.
- `SPEC-4.9.3` The table `account_delete_dispatch_failures` must have `id`, `user_id UUID NOT NULL` (no foreign key),
  `app_slug TEXT NOT NULL`, `last_error TEXT NOT NULL`, `attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()` and an index
  on `user_id`, so a failure record survives the user's deletion.

### 4.10 Rate limiting and bans

- `SPEC-4.10.1` The table `rate_limits` must have `id`, `key VARCHAR(255) NOT NULL`, `action VARCHAR(100) NOT NULL`,
  `count INTEGER NOT NULL DEFAULT 1`, `window_start TIMESTAMPTZ NOT NULL DEFAULT NOW()`, the constraint
  `unique_rate_limit UNIQUE (key, action)`, an index `idx_rate_limits_key_action (key, action)` and an index on
  `window_start`.
- `SPEC-4.10.2` The table `rate_limit_configs` must have `action VARCHAR(64) PRIMARY KEY`,
  `max_requests INTEGER NOT NULL CHECK (max_requests > 0)`, `window_seconds BIGINT NOT NULL CHECK (window_seconds > 0)`,
  `updated_at` and `updated_by UUID REFERENCES users(id) ON DELETE SET NULL`.
- `SPEC-4.10.3` The table `rate_limit_history` must have `id`, `action TEXT NOT NULL`, `key TEXT NOT NULL`,
  `fired_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `expires_at TIMESTAMPTZ NOT NULL` and indexes
  `rate_limit_history_fired_at_idx (fired_at DESC)` and `rate_limit_history_action_fired_at_idx (action, fired_at DESC)`.
- `SPEC-4.10.4` The table `rate_limit_traffic` must have `action TEXT NOT NULL`, `key_hash BYTEA NOT NULL` (SHA-256 of
  the raw key), `bucket_start TIMESTAMPTZ NOT NULL` (start of a 15-minute bucket), `count INTEGER NOT NULL DEFAULT 0`,
  `PRIMARY KEY (action, key_hash, bucket_start)` and an index `(action, bucket_start DESC)`.
- `SPEC-4.10.5` The table `rate_limit_whitelist` must have `id`, `kind TEXT NOT NULL CHECK (kind IN ('user', 'email',
  'ip'))`, `value TEXT NOT NULL`, `reason TEXT NOT NULL DEFAULT ''`, `added_by UUID REFERENCES users(id) ON DELETE SET
  NULL`, `added_at timestamptz NOT NULL DEFAULT NOW()`, a unique index `rate_limit_whitelist_kind_value_uq (kind,
  value)` and a lookup index on `(kind, value)`.
- `SPEC-4.10.6` The table `ip_bans` must have `id`, `ip_address INET NOT NULL`, `reason VARCHAR(255) NOT NULL`,
  `strikes INTEGER NOT NULL DEFAULT 1`, `banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `expires_at TIMESTAMPTZ NOT
  NULL`, the constraint `unique_ip_ban UNIQUE (ip_address)` and an index `idx_ip_bans_expires (expires_at)`.
- `SPEC-4.10.7` The table `auto_ban_config` must be a singleton (see SPEC-4.11.1) with nullable `enabled BOOLEAN`,
  `threshold BIGINT`, `window_secs BIGINT` and `ban_duration_secs BIGINT`, plus `updated_at` and
  `updated_by UUID REFERENCES users(id)`; NULL means "use the environment default".

### 4.11 Singleton configuration tables

- `SPEC-4.11.1` Each of `stripe_config`, `tier_config`, `auto_ban_config`, `email_config`, `branding`, `mirzam_config`
  and `mokosh_config` must have `id INTEGER PRIMARY KEY CHECK (id = 1)` and exactly one row, inserted by the
  migration that creates it.
- `SPEC-4.11.2` The table `stripe_config` must have `secret_key BYTEA`, `secret_key_nonce BYTEA`,
  `webhook_secret BYTEA`, `webhook_secret_nonce BYTEA`, `key_version SMALLINT NOT NULL DEFAULT 1`, `app_tag TEXT`,
  `success_url TEXT`, `cancel_url TEXT`, `trial_period_days INTEGER`, `updated_at` and
  `updated_by UUID REFERENCES users(id)`; the plaintext secret columns and the `price_id_personal` and
  `price_id_business` columns must not exist.
- `SPEC-4.11.3` The migration that encrypted the Stripe secrets must refuse to run, raising an exception, when
  `stripe_config` still holds a non-NULL plaintext `secret_key` or `webhook_secret`, rather than dropping them.
- `SPEC-4.11.4` The table `tier_config` must have `lifetime_slots`, `early_adopter_slots`, `early_adopter_trial_days`
  and `standard_trial_days` (all nullable `BIGINT`); nullable `TEXT` columns `free_price_id`, `early_adopter_price_id`,
  `standard_price_id`, `lifetime_product_id`, `early_adopter_product_id` and `standard_product_id`;
  `pricing_enabled BOOLEAN NOT NULL DEFAULT FALSE`; `orgs_enabled BOOLEAN NOT NULL DEFAULT FALSE`;
  `lifetime_visible`, `early_adopter_visible` and `standard_visible BOOLEAN NOT NULL DEFAULT true`; `updated_at` and
  `updated_by UUID REFERENCES users(id)`. A NULL numeric column means "fall back to the environment default". The
  column `lifetime_price_id` must not exist.
- `SPEC-4.11.5` The table `email_config` must have nullable `enabled BOOLEAN`, `smtp_host TEXT`, `smtp_port INTEGER`,
  `smtp_tls TEXT`, `smtp_username TEXT`, `smtp_password BYTEA`, `smtp_password_nonce BYTEA`, `from_email TEXT`,
  `from_name TEXT`, `admin_notification_emails TEXT`, `imap_host TEXT`, `imap_port INTEGER`, `imap_username TEXT`,
  `imap_password BYTEA`, `imap_password_nonce BYTEA`, `imap_mailbox TEXT`, `imap_enabled BOOLEAN`;
  `key_version SMALLINT NOT NULL DEFAULT 1`; `updated_at`; `updated_by UUID REFERENCES users(id)`.
- `SPEC-4.11.6` The table `branding` must have `brand_name`, `tagline`, `meta_description`, `og_image_url`,
  `theme_css`, `theme_color_light`, `theme_color_dark` and `newsletter_url`, each `TEXT NOT NULL DEFAULT ''` (empty
  string means "not set"), nullable `mark_updated_at`, `favicon_updated_at` and `mascot_updated_at TIMESTAMPTZ`,
  `updated_at` and `updated_by UUID REFERENCES users(id)`.
- `SPEC-4.11.7` The table `mirzam_config` must have `enabled BOOLEAN NOT NULL DEFAULT FALSE`, `base_url`,
  `updates_list` and `notices_list TEXT NOT NULL DEFAULT ''`, `api_token BYTEA`, `api_token_nonce BYTEA`,
  `key_version SMALLINT NOT NULL DEFAULT 1`, `last_error TEXT`, `last_error_at TIMESTAMPTZ`, `updated_at` and
  `updated_by UUID REFERENCES users(id) ON DELETE SET NULL`.
- `SPEC-4.11.8` The table `mokosh_config` must have `google_client_id TEXT NOT NULL DEFAULT ''`,
  `google_client_secret BYTEA`, `google_client_secret_nonce BYTEA`, `key_version SMALLINT NOT NULL DEFAULT 1`,
  `updated_at` and `updated_by UUID REFERENCES users(id) ON DELETE SET NULL`.
- `SPEC-4.11.9` Every secret stored in a configuration or credential table (`stripe_config`, `email_config`,
  `mirzam_config`, `mokosh_config`, `user_totp`) must be a ciphertext `BYTEA` paired with its `*_nonce BYTEA` and a
  `key_version SMALLINT NOT NULL DEFAULT 1` naming the encryption key version; plaintext secret columns must not exist.

### 4.12 Feature toggles, suppressions, webhook events

- `SPEC-4.12.1` The table `feature_toggles` must have `key TEXT PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*$')`,
  `enabled BOOLEAN NOT NULL DEFAULT FALSE`, `updated_at` and `updated_by UUID REFERENCES users(id) ON DELETE SET NULL`;
  an absent key means off.
- `SPEC-4.12.2` The table `mailer_suppressions` must have `address TEXT PRIMARY KEY`, `reason TEXT NOT NULL`,
  `detail TEXT`, `created_at` and `updated_at`.
- `SPEC-4.12.3` The table `stripe_webhook_events` must have `event_id TEXT PRIMARY KEY`, `event_type TEXT NOT NULL`,
  `received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `status TEXT NOT NULL DEFAULT 'done'` (values written by the
  application: `processing` while claimed, `done` once handled) and an index `(status, received_at)`.
- `SPEC-4.12.4` Rows that existed before the `status` column was added must read as `done`, so they are never
  reprocessed.

### 4.13 Feedback

- `SPEC-4.13.1` The table `feedback` must have `id`, `name VARCHAR(100)`, `email VARCHAR(255)`, `subject VARCHAR(200)`,
  `message TEXT NOT NULL`, `page_path VARCHAR(255)`, `status VARCHAR(20) NOT NULL DEFAULT 'new'`, `admin_response TEXT`,
  `responded_by UUID REFERENCES users(id)`, `responded_at`, `is_spam BOOLEAN NOT NULL DEFAULT FALSE`,
  `tags TEXT[] NOT NULL DEFAULT '{}'`, `submitter_ip INET`, `user_agent TEXT`, `created_at` and `updated_at`; indexes
  on `status`, `created_at DESC`, `responded_by` and a GIN index on `tags`.
- `SPEC-4.13.2` The table `feedback_attachments` must have `id`, `feedback_id NOT NULL REFERENCES feedback(id) ON
  DELETE CASCADE`, `filename TEXT NOT NULL`, `mime_type TEXT NOT NULL`, `size_bytes INTEGER NOT NULL CHECK (size_bytes >
  0 AND size_bytes <= 5242880)`, `data BYTEA NOT NULL`, `created_at`, the constraint
  `feedback_attachments_data_size CHECK (octet_length(data) = size_bytes)` and an index on `feedback_id`.
- `SPEC-4.13.3` The table `feedback_archive` must have `id UUID PRIMARY KEY` (no default, the archived feedback id),
  `archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `data JSONB NOT NULL` and an index `(archived_at DESC)`.
- `SPEC-4.13.4` The table `feedback_spam_reasons` must have `feedback_id uuid PRIMARY KEY REFERENCES feedback(id) ON
  DELETE CASCADE`, `reason text NOT NULL` and `created_at timestamptz NOT NULL DEFAULT NOW()`.

### 4.14 Support mailbox

- `SPEC-4.14.1` The table `support_tickets` must have `id`, `subject TEXT NOT NULL`, `requester_email VARCHAR(255) NOT
  NULL`, `requester_name VARCHAR(255)`, `status VARCHAR(20) NOT NULL DEFAULT 'open'`, `created_at`, `updated_at`,
  `last_message_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`; indexes on `status`, `requester_email` and
  `last_message_at DESC`.
- `SPEC-4.14.2` The table `support_messages` must have `id`, `ticket_id NOT NULL REFERENCES support_tickets(id) ON
  DELETE CASCADE`, `direction VARCHAR(10) NOT NULL`, `from_email VARCHAR(255) NOT NULL`, `to_email VARCHAR(255)`,
  `body_text TEXT NOT NULL`, `body_html TEXT`, `message_id TEXT`, `in_reply_to TEXT`, `mail_references TEXT`,
  `created_at`; an index on `ticket_id` and a unique partial index `idx_support_messages_message_id (message_id) WHERE
  message_id IS NOT NULL`, so a repeated mail `Message-ID` cannot be stored twice.

### 4.15 Binary assets

- `SPEC-4.15.1` The table `user_avatars` must have `user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE`,
  `mime_type TEXT NOT NULL`, `size_bytes INTEGER NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 2097152)`,
  `data BYTEA NOT NULL`, `updated_at` and the constraint `user_avatars_data_size CHECK (octet_length(data) =
  size_bytes)`.
- `SPEC-4.15.2` The table `branding_assets` must have `kind TEXT PRIMARY KEY`, `mime_type TEXT NOT NULL`, `size_bytes
  INTEGER NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 2097152)`, `data BYTEA NOT NULL`, `updated_at` and the
  constraint `branding_assets_data_size CHECK (octet_length(data) = size_bytes)`.

### 4.16 oauth_clients

- `SPEC-4.16.1` The table `oauth_clients` must have `id`; `client_id UUID NOT NULL UNIQUE` (the public identifier and the
  target of all foreign keys); `client_secret_hash TEXT` (Argon2id; NULL for public clients); `client_type TEXT NOT NULL
  CHECK (client_type IN ('public', 'confidential'))`; `name TEXT NOT NULL`; `redirect_uris TEXT[] NOT NULL`;
  `post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}'`; `backchannel_logout_uri TEXT`; `lifecycle_event_uri TEXT`;
  `allowed_scopes TEXT[] NOT NULL`; `allowed_grant_types TEXT[] NOT NULL`; `audience TEXT NOT NULL`;
  `created_at`; `created_by UUID REFERENCES users(id)`; `disabled_at TIMESTAMPTZ`.
- `SPEC-4.16.2` `oauth_clients.token_endpoint_auth_method` must be `TEXT NOT NULL CHECK (... IN ('none',
  'client_secret_basic', 'private_key_jwt'))`; `require_pkce` must be `BOOLEAN NOT NULL DEFAULT TRUE`;
  `dpop_bound` must be `BOOLEAN NOT NULL DEFAULT FALSE`.
- `SPEC-4.16.3` The token lifetimes must be `access_token_ttl_seconds INT NOT NULL DEFAULT 600 CHECK (BETWEEN 60 AND
  900)`, `refresh_token_ttl_seconds INT NOT NULL DEFAULT 2592000 CHECK (BETWEEN 3600 AND 7776000)` and
  `refresh_idle_ttl_seconds INT NOT NULL DEFAULT 1209600 CHECK (BETWEEN 3600 AND 7776000)`.
- `SPEC-4.16.4` The table `oauth_clients` must also have `tenant_claim_name TEXT` (when non-NULL, authorization gates on
  `oauth_client_user_tenants` and tokens carry the selected tenant under that claim name), `first_party BOOLEAN NOT NULL
  DEFAULT FALSE`, `logo_uri TEXT`, `allowed_secret_keys TEXT[] NOT NULL DEFAULT '{}'` and
  `allowed_config_keys TEXT[] NOT NULL DEFAULT '{}'` (empty means the client may read no host keys), and a partial
  index `oauth_clients_active (client_id) WHERE disabled_at IS NULL`.
- `SPEC-4.16.5` `allowed_grant_types` is documented as a subset of `authorization_code`, `refresh_token` and
  `client_credentials`; the database must not constrain its elements, so the application must validate them.
- `SPEC-4.16.6` After the chain, `oauth_clients` must contain no row for the early placeholder server client (it was
  inserted soft-deleted and then deleted), and must contain the seeded relying parties of SPEC-4.21.1 and SPEC-4.21.2.
- `SPEC-4.16.7` The table `oauth_client_user_tenants` must have `id`, `oauth_client_id UUID NOT NULL REFERENCES
  oauth_clients(client_id) ON DELETE CASCADE`, `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`,
  `tenant_id UUID NOT NULL`, `role TEXT`, `created_at`, `created_by UUID REFERENCES users(id)`,
  `UNIQUE (oauth_client_id, user_id, tenant_id)` and an index on `(oauth_client_id, user_id)`.

### 4.17 OIDC sessions, codes and grants

- `SPEC-4.17.1` The table `op_sessions` must have `id`, `sid TEXT NOT NULL UNIQUE` (the cookie value),
  `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`, `created_at`, `last_active_at`
  (both `NOT NULL DEFAULT NOW()`), `expires_at TIMESTAMPTZ NOT NULL`, `revoked_at`, `user_agent TEXT`, `ip INET`,
  `acr TEXT`, `amr TEXT[]`, `idle_expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')` and
  `idle_ttl_seconds INT NOT NULL DEFAULT 28800`.
- `SPEC-4.17.2` The table `op_sessions` must have partial indexes `op_sessions_user_active (user_id)` and
  `op_sessions_sid (sid)`, both `WHERE revoked_at IS NULL`.
- `SPEC-4.17.3` A session is live only while both `expires_at` and `idle_expires_at` are in the future;
  `idle_ttl_seconds` records the initial idle window so a refresh rotation slides `idle_expires_at` by the same window.
- `SPEC-4.17.4` The table `oauth_authorization_codes` must have `code_hash BYTEA PRIMARY KEY`,
  `client_id UUID NOT NULL REFERENCES oauth_clients(client_id)`, `user_id UUID NOT NULL REFERENCES users(id) ON DELETE
  CASCADE`, `op_session_id UUID NOT NULL REFERENCES op_sessions(id)`, `redirect_uri TEXT NOT NULL`,
  `scope TEXT[] NOT NULL`, `code_challenge TEXT NOT NULL`, `code_challenge_method TEXT NOT NULL CHECK
  (code_challenge_method = 'S256')`, `nonce TEXT NOT NULL`, `auth_time TIMESTAMPTZ NOT NULL`, `acr TEXT`,
  `amr TEXT[]`, `issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `expires_at TIMESTAMPTZ NOT NULL`, `consumed_at`,
  `revoked_at` and `selected_tenant_id UUID`; an index `oauth_codes_expires (expires_at)`.
- `SPEC-4.17.5` The table `user_application_access` must have `user_id NOT NULL REFERENCES users(id) ON DELETE
  CASCADE`, `client_id NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE`, `granted_scopes TEXT[] NOT
  NULL`, `granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `granted_by UUID REFERENCES users(id)`, `revoked_at`,
  `PRIMARY KEY (user_id, client_id)` and the partial index `user_application_access_active (user_id) WHERE revoked_at IS
  NULL`.
- `SPEC-4.17.6` After the chain no `user_application_access` row may carry the scope `profile` or `phone` in
  `granted_scopes`, so those scopes require fresh consent.

### 4.18 OIDC refresh tokens and blocklist

- `SPEC-4.18.1` The table `refresh_token_families` must have `id`, `client_id NOT NULL REFERENCES
  oauth_clients(client_id)`, `user_id NOT NULL REFERENCES users(id) ON DELETE CASCADE`, `op_session_id NOT NULL
  REFERENCES op_sessions(id) ON DELETE CASCADE`, `created_at`, `revoked_at`, `revoke_reason TEXT`,
  `auth_time TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `acr TEXT NOT NULL DEFAULT 'urn:bunyip:loa:pwd'` and
  `amr TEXT[] NOT NULL DEFAULT ARRAY['pwd']`; the partial index `refresh_token_families_user (user_id) WHERE revoked_at
  IS NULL`.
- `SPEC-4.18.2` The table `refresh_tokens_v2` must have `id`, `token_hash BYTEA NOT NULL UNIQUE` (SHA-256 of the raw
  token), `family_id NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE`, `parent_id UUID REFERENCES
  refresh_tokens_v2(id)`, `client_id NOT NULL REFERENCES oauth_clients(client_id)`, `user_id NOT NULL REFERENCES
  users(id) ON DELETE CASCADE`, `scope TEXT[] NOT NULL`, `cnf_jkt TEXT`, `issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
  `used_at`, `revoked_at`, `idle_expires_at TIMESTAMPTZ NOT NULL`, `absolute_expires_at TIMESTAMPTZ NOT NULL`,
  `ip INET`, `user_agent TEXT` and `selected_tenant_id UUID`.
- `SPEC-4.18.3` The table `refresh_tokens_v2` must have an index on `family_id` and the partial index
  `refresh_tokens_active_user (user_id) WHERE revoked_at IS NULL AND used_at IS NULL`.
- `SPEC-4.18.4` The table `access_token_blocklist` must have `jti TEXT PRIMARY KEY`, `exp TIMESTAMPTZ NOT NULL`,
  `reason TEXT NOT NULL`, `revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()` and an index on `exp`.

### 4.19 Lifecycle event outbox

- `SPEC-4.19.1` The table `lifecycle_event_outbox` must have `id`, `event_type TEXT NOT NULL CHECK (event_type IN
  ('user.suspended', 'user.unsuspended', 'user.deleted', 'entitlement.granted', 'entitlement.revoked'))`,
  `user_id UUID NOT NULL`, `payload JSONB NOT NULL` and `created_at`.
- `SPEC-4.19.2` `lifecycle_event_outbox.user_id` must have no foreign key, so a `user.deleted` event outlives the user
  it describes; readers must tolerate a `user_id` with no `users` row.
- `SPEC-4.19.3` The table `lifecycle_event_delivery` must have `id`, `event_id NOT NULL REFERENCES
  lifecycle_event_outbox(id) ON DELETE CASCADE`, `client_id NOT NULL REFERENCES oauth_clients(client_id) ON DELETE
  CASCADE`, `delivery_url TEXT NOT NULL`, `jti UUID NOT NULL UNIQUE DEFAULT gen_random_uuid()` (stable across retries),
  `attempts INT NOT NULL DEFAULT 0`, `next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `last_attempt_at`,
  `delivered_at`, `failed_at` and `last_error TEXT`.
- `SPEC-4.19.4` The table `lifecycle_event_delivery` must have the partial index
  `lifecycle_event_delivery_pending (next_attempt_at) WHERE delivered_at IS NULL AND failed_at IS NULL`.

### 4.20 Removed billing objects

- `SPEC-4.20.1` After the chain the tables `subscriptions`, `payment_history` and `invoices`, and the sequence
  `invoice_number_seq`, must not exist, because Stripe is the system of record for that data.
- `SPEC-4.20.2` The dropped billing tables must be removed with `DROP ... IF EXISTS`, never with a cascading drop.

### 4.21 Seeded relying-party clients

- `SPEC-4.21.1` The chain must leave in `oauth_clients` a public PKCE client (auth method `none`) for the hosted PSA
  application and another for the hosted DMARC application, each with scopes `openid email offline_access profile phone`,
  grant types `authorization_code` and `refresh_token`, and access token TTL 600 seconds.
- `SPEC-4.21.2` The chain must leave in `oauth_clients` a confidential client (auth method `client_secret_basic`, grant
  type `authorization_code` only, scopes `openid email profile phone`, TTL 600) for the chat relying party, with an
  Argon2id `client_secret_hash` and no plaintext secret in the repository.
- `SPEC-4.21.3` The hosted PSA relying party must be non-first-party (`first_party = FALSE`) so its authorization shows
  a named consent screen with its display name and a same-origin `logo_uri`, and must have a back-channel logout URI.
- `SPEC-4.21.4` Each seed insert into `oauth_clients` must be idempotent (`ON CONFLICT (client_id) DO NOTHING`), and a
  client with `redirect_uris` must list exact redirect URIs with no wildcards.

### 4.22 Seeded catalog rows

- `SPEC-4.22.1` The chain must seed three non-hosted registry-proxy applications (a server, an API and a web image) with
  `container_name = 'catalog'`, `is_active = TRUE`, a pinned image tag and an image owner, and one non-hosted
  download-proxy application using `artifact_source = 'generic_package'`, which is then set `is_active = FALSE`.
- `SPEC-4.22.2` The chain must seed two hosted applications with `is_hosted = TRUE`, an assigned `subdomain` and
  initial `sort_order` 10 and 20 (the hosted PSA platform and the DMARC reporter; later renumbered by SPEC-4.6.5), and
  must set a `chat` subdomain on the chat
  application when its subdomain is NULL, empty or equal to its slug.
- `SPEC-4.22.3` Every seed insert into `applications` and `application_docs` must be idempotent (`ON CONFLICT (slug)` or
  `(application_id, slug)` `DO NOTHING`), and a doc seed must select its application by slug so a missing application
  inserts nothing rather than failing.
- `SPEC-4.22.4` The chain must seed `application_docs` for the PSA server application (getting-started, configuration,
  docker-compose, registry-login, split-deployment and quick-start, the last with `sort_order` -1) and for the web
  application (getting-started).
- `SPEC-4.22.5` The chain must set `release_notes_url` on the two hosted applications only when it is NULL.

### 4.23 Migration data fixes

- `SPEC-4.23.1` The chain must set `membership_status = 'active'` for non-deleted verified users with status `none` that
  held a lifetime membership or a trial end date.
- `SPEC-4.23.2` The chain must reset to tier `standard` (no lifetime flag, trial, or override) every non-deleted user
  whose status is `canceled` but who held tier `lifetime`, `early_adopter` or `free`.
- `SPEC-4.23.3` The chain must rename tier values `trial_3m` to `early_adopter` and `trial_1m` to `standard`.
- `SPEC-4.23.4` The chain must clamp `op_sessions.idle_expires_at` to `expires_at` for rows where it exceeded it.

### 4.24 Seed template files

- `SPEC-4.24.1` Each seed template under `bunyip-api/seed/` must be a JSON object with `version` 1 and an `owns` object
  declaring the email domains (`owns.domains`) or exact addresses (`owns.emails`) the template owns.
- `SPEC-4.24.2` A seed template may contain `application_groups` (`slug`, `name`, `display_name`, `sort_order`),
  `applications` (`slug`, `name`, `display_name`, `container_name`, `group_slug`, `description`, and in the demo
  template `restricted`), `users`, `entitlements` (`app_slug`, `user_email`) and `feedback` (`email`, `subject`,
  `message`, `tags`).
- `SPEC-4.24.3` Each user entry must have `email`, `role` (`admin` or `subscriber`) and `verified`; it must carry a
  password through either the template-level `default_password` or a per-user `password_env` naming an environment
  variable, and must not embed any other secret.
- `SPEC-4.24.4` The e2e template must contain exactly one `subscriber` and one `admin` user, both verified, whose
  passwords come from the environment variable `BUNYIP_E2E_TEST_USER_PASSWORD`, and no other section.
- `SPEC-4.24.5` The minimal template must contain two application groups, three applications (two in `core`, one in
  `add-ons`) and three users (an admin, an active standard member and an unverified user), with membership status and
  tier per user.
- `SPEC-4.24.6` The demo template must contain three groups, eight applications (two flagged `restricted`), 42
  users (2 admins and 40 subscribers) across the membership states `active/standard`, `active/early_adopter` (with
  `price_locked` and `locked_price_amount` 4900), `active/lifetime`, `none/free`, `past_due/standard`,
  `grace_period/standard` and `canceled/standard`, six entitlements and the demo feedback entries.
- `SPEC-4.24.7` The demo and minimal templates must use only addresses on a reserved `.test` domain, and no template
  may contain a credential other than the template-level demo password or an environment-supplied password.

## 5. OIDC provider crate

### 5.1 Crate surface

- `SPEC-5.1.1` The `bunyip-oidc` crate must expose `config`, `errors`, `middleware`, `models` and `repositories` as
  glob re-exports of the same-named `bunyip-domain` modules, so that OIDC code resolves `crate::errors::AppError` and
  the other domain types to the single domain definitions.
- `SPEC-5.1.2` The crate's `services` module must re-export the `bunyip-domain` services (including `jwt`), the
  `oidc_keys` module and `OidcKeySet` from `dunite-oidc`, and `OAuthClient` and `OidcProvider` from its own
  `oidc_provider` module. Ed25519 key loading and JWKS construction must stay in `dunite-oidc` and must not be
  reimplemented here.
- `SPEC-5.1.3` The crate must depend on `dunite-oidc` and `dunite-oidc-op` pinned by an explicit git `rev` (the same
  `rev` for both), never by branch.

### 5.2 Route registration

- `SPEC-5.2.1` `configure_well_known` must register, at the application root outside `/v1`,
  `GET /.well-known/openid-configuration` (handler `discovery`) and `GET /.well-known/jwks.json` (handler `jwks`).
- `SPEC-5.2.2` `configure_oauth2` must register, under the `/oauth2` scope at the application root, `GET /authorize`,
  `POST /token`, `GET /userinfo`, `POST /revoke` and `GET /logout`, each bound to the handler of the same name.

### 5.3 Provider availability

- `SPEC-5.3.1` Every OIDC handler (`discovery`, `jwks`, `authorize`, `token`, `userinfo`, `revoke`, `logout`) must
  answer `404` with an empty body, before any other work, when the registered `Option<Arc<OidcProvider>>` is `None`.
- `SPEC-5.3.2` `discovery` must also answer `404` with an empty body when the provider's configured issuer is unset or
  empty.
- `SPEC-5.3.3` `OidcProvider::issuer` must return the configured issuer, or the empty string when none is configured,
  and `OidcProvider::enabled` must return the configuration's enabled state.

### 5.4 Discovery document

- `SPEC-5.4.1` `discovery` must answer `200` with `Content-Type: application/json`, header
  `Cache-Control: public, max-age=300`, and a JSON document whose `issuer` is the configured issuer and whose
  endpoint members are the issuer with a fixed suffix appended: `authorization_endpoint` `/oauth2/authorize`,
  `token_endpoint` `/oauth2/token`, `userinfo_endpoint` `/oauth2/userinfo`, `jwks_uri` `/.well-known/jwks.json`,
  `revocation_endpoint` `/oauth2/revoke`, `end_session_endpoint` `/oauth2/logout`.
- `SPEC-5.4.2` The discovery document must declare `response_types_supported` `["code"]`, `response_modes_supported`
  `["query"]`, `grant_types_supported` `["authorization_code","refresh_token"]`, `subject_types_supported`
  `["public"]`, `id_token_signing_alg_values_supported` `["EdDSA"]`, `token_endpoint_auth_methods_supported`
  `["client_secret_basic","none"]`, `code_challenge_methods_supported` `["S256"]`, `require_pkce` `true`,
  `request_parameter_supported` `false`, `request_uri_parameter_supported` `false`,
  `backchannel_logout_supported` `true` and `backchannel_logout_session_supported` `true`.
- `SPEC-5.4.3` The discovery document must declare `scopes_supported` `["openid","email","offline_access",
  "dmarc:read","dmarc:write"]` and `claims_supported` `["iss","sub","aud","exp","iat","auth_time","nonce","azp",
  "email","email_verified","membership_status","has_member_access","bunyip_role"]`.

### 5.5 JWKS

- `SPEC-5.5.1` `jwks` must answer `200` with `Content-Type: application/json`, header
  `Cache-Control: public, max-age=300`, and the provider's key set JWKS as the body.

### 5.6 Per-IP rate limiting of OAuth endpoints

- `SPEC-5.6.1` `authorize`, `token`, `userinfo` and `revoke` must each check a per-IP rate limit, keyed by the
  request's client IP (string form; the literal `unknown` when no client IP resolves), before any client lookup,
  credential handling or token work, and must return the rate-limit repository's error unchanged when the check
  fails. The budgets must be `authorize` 120 requests per 60 seconds, `token` 60 per 60, `userinfo` 240 per 60 and
  `revoke` 60 per 60.

### 5.7 Authorize: authenticating the user

- `SPEC-5.7.1` `authorize` must read the `JwtService` as a bare `Arc<JwtService>` from request `app_data`, and must
  fail with an internal error `JwtService not configured` when it is absent.
- `SPEC-5.7.2` `authorize` must treat the caller as authenticated only through a live OP session identified by the
  `bunyip_op_session` cookie; the session is live only when it is not revoked, its absolute `expires_at` is in the
  future and its `idle_expires_at` is in the future. A stateless hub `access_token` alone must not allow a code to be
  issued except through the silent-SSO path, which first creates a new OP session.
- `SPEC-5.7.3` When the OP session is live, `authorize` must use it and must attach no session cookies to the
  response.
- `SPEC-5.7.4` A database failure while loading or creating an OP session during `authorize` must propagate as an
  error response and must not fall back to the login redirect.

### 5.8 Authorize: silent SSO

- `SPEC-5.8.1` When no live OP session resolves and the `access_token` cookie verifies as a hub access token,
  `authorize` must create an OP session for the token's subject with `acr` `urn:bunyip:loa:pwd`, `amr` `["pwd"]` and
  the short (non-remember) idle window, log the user id and `sid` at info level, and attach the cookies from
  `AuthCookies::op_session_set` (using the OP-session cookie domain, which is the configured cookie domain only when
  shared cookies are enabled) to the final response.
- `SPEC-5.8.2` When the `access_token` cookie is absent or does not verify, and a `refresh_token` cookie is present,
  `authorize` must first verify that refresh token locally; if it does not verify, it must fall back to the login
  redirect without any database write.
- `SPEC-5.8.3` When the `refresh_token` cookie verifies locally, `authorize` must rotate it through the same
  `AuthService::refresh_tokens` operation that `/v1/auth/refresh` uses, passing the User-Agent-derived device info and
  client IP. If the rotation fails, it must log a warning naming the user id and the error and fall back to the login
  redirect.
- `SPEC-5.8.4` After a successful refresh-token rotation, `authorize` must create the OP session as in `SPEC-5.8.1`
  and attach, in order, the `AuthCookies::clear_stale` clears, the rotated `access_token` cookie, the rotated
  `refresh_token` cookie (remember-me lifetime) and the `bunyip_op_session` cookie, using the configured cookie domain
  for the first two and the OP-session cookie domain for the last.

### 5.9 Authorize: login redirect

- `SPEC-5.9.1` When neither a live OP session nor silent SSO yields an identity, `authorize` must answer `302` with
  `Location` `{web_origin without trailing "/"}/login?redirect=<url-encoded issuer + original request URI>&checked=1`,
  and must log at info level the `client_id`, `redirect_uri`, whether an OP-session cookie was present and whether an
  `access_token` cookie was present.
- `SPEC-5.9.2` When the login redirect is issued and the request carried a `bunyip_op_session` cookie, the response
  must also carry the `AuthCookies::clear_op_session_only` clears (a no-domain clear and, when `cookie_domain` is
  configured, a domain-scoped clear, regardless of whether shared cookies are enabled) and must not clear
  `access_token` or `refresh_token`.

### 5.10 Authorize: request validation

- `SPEC-5.10.1` Parameter validation must run only after the user is authenticated. An unauthenticated request must be
  redirected to login even when its parameters are invalid.
- `SPEC-5.10.2` `authorize` must reject, with `400` and a JSON body `{"error","error_description"}`, in this order:
  `response_type` other than `code` (`unsupported_response_type`, `only response_type=code is supported`);
  `code_challenge_method` other than `S256` (`invalid_request`, `code_challenge_method must be S256`); empty
  `code_challenge` (`invalid_request`, `code_challenge is required`); empty `state` (`invalid_request`,
  `state is required`); empty `nonce` (`invalid_request`, `nonce is required`); a `scope` lacking the `openid` token
  (`invalid_scope`, `scope must include openid`).
- `SPEC-5.10.3` `authorize` must reject a `client_id` that is not a UUID with a bad-request error
  `invalid client_id UUID`, and an unknown or disabled client with a bad-request error `unknown client_id`.
- `SPEC-5.10.4` `authorize` must accept the `prompt` query parameter and must not act on its value, other than
  re-emitting it as a hidden field of the tenant picker.

### 5.11 Authorize: redirect URI

- `SPEC-5.11.1` `authorize` must accept a `redirect_uri` only when it matches at least one of the client's registered
  `redirect_uris` under `SPEC-5.11.2`; otherwise it must answer `400` JSON `invalid_request`,
  `redirect_uri not registered`, and must not redirect.
- `SPEC-5.11.2` A registered redirect URI must match byte-for-byte, except that a registration equal to exactly
  `http://127.0.0.1` or `http://localhost` must match any requested URI that parses as an `http` URL with no username
  or password and a host that is `127.0.0.1`, `::1` or `localhost`, with any port and path.
- `SPEC-5.11.3` When the validated request carries `consent=denied`, `authorize` must answer `302` to
  `{redirect_uri}?error=access_denied&error_description=<url-encoded "The user declined to authorize the request">&state=<url-encoded state>`
  without issuing a code and without evaluating scopes.

### 5.12 Authorize: scopes

- `SPEC-5.12.1` `authorize` must compute the requested scopes as the whitespace-separated tokens of `scope` that are
  members of the client's `allowed_scopes`, in request order, dropping all others.
- `SPEC-5.12.2` When the computed scope set is empty, `authorize` must answer `400` JSON `invalid_scope`,
  `none of the requested scopes are permitted for this client`, and must not issue a code.

### 5.13 Authorize: entitlement baseline and consent gate

- `SPEC-5.13.1` When the user has no active entitlement for the client, `authorize` must grant one whose scopes are the
  client's `allowed_scopes` restricted to the baseline set `openid`, `email` and `offline_access`.
- `SPEC-5.13.2` `authorize` must compute `missing` as the requested scopes not in the user's currently granted scopes
  for the client, and must log at info level, target `consent_gate`, the user id, client id, requested, granted and
  missing scopes.
- `SPEC-5.13.3` When `missing` is non-empty and the client is first-party, `authorize` must add the missing scopes to
  the grant, log at info level, and continue to issue the code without prompting.
- `SPEC-5.13.4` When `missing` is non-empty and the client is not first-party, `authorize` must answer `302` to
  `{web_origin}/oauth2/consent` with url-encoded query parameters `client_id`, `client_name`, `logo_uri` (only when
  the client's logo is non-blank), `missing` (space-joined) and `continue` (issuer + original request URI), attach any
  silent-SSO cookies, and must not issue a code.

### 5.14 Authorize: tenant gating

- `SPEC-5.14.1` For a client whose `tenant_claim_name` is unset, `authorize` must skip tenant gating, issue the code
  with no selected tenant and ignore `selected_tenant_id`.
- `SPEC-5.14.2` For a client whose `tenant_claim_name` is set, `authorize` must load the user's tenant assignments for
  that client and: with zero assignments answer `400` JSON `access_denied`, `no tenant assigned for this client`; with
  one assignment select it, ignoring `selected_tenant_id`; with more than one and a `selected_tenant_id` among them
  select it; with more than one and a `selected_tenant_id` not among them answer `400` JSON `access_denied`,
  `selected tenant is not assigned to this user`; with more than one and no `selected_tenant_id` answer the tenant
  picker page.

### 5.15 Authorize: tenant picker page

- `SPEC-5.15.1` The tenant picker must answer `200` with `Content-Type: text/html; charset=utf-8` and a GET form to
  `/oauth2/authorize` carrying hidden inputs for `response_type`, `client_id`, `redirect_uri`, `scope`, `state`,
  `nonce`, `code_challenge`, `code_challenge_method` and (when present) `prompt`, one `selected_tenant_id` radio per
  assignment with the first checked, and the assignment's role (when non-empty) in its label.
- `SPEC-5.15.2` The tenant picker must HTML-escape `&`, `<`, `>`, `"` and `'` in every request-derived, client-derived
  and role value it interpolates, and must attach the silent-SSO cookies to the response.

### 5.16 Authorize: code issuance

- `SPEC-5.16.1` `authorize` must issue the code with `auth_time` equal to the OP session's `created_at`, `acr` equal to
  the session's `acr` or `urn:bunyip:loa:pwd` when null, and `amr` equal to the session's `amr` or `["pwd"]` when
  null.
- `SPEC-5.16.2` `issue_authorization_code` must generate a 32-byte opaque code, store only its SHA-256 hash in
  `oauth_authorization_codes` together with the client, user, OP session, redirect URI, scopes, code challenge,
  method `S256`, nonce, `auth_time`, `acr`, `amr`, the selected tenant and `expires_at` = now + `code_ttl_secs`, and
  return the raw code. A database failure must surface as an internal error `Failed to insert authorization code`.
- `SPEC-5.16.3` On success `authorize` must answer `302` to `{redirect_uri}?code=<url-encoded code>&state=<url-encoded
  state>` and attach any silent-SSO cookies.

### 5.17 Token and revoke: client credential extraction

- `SPEC-5.17.1` `token` and `revoke` must read client credentials first from an `Authorization: Basic` header whose
  base64 payload is UTF-8 and contains a `:`, splitting at the first `:` and percent-decoding both halves; when the
  header is absent, not `Basic`, not decodable or has no `:`, they must read `client_id` and the optional
  `client_secret` from the form body.
- `SPEC-5.17.2` When no valid Basic credentials are present and the form has no `client_id`, the endpoint must fail
  with `OidcInvalidClient` `client_id is required`.
- `SPEC-5.17.3` The endpoint must fail with `OidcInvalidClient` `invalid client_id format` when the `client_id` is not
  a UUID, and with `OidcInvalidClient` `unknown client` when no enabled client has that id.

### 5.18 Client authentication

- `SPEC-5.18.1` Client authentication must branch on the client's registered `token_endpoint_auth_method`. For `none`
  it must fail with `OidcInvalidClient` unless `client_type` is `public`, and must fail with `OidcInvalidClient`
  `public client must not present a client_secret` when any secret is presented.
- `SPEC-5.18.2` For `client_secret_basic`, client authentication must fail with `OidcInvalidClient` when `client_type`
  is `public`, when the client has no stored secret hash (`client has no secret configured`), or when no secret is
  presented (`client_secret required for confidential client`).
- `SPEC-5.18.3` For `client_secret_basic`, client authentication must verify the presented secret against the stored
  PHC-format Argon2 hash on the blocking pool (offload label `oidc client secret verify`), failing with
  `OidcInvalidClient` `malformed client secret hash` for an unparsable hash and `invalid client_secret` for a mismatch.
- `SPEC-5.18.4` Client authentication must always fail with `OidcInvalidClient`
  `token_endpoint_auth_method=private_key_jwt is not yet implemented` for `private_key_jwt`, and with
  `OidcInvalidClient` `unsupported token_endpoint_auth_method: {value}` for any other value.
- `SPEC-5.18.5` Every client-authentication failure must be `AppError::OidcInvalidClient`, which is answered `401`
  with a `WWW-Authenticate` header and a JSON `invalid_client` body.

### 5.19 Token endpoint dispatch

- `SPEC-5.19.1` `token` must process a request in this order: provider presence, per-IP rate limit, credential
  extraction, client load, client authentication, grant-type entitlement, then the grant handler. The body must be
  form-encoded.
- `SPEC-5.19.2` `token` must answer `400` JSON `unauthorized_client` with description
  `client {client_id} is not registered for grant_type={grant_type}` when the requested `grant_type` is not in the
  client's `allowed_grant_types`.
- `SPEC-5.19.3` `token` must answer `400` JSON `unsupported_grant_type` with description
  `unsupported grant_type: {grant_type}` for a registered grant type other than `authorization_code` and
  `refresh_token`.

### 5.20 Token endpoint: authorization-code grant

- `SPEC-5.20.1` The `authorization_code` grant must fail with `OidcInvalidRequest` `code is required for
  authorization_code grant`, `redirect_uri is required` or `code_verifier is required (PKCE)` when the respective
  parameter is absent.
- `SPEC-5.20.2` After redeeming the code, the grant must fail with `OidcInvalidGrant` `user not found` when the code's
  user no longer exists, and must answer `400` JSON `access_denied`, `user not entitled to this client` when the user
  has no active entitlement for the client.
- `SPEC-5.20.3` On success the grant must mint an access token and an ID token from the code row's scopes, `auth_time`,
  `acr`, `amr`, nonce, selected tenant and OP-session `sid`, issue the first refresh token of a new family, and answer
  `200` JSON with `access_token`, `token_type` `Bearer`, `expires_in` (whole seconds until the access token's `exp`),
  `refresh_token`, `scope` (space-joined) and `id_token`.
- `SPEC-5.20.4` `issue_refresh_token` must create a `refresh_token_families` row persisting the client, user, OP
  session, `auth_time`, `acr` and `amr`, then insert the first `refresh_tokens_v2` row: a 32-byte opaque token stored
  only as its SHA-256 hash, no parent, `idle_expires_at` = now + the client's `refresh_idle_ttl_seconds`,
  `absolute_expires_at` = now + the client's `refresh_token_ttl_seconds`, with the client IP, User-Agent and selected
  tenant. Database failures must surface as internal errors.

### 5.21 Authorization-code redemption

- `SPEC-5.21.1` `consume_authorization_code` must run in one SERIALIZABLE transaction that loads the code row by the
  SHA-256 hash of the presented code with a row lock, joined to its OP session to obtain the session `sid`, and must
  fail with `OidcInvalidGrant` `unknown authorization code` when no row exists.
- `SPEC-5.21.2` When the code row is already consumed or revoked, redemption must revoke every non-revoked refresh
  token family of the code's OP session with reason `reuse_detected`, commit, and fail with `OidcInvalidGrant`
  `authorization code already used`.
- `SPEC-5.21.3` Redemption must otherwise fail with `OidcInvalidGrant`, checking in this order: expired when
  now >= `expires_at` (`authorization code expired`); the presented client differs from the code's client
  (`client_id mismatch`); the presented redirect URI differs byte-for-byte (`redirect_uri mismatch`); the
  base64url-without-padding SHA-256 of `code_verifier` differs, compared in constant time, from the stored challenge
  (`PKCE verification failed`).
- `SPEC-5.21.4` Redemption must mark the code consumed with an update guarded by `consumed_at IS NULL`, failing with
  `OidcInvalidGrant` `authorization code already used` when zero rows change, and must commit only after the update;
  any validation failure must leave the code unconsumed.

### 5.22 Token endpoint: refresh grant

- `SPEC-5.22.1` The `refresh_token` grant must fail with `OidcInvalidRequest` `refresh_token is required` when the
  parameter is absent, and must pass the optional space-separated `scope` parameter to rotation as a narrowing
  request.
- `SPEC-5.22.2` After rotation, the grant must fail with `OidcInvalidGrant` `user not found` when the token's user no
  longer exists, and must answer `400` JSON `access_denied`, `user not entitled to this client` when the user has no
  active entitlement.
- `SPEC-5.22.3` For a client whose `tenant_claim_name` is set and a rotated token carrying a selected tenant, the grant
  must fail with `OidcInvalidGrant` `selected tenant is no longer assigned to this user` unless that tenant is among
  the user's current assignments for the client.
- `SPEC-5.22.4` On success the grant must answer `200` JSON with a new access token minted from the family's persisted
  `auth_time`, `acr`, `amr`, selected tenant and OP-session `sid`, `token_type` `Bearer`, `expires_in`, the new
  `refresh_token`, the effective `scope`, and no `id_token`.

### 5.23 Refresh-token rotation

- `SPEC-5.23.1` `rotate_refresh_token` must run in one SERIALIZABLE transaction that loads the token by the SHA-256
  hash of the presented value, joined to its family and OP session, locking the token and session rows, and must fail
  with `OidcInvalidGrant` `unknown refresh token` when none exists.
- `SPEC-5.23.2` When the loaded token is already used or revoked, rotation must revoke its whole family with reason
  `reuse_detected`, commit, write a Critical `AuthRefreshReuseDetected` audit-log entry (resource
  `refresh_token_family`, actor the token's user, metadata with the client id and the token's `used_at` and
  `revoked_at`), and fail with `OidcInvalidGrant` `refresh token already used - possible replay attack`; an
  audit-write failure must be logged at warn level naming the family and user and must not change the result.
- `SPEC-5.23.3` Rotation must otherwise fail with `OidcInvalidGrant`, checking in this order: client differs
  (`client_id mismatch`); now >= the token's idle or absolute deadline (`refresh token expired`); the family is revoked
  or missing (`token family revoked`); the OP session is revoked, past its absolute deadline or past its idle deadline
  (the classified reason text, one `invalid_grant` for all three).
- `SPEC-5.23.4` Rotation must compute the effective scope as the token's scope narrowed to the non-empty requested
  scope when one is given (requested scopes outside the token's scope are dropped), then, when the user's current
  non-revoked `granted_scopes` for the client is non-empty, intersected with it, and must fail with
  `OidcInvalidGrant` `refresh rejected: no scopes remain after intersection with current grants` when the result is
  empty.
- `SPEC-5.23.5` Rotation must mark the presented token used, fail with `OidcInvalidGrant`
  `client not found or disabled` when the client is missing or disabled, and insert a new token in the same family
  with the old token as parent, the same selected tenant, a fresh 32-byte opaque value stored as its SHA-256 hash, and
  deadlines from `rotated_refresh_deadlines` capped by the client's idle and absolute TTLs, the old token's absolute
  deadline, the OP session's absolute deadline and the slid session idle deadline.
- `SPEC-5.23.6` Rotation must slide the OP session in the same transaction: `last_active_at` = now and
  `idle_expires_at` = min(now + the session's `idle_ttl_seconds`, the session's `expires_at`). Any database failure
  in rotation must roll the whole transaction back and surface as an internal error naming the failed step.
- `SPEC-5.23.7` On success rotation must return the new raw token, its id, the user, the effective scope, the client,
  and the family's `selected_tenant_id`, `auth_time`, `acr`, `amr` and the OP session's `sid`.

### 5.24 OP session lifecycle

- `SPEC-5.24.1` `create_op_session` must generate a 32-byte opaque `sid` and insert an `op_sessions` row whose idle
  window is `session_idle_ttl_remember_secs` when `remember` is true and `session_idle_ttl_secs` otherwise, whose
  absolute window is 30 days when `remember` is true and 1 day otherwise, and which stores `idle_ttl_seconds`, the
  User-Agent, the client IP, `acr` and `amr`. A database failure must surface as an internal error
  `Failed to create op_session`.
- `SPEC-5.24.2` `load_op_session` must return a session only when it is not revoked, `expires_at > now` and
  `idle_expires_at > now`, and must surface a database failure as an internal error rather than as `None`.
- `SPEC-5.24.3` `revoke_op_session_by_sid` must set `revoked_at` only on a session satisfying the same liveness
  predicate, return `true` when a row was revoked and `false` otherwise (a missing or already-dead session is not an
  error), and surface a database failure as an internal error.
- `SPEC-5.24.4` A deadline equal to the current instant must count as expired for OP sessions, refresh tokens and
  authorization codes.

### 5.25 Access token minting

- `SPEC-5.25.1` `mint_access_token` must sign with EdDSA using the active key, header `kid` = the active key id and
  `typ` `at+jwt`, with `exp` = now + the client's `access_token_ttl_seconds`, and must surface a signing failure as an
  internal error `Failed to mint access token`.
- `SPEC-5.25.2` The access-token claims must be `iss` (issuer), `sub` (user id), `aud` (the client's `audience`),
  `client_id`, `scope` (space-joined), `jti` (random UUID v4), `iat` and `nbf` (now), `exp`, `auth_time`, `acr`, `amr`
  and `bunyip_role` (the user's role, emitted on every mint regardless of scope).
- `SPEC-5.25.3` The access token must carry `sid` only when a session id is supplied, must carry the selected tenant
  under the client's `tenant_claim_name` only when both are present, and must carry `given_name` and `family_name`
  only when the `profile` scope is granted and the source value is non-empty.
- `SPEC-5.25.4` Deserializing access-token claims must succeed when `bunyip_role` or `sid` is absent.

### 5.26 ID token minting

- `SPEC-5.26.1` `mint_id_token` must sign with EdDSA using the active key and header `kid`, leave `typ` at its default
  `JWT`, set `exp` = now + the client's `access_token_ttl_seconds`, and surface a signing failure as an internal error
  `Failed to mint ID token`.
- `SPEC-5.26.2` The ID-token claims must be `iss`, `sub`, `aud` and `azp` (both the client id), `exp`, `iat`,
  `auth_time`, `nonce`, `at_hash` (computed by `at_hash_eddsa` from the issued access token) and `bunyip_role`
  (always emitted).
- `SPEC-5.26.3` The ID token must carry `email`, `email_verified`, `membership_status` and `has_member_access` only
  when the `email` scope is granted; `given_name` and `family_name` only for the `profile` scope with non-empty
  values; `phone_number` only for the `phone` scope with a non-empty value; `sid` only when supplied; and the tenant
  claim under the same condition as the access token.

### 5.27 Access-token and ID-token hint verification

- `SPEC-5.27.1` `verify_at_jwt_claims` must reject with `OidcInvalidToken` a token whose header does not decode
  (`malformed JWT header`), whose `typ` is not `at+jwt` (`JWT typ must be at+jwt`), which lacks `kid`
  (`JWT header missing kid`) or whose `kid` is not in the key set (`unknown kid: {kid}`), and must verify EdDSA
  signature, `iss` equal to the issuer, `exp` and `nbf` with 30 seconds of leeway and no audience check, failing with
  `access token verification failed: {cause}`.
- `SPEC-5.27.2` The resource-server verification (`verify_at_jwt_for_rs`) must apply the checks of `SPEC-5.27.1`
  and additionally require `aud` to equal the configured `rs_audience`.
- `SPEC-5.27.3` The provider's `AtJwtVerifier` implementation must verify with the resource-server verification, load
  the user named by `sub` (failing with `Unauthorized` for a non-UUID `sub` or a missing user), and return the legacy
  access-token claims built from the token's `iss`, `iat`, `exp`, `jti` and the user row, together with the user row.
- `SPEC-5.27.4` `verify_id_token_client` must verify an ID token used as a logout hint for EdDSA signature, issuer and
  a `kid` in the key set, must not check expiry or audience, and must return its `aud` parsed as a UUID, failing with
  `OidcInvalidToken` `id_token aud is not a client_id` when it is not one.

### 5.28 Userinfo endpoint

- `SPEC-5.28.1` `userinfo` must read the bearer token from an `Authorization` header with the case-sensitive prefix
  `Bearer `, failing with `OidcInvalidToken` `missing Bearer token` when absent, and must verify it with
  `verify_at_jwt_claims`.
- `SPEC-5.28.2` `userinfo` must fail with `OidcInvalidToken` `invalid sub in access token` when `sub` is not a UUID,
  and `user not found` when the user row does not exist; it must reuse the user row already read earlier in the same
  request only when its id equals the token's `sub`, and otherwise read the row.
- `SPEC-5.28.3` `userinfo` must answer `200` JSON containing `sub` always; `email`, `email_verified`,
  `membership_status` and `has_member_access` only when the token's `scope` contains `email`; `given_name` and
  `family_name` only for `profile` with non-empty values; and `phone_number` only for `phone` with a non-empty value.

### 5.29 Revocation endpoint

- `SPEC-5.29.1` `revoke` must authenticate the client exactly as `token` does before acting on any token.
- `SPEC-5.29.2` `revoke` must hash the presented token with SHA-256, find a `refresh_tokens_v2` row with that hash and
  the authenticated client's id, and set its family's `revoked_at` to now with `revoke_reason` `client_revocation`;
  a token that is unknown or belongs to another client must change nothing.
- `SPEC-5.29.3` After authentication `revoke` must answer `200` with an empty body whether or not a token was found,
  and must log a revocation failure at warn level naming the client id and the error. It must not revoke access
  tokens and must ignore `token_type_hint`.

### 5.30 Logout endpoint

- `SPEC-5.30.1` `logout` must always answer `302` with `Location` and `Set-Cookie` clears from `AuthCookies::clear`
  for `access_token`, `refresh_token` and `bunyip_op_session` (no-domain, plus domain-scoped when `cookie_domain` is
  configured), using the `Secure` flag from `Config::cookies_secure`.
- `SPEC-5.30.2` `logout` must redirect to `post_logout_redirect_uri` only when that value is non-empty, an
  `id_token_hint` is supplied and verifies by `SPEC-5.27.4`, and the hinted client is enabled and lists the value
  exactly in its `post_logout_redirect_uris`; otherwise it must redirect to `/`.
- `SPEC-5.30.3` When `post_logout_redirect_uri` is supplied but the hint is missing or does not verify, `logout` must
  log a warning (naming the URI, or the verification error) and redirect to `/`.
- `SPEC-5.30.4` When it redirects to the supplied URI and a non-empty `state` is supplied, `logout` must append
  `state=<url-encoded>` using `&` if the URI already contains `?` and `?` otherwise.
- `SPEC-5.30.5` A database failure while checking the client's allowlist must propagate as an error response.
- `SPEC-5.30.6` When the request identifies an authenticated user (access token via cookie or bearer), `logout` must
  revoke that user's sessions as in `SPEC-5.31.1`, and must log a failure at warn level and still complete the
  redirect and cookie clears.

### 5.31 Back-channel logout

- `SPEC-5.31.1` `revoke_sessions_for_backchannel` must select the distinct `(client_id, backchannel_logout_uri, sid)`
  of the user's non-revoked OP sessions that have a non-revoked refresh-token family for a client with a non-null
  `backchannel_logout_uri`, then set `revoked_at` on all the user's non-revoked OP sessions, then set `revoked_at` and
  `revoke_reason` `logout` on all the user's non-revoked refresh-token families, and return the selected tuples.
  Each database failure must surface as an internal error.
- `SPEC-5.31.2` When targets exist, `logout` must deliver notifications in a spawned background task, sequentially per
  target, by minting a logout token and POSTing it form-encoded as `logout_token` to the client's URI with the shared
  HTTP client; it must log 2xx at info level, a non-2xx status, a transport failure and a mint failure each at warn
  level naming the client id (and URI where known), and must not retry.
- `SPEC-5.31.3` A logout token must be signed EdDSA with header `kid` = the active key id and `typ` `logout+jwt`, with
  claims `iss`, `aud` (client id), `iat`, `jti` (random UUID v4), `events`
  `{"http://schemas.openid.net/event/backchannel-logout": {}}`, `sub` (user id) and `sid`, and must verify against
  the published JWKS. A signing failure must surface as an internal error `Failed to mint logout token`.

### 5.32 Lifecycle event tokens

- `SPEC-5.32.1` `mint_lifecycle_token` must sign EdDSA with header `kid` = the active key id and `typ`
  `lifecycle-event+jwt`, with claims `iss`, `aud` (client id), `iat`, `jti` (random UUID v4) and `events` holding one
  entry keyed by the configured `lifecycle_event_key` whose value has `subject.id` = the user id, `type` = the event
  type and no `reason`. A signing failure must surface as an internal error `Failed to mint lifecycle token`.
- `SPEC-5.32.2` `lifecycle_event_targets` must return `(client_id, lifecycle_event_uri)` for every enabled client with a
  non-null `lifecycle_event_uri`, and surface a database failure as an internal error.

### 5.33 Entitlements and granted scopes

- `SPEC-5.33.1` `has_entitlement` must return true only when a `user_application_access` row exists for the user and
  client with `revoked_at` null, and must surface a database failure as an internal error.
- `SPEC-5.33.2` `grant_entitlement` must insert the row, or on conflict replace `granted_scopes` only when the existing
  row's `revoked_at` is null; it must never clear `revoked_at`.
- `SPEC-5.33.3` `add_scopes_to_grant` must insert the row, or on conflict set `granted_scopes` to the distinct union of
  the existing and supplied scopes only when the existing row's `revoked_at` is null; it must never clear `revoked_at`.
- `SPEC-5.33.4` `get_granted_scopes` must return the row's `granted_scopes`, an empty list when the row is absent or
  revoked, and must surface a database failure as an internal error.

### 5.34 Client registry lookup

- `SPEC-5.34.1` `load_client` must return the `oauth_clients` registration with the given `client_id` only when
  `disabled_at` is null, so a disabled registration is indistinguishable from an unregistered one, and must surface a
  database failure as an internal error `Failed to load oauth_client`.
- `SPEC-5.34.2` `allowed_secret_keys` and `allowed_config_keys` of a registration must be independent of
  `allowed_scopes`, and an empty list must grant no host secret or host config key.

### 5.35 Machine-client authentication

- `SPEC-5.35.1` `basic_credentials` must return `(client_id, client_secret)` from an `Authorization: Basic` header by
  base64-decoding the trimmed payload, requiring UTF-8, splitting at the first `:` and percent-decoding both halves,
  and must return `None` when the header is absent, is not `Basic`, does not decode, has no `:`, or a half does not
  percent-decode.
- `SPEC-5.35.2` `load_machine_client` must fail with `OidcInvalidClient` `invalid client_id format` for a non-UUID id and
  `unknown client` when no enabled registration exists, using only the database pool (no OIDC provider).
- `SPEC-5.35.3` `verify_machine_client` must first authenticate the secret under `SPEC-5.18` and only then require
  `client_credentials` in the client's `allowed_grant_types`, failing with `AppError::Forbidden` (`403`) when absent,
  so a wrong secret is always `401` and never reveals whether the client may relay.
- `SPEC-5.35.4` `hash_client_secret` must return a PHC-format Argon2 hash with `Argon2::default()` parameters and a
  fresh random salt, computed on the blocking pool (offload label `oidc client secret hash`), and must fail with an
  internal error `Failed to hash client secret` on a hashing error. A hash it produces must verify under `SPEC-5.18.3`.

### 5.36 OIDC error responses

- `SPEC-5.36.1` Errors that this crate builds directly as JSON must answer `400` with body
  `{"error": <code>, "error_description": <text>}`.
- `SPEC-5.36.2` `AppError::OidcInvalidGrant` and `AppError::OidcInvalidRequest` must be answered `400`, and
  `AppError::OidcInvalidClient` and `AppError::OidcInvalidToken` `401`, each with JSON `error` equal to
  `invalid_grant`, `invalid_request`, `invalid_client` and `invalid_token` respectively; `OidcInvalidClient` must add a
  `WWW-Authenticate` header.

## 6. OCI registry crate

### 6.1 Crate composition

- `SPEC-6.1.1` The bunyip-oci crate must expose the registry as a consumer-side wiring layer: its `errors`, `models`,
  `services`, `repositories` and `middleware` modules must glob-re-export their bunyip-domain counterparts and add the
  matching dunite-oci engine items, so handler code addresses them through `crate::` paths.
- `SPEC-6.1.2` The crate must depend on the dunite-oci engine pinned by an exact git `rev` in its manifest, never by
  branch, so moving to a newer engine is an explicit manifest diff.
- `SPEC-6.1.3` The crate must re-export the engine's `WwwAuthenticate` middleware from `middleware` so the binary does
  not need its own dunite-oci dependency.
- `SPEC-6.1.4` The crate must persist registry bookkeeping only through the two repositories `OciBlobCacheRepository`
  and `OciPullDailyCountRepository`, which implement the engine's `BlobStore` and `PullCounter` traits.

### 6.2 Routes

- `SPEC-6.2.1` `routes::configure` must register `GET /auth/token` to the token handler, outside the `/v2` scope.
- `SPEC-6.2.2` `routes::configure` must register `GET /v2` and `GET /v2/` to the version probe.
- `SPEC-6.2.3` `routes::configure` must register `GET` and `HEAD` on `/v2/{slug}/manifests/{reference}` to the manifest
  handler and `GET` and `HEAD` on `/v2/{slug}/blobs/{digest}` to the blob handler.
- `SPEC-6.2.4` `routes::configure` must register `POST`, `PUT`, `PATCH` and `DELETE` on every other path under `/v2/` to
  the push-rejection handler.
- `SPEC-6.2.5` The registry routes must be mounted on a dedicated actix `App` (own port and host), separate from the
  main API `configure()`, and only when the OCI registry is enabled in configuration.

### 6.3 Token endpoint: request parsing

- `SPEC-6.3.1` `GET /auth/token` must read credentials only from an `Authorization: Basic <base64(email:password)>`
  header, splitting the decoded UTF-8 text at the first `:`.
- `SPEC-6.3.2` When the `Authorization` header is absent, not `Basic`, not valid base64, not valid UTF-8 or has no `:`,
  the endpoint must answer the OCI `UNAUTHORIZED` error (HTTP 401) before any rate-limit counter or database lookup.
- `SPEC-6.3.3` The endpoint must accept the optional query parameters `service` and `scope`; `service` must be ignored.
- `SPEC-6.3.4` The per-email rate-limit key must be the lowercased email from the header.
- `SPEC-6.3.5` After authentication, a `scope` value must be accepted only in the exact form `repository:<slug>:pull`, taking `<slug>` as
  everything between the first `:` and the last `:`; any other kind, any action other than `pull`, or a missing second
  `:` must be answered with the OCI `DENIED` error (HTTP 403).

### 6.4 Token endpoint: rate limiting

- `SPEC-6.4.1` Before verifying a password the endpoint must refuse with HTTP 429 when the failed-verification counter
  for the lowercased email has reached the effective `oci_token_failures` cap (default 5 per 60 seconds).
- `SPEC-6.4.2` Before verifying a password the endpoint must refuse with HTTP 429 when the failed-verification counter
  for the client IP has reached the effective `oci_token_ip_failures` cap (default 20 per 60 seconds); this check must
  be skipped only when no client IP can be determined.
- `SPEC-6.4.3` The two failure-cap checks must be read-only and must compare with `count >= max_requests`, so the
  boundary value blocks and a request that may succeed does not consume the failure budget.
- `SPEC-6.4.4` Every request that passes both failure checks must be counted against the per-email
  `oci_token_throughput` cap (default 60 per 60 seconds), and must be refused with HTTP 429 when that count exceeds it.
- `SPEC-6.4.5` The effective cap of each of the three limits must be resolved through the persisted override for the
  limit's action, falling back to the compiled default; the check must use the resolved value.
- `SPEC-6.4.6` When a failure-cap read, override lookup or throughput increment fails, the endpoint must log the cause
  with the failing action and answer the internal OCI error (HTTP 500, code `UNKNOWN`); it must not allow the request through.
- `SPEC-6.4.7` A 429 from this endpoint must carry `Retry-After` taken from the window of the counter that tripped
  (same key and action); when that lookup fails it must log a warning naming the action and advertise 60 seconds.
- `SPEC-6.4.8` Each 429 must write an `oci_login_failed` audit record whose metadata holds the email and the reason
  `rate_limited`, `rate_limited_ip` or `rate_limited_throughput` matching the cap that tripped.

### 6.5 Token endpoint: credential verification

- `SPEC-6.5.1` An unknown email must be answered with HTTP 401 only after one Argon2 verification against a fixed dummy
  hash, so the response time does not reveal whether the email exists.
- `SPEC-6.5.2` An account with no password hash (passwordless) must be answered with HTTP 401 after the same dummy
  verification, with audit reason `no_password`.
- `SPEC-6.5.3` The dummy hash must be an Argon2id hash of a fixed string, computed once per process on first use inside
  the blocking-pool task, never on an actix worker.
- `SPEC-6.5.4` All Argon2 work in this endpoint (real and dummy verification) must run through `argon2_offload` on the
  blocking pool.
- `SPEC-6.5.5` When the dummy verification itself errors, the endpoint must log it at `error` and continue to answer 401.
- `SPEC-6.5.6` A wrong password must be answered with HTTP 401 and audit reason `bad_password`.
- `SPEC-6.5.7` When password verification fails to execute (as opposed to returning "no match"), the endpoint must log
  the cause with the user id and answer the internal OCI error (HTTP 500); it must not count it as a credential failure.
- `SPEC-6.5.8` Each credential failure (reasons `user_not_found`, `no_password`, `bad_password`) must increment both the
  per-email `oci_token_failures` counter and, when a client IP is known, the per-IP `oci_token_ip_failures` counter,
  write an `oci_login_failed` audit record, and answer 401.
- `SPEC-6.5.9` When incrementing a failure counter fails, the endpoint must still answer 401 and must log a warning
  naming which counter (email or IP) failed to increment.
- `SPEC-6.5.10` Authorization failures after a correct password (deleted account, no active membership, no entitlement)
  must not increment the failure counters.

### 6.6 Token endpoint: authorization

- `SPEC-6.6.1` A soft-deleted account must be answered with HTTP 401 and audit reason `inactive_user` after its password
  check passes.
- `SPEC-6.6.2` An account for which `User::is_access_allowed` is false (not admin, not lifetime, no unexpired trial, no
  active or in-grace membership) must be answered with HTTP 401 and audit reason `no_active_membership`.
- `SPEC-6.6.3` When `scope` names a slug, the token must be issued only if an active application with that slug exists
  and `Application::is_pullable` holds; otherwise the endpoint must answer OCI `NAME_UNKNOWN` (HTTP 404).
- `SPEC-6.6.4` When `scope` names a slug, the endpoint must apply `EntitlementRepository::is_allowed` for the user and
  the application, and on denial must answer `NAME_UNKNOWN` (HTTP 404) with audit reason `no_entitlement`, so a
  restricted product's existence does not leak through the status code.
- `SPEC-6.6.5` When the application or entitlement lookup fails, the endpoint must log the cause with the user id and
  slug and answer the internal OCI error (HTTP 500).
- `SPEC-6.6.6` When `scope` is absent, the endpoint must still issue a token, with an empty scope string; such a token
  must be unusable on `/v2/{slug}/*` routes.

### 6.7 Token endpoint: response and audit

- `SPEC-6.7.1` On success the endpoint must answer HTTP 200 JSON with `token` and `access_token` (the same bearer JWT),
  `expires_in` (the token service TTL in seconds) and `issued_at` (RFC 3339 now).
- `SPEC-6.7.2` The issued bearer token must carry the user id as subject and the granted scope string
  `repository:<slug>:pull` (or empty), as issued by the engine's token service.
- `SPEC-6.7.3` On success the endpoint must write an `oci_login_succeeded` audit record with the actor (id, email,
  role), the client IP, metadata `{"scope": <scope string>}` and, when a scope was granted, the resource
  `application:<application id>`.
- `SPEC-6.7.4` When an audit write fails (success or failure records), the endpoint must log a warning with the cause and
  must not change the HTTP outcome.

### 6.8 Bearer extractor

- `SPEC-6.8.1` `OciBearerUser` must read the `Authorization: Bearer <jwt>` header and answer `UNAUTHORIZED` (401) when it
  is absent or lacks the `Bearer ` prefix.
- `SPEC-6.8.2` `OciBearerUser` must validate the token through the engine's `OciTokenService::verify` (registry
  audience, expiry, issuer) and propagate its error.
- `SPEC-6.8.3` On every request `OciBearerUser` must re-load the user by the token subject and answer `UNAUTHORIZED` when
  the user does not exist, is soft-deleted, or fails `User::is_access_allowed`.
- `SPEC-6.8.4` When the token service or database pool is missing from app data, or the user lookup errors, the
  extractor must answer the internal OCI error (HTTP 500) via `internal_fault`/`internal_ctx`, which logs the cause first.
- `SPEC-6.8.5` `OciBearerUser` must carry the verified claims, the user's email and role, and `is_admin` must be true
  only for role `admin`.
- `SPEC-6.8.6` `OciBearerUser::assert_scope(slug)` must succeed only when the token scope equals
  `repository:<slug>:pull` exactly, and otherwise return `DENIED` (403); the extractor itself must not enforce scope.

### 6.9 Version probe

- `SPEC-6.9.1` `GET /v2/` and `GET /v2` must answer HTTP 200 with header `Docker-Distribution-API-Version:
  registry/2.0` for any valid bearer, with no scope requirement.
- `SPEC-6.9.2` The probe must answer `UNAUTHORIZED` (401) when the bearer is absent or fails extraction for any reason
  (invalid, expired, deleted user, no membership, or an internal fault).

### 6.10 Manifest endpoint

- `SPEC-6.10.1` For `GET` or `HEAD /v2/{slug}/manifests/{reference}` the handler must first require
  `assert_scope(slug)`; on mismatch it must write an `oci_pull_denied_scope` audit record (requested slug and token
  scope) and answer `DENIED` (403).
- `SPEC-6.10.2` The handler must answer `NAME_UNKNOWN` (404) when the Forgejo registry client is not configured, and the internal OCI error (HTTP 500, logged) when the manifest cache is missing from app data.
- `SPEC-6.10.3` The handler must load the application by slug among active applications and answer `NAME_UNKNOWN`
  (404) when absent or when `is_pullable` is false.
- `SPEC-6.10.4` The handler must apply the per-product entitlement gate (see SPEC-6.15.1) before touching the cache or
  upstream.
- `SPEC-6.10.5` The handler must serve only a `reference` that is the application's pinned image tag, any reference
  beginning with `sha256:`, or a tag recorded and not yanked in `application_versions`; any other reference must be
  answered `MANIFEST_UNKNOWN` (404).
- `SPEC-6.10.6` When the version-history lookup fails, the handler must log the cause with application id and
  reference and answer the internal OCI error (HTTP 500).
- `SPEC-6.10.7` The handler must use the request `Accept` header when present, else the default list: OCI image
  manifest v1, Docker manifest v2, OCI image index v1, Docker manifest list v2.
- `SPEC-6.10.8` On a manifest-cache miss the handler must fetch from the upstream registry using the application's
  `oci_image_owner`/`oci_image_name`, then insert the result into the cache keyed by application id and reference.
- `SPEC-6.10.9` A manifest response must be HTTP 200 with `Content-Type` set to the manifest media type,
  `Docker-Content-Digest` and `Content-Length` set, and a body only for `GET` (`HEAD` must send headers only).
- `SPEC-6.10.10` An upstream not-found must map to `MANIFEST_UNKNOWN` (404); every other upstream failure must map to
  `UPSTREAM` (502).
- `SPEC-6.10.11` When an upstream manifest failure maps to `UPSTREAM`, the handler must write an
  `oci_pull_failed_upstream` audit record (kind `manifest`, reference, error text).
- `SPEC-6.10.12` The manifest digest must be the upstream-supplied digest, or `sha256:<hex>` over the manifest bytes
  when upstream supplied an empty digest; the member pull path and the admin refresh path must share this one rule.
- `SPEC-6.10.13` Each served pull must write an `oci_pull_requested` audit record (reference) before the cache or
  upstream is consulted and an `oci_pull_completed` record (reference, digest) after the manifest is obtained.

### 6.11 Manifest metering and concurrency

- `SPEC-6.11.1` Only tag-addressed manifest requests (reference not beginning with `sha256:`) must count toward the
  per-user daily pull cap; digest-addressed requests must be served but not counted.
- `SPEC-6.11.2` A tag-addressed request must acquire a slot through the engine limiter, which enforces both the
  per-user concurrency bound and the daily cap, counting through `OciPullDailyCountRepository`.
- `SPEC-6.11.3` A digest-addressed request must acquire a concurrency-only slot, so it is bounded by the per-user
  concurrency limit without touching the daily counter.
- `SPEC-6.11.4` On a concurrency denial the handler must write an `oci_pull_denied_rate_limit` audit record with reason
  `concurrency` and answer `TOOMANYREQUESTS` (429) with no `Retry-After`.
- `SPEC-6.11.5` On a daily-cap denial the handler must write an `oci_pull_denied_rate_limit` audit record with reason
  `daily_cap` and the reset seconds, and answer 429 with `Retry-After` equal to the seconds until reset (never
  negative).
- `SPEC-6.11.6` When the limiter's daily-count read or increment fails, the handler must log the cause with the user id
  and answer the internal OCI error (HTTP 500).
- `SPEC-6.11.7` The concurrency slot must be released after the manifest is resolved and audited, before the response
  body is built.

### 6.12 Version-history self-heal

- `SPEC-6.12.1` After a tag-addressed manifest is obtained, the handler must record the tag and its resolved digest in
  `application_versions` (insert, or fill a NULL digest, never overwrite a recorded digest); digest references must not
  be recorded.
- `SPEC-6.12.2` A failure to record the version must be logged as a warning with application id and tag and must not
  fail the pull.

### 6.13 Blob endpoint

- `SPEC-6.13.1` For `GET` or `HEAD /v2/{slug}/blobs/{digest}` the handler must apply the same scope check, audit and
  `DENIED` answer as the manifest endpoint, then the same active/pullable lookup (`NAME_UNKNOWN` when missing or not
  pullable) and entitlement gate.
- `SPEC-6.13.2` The handler must answer the internal OCI error (HTTP 500) (logged) when the blob cache is missing from app data.
- `SPEC-6.13.3` The handler must obtain the blob through the engine's `BlobCache::get_or_fetch(owner, name, digest)`
  using the application's `oci_image_owner` and `oci_image_name`; the blob endpoint must not apply the pinned-tag
  allow-list, since blobs are addressed by digest.
- `SPEC-6.13.4` A blob response must be HTTP 200 with `Docker-Content-Digest`, `Content-Length` (the cached size) and,
  when known, `Content-Type`; a `HEAD` must send headers only.
- `SPEC-6.13.5` A `GET` must stream the cached file from disk in chunks rather than loading it into memory.
- `SPEC-6.13.6` A blob fetch failure must map through the engine's classification of the cache error; an unknown blob
  must answer `BLOB_UNKNOWN` (404), and every other failure must be logged at `error` with slug and digest and
  recorded as an `oci_pull_failed_upstream` audit record (kind `blob`, digest, error text).
- `SPEC-6.13.7` When the cached file cannot be opened after a successful fetch, the handler must log the cause with the
  digest and path and answer the internal OCI error (HTTP 500).
- `SPEC-6.13.8` A read error after streaming has started must be logged at `error` with slug and digest, because the
  status is already sent and the log is the only report.
- `SPEC-6.13.9` A blob digest that is not `sha256:` followed by 64 lowercase hex digits must be rejected by the engine
  before any path is built or any file is opened, so a crafted digest cannot reach the filesystem.

### 6.14 Read-only enforcement

- `SPEC-6.14.1` Any `POST`, `PUT`, `PATCH` or `DELETE` under `/v2/` must be answered with the OCI `UNSUPPORTED` error
  (HTTP 405) without consulting authentication, the database or upstream.

### 6.15 Entitlement gate and error disguise

- `SPEC-6.15.1` The entitlement gate must call `EntitlementRepository::is_allowed(user, is_admin, application)`; on
  denial it must write an `oci_pull_denied_entitlement` audit record (actor, application, client IP, slug) and answer
  `NAME_UNKNOWN` (404), the same as a non-pullable product.
- `SPEC-6.15.2` When the entitlement lookup fails, the gate must log the cause with user id and slug and answer the internal OCI error (HTTP 500); it must not treat the failure as allowed or denied.
- `SPEC-6.15.3` When Forgejo answers 401 or 403 to a manifest or blob fetch, the handler must log at `error` that the
  registry service credentials were rejected (naming the status and the token variable to verify) while the member
  receives only the generic `UPSTREAM` error.

### 6.16 Audit records

- `SPEC-6.16.1` Every registry audit record must carry the client IP resolved by `extract_client_ip` (trusted-proxy
  aware) and, for authenticated requests, the actor id, email and role.
- `SPEC-6.16.2` The registry must use these audit actions: `oci_login_succeeded`, `oci_login_failed`,
  `oci_pull_requested`, `oci_pull_completed`, `oci_pull_failed_upstream`, `oci_pull_denied_rate_limit`,
  `oci_pull_denied_scope`, `oci_pull_denied_entitlement`.
- `SPEC-6.16.3` An audit write failure on any registry path must be logged as a warning with the cause and must never
  change the HTTP outcome of the request.

### 6.17 Admin cache refresh

- `SPEC-6.17.1` `POST /v1/admin/applications/{slug}/oci/refresh` must require an admin user and answer a not-found error for resource `OCI
  registry disabled` when the Forgejo client or the manifest cache is not configured.
- `SPEC-6.17.2` The refresh must answer a not-found error for resource `Application` when no active application has the slug and for
  `Application not pullable` when `is_pullable` is false.
- `SPEC-6.17.3` The refresh must drop every cached manifest of the application, then re-fetch the pinned tag with the
  accept list OCI image manifest v1 and OCI image index v1 and insert it into the cache with the digest rule of
  SPEC-6.10.12.
- `SPEC-6.17.4` When the re-fetch fails, the refresh must log a warning with the cause and slug and still answer
  success, because the invalidation already took effect and the next pull repopulates the cache.
- `SPEC-6.17.5` On success the refresh must answer the standard no-data success envelope with the request id.

### 6.18 Blob cache repository

- `SPEC-6.18.1` `OciBlobCacheRepository::upsert` must insert a row keyed by `content_digest` or, on conflict, update
  `size_bytes`, keep the existing `media_type` when the new one is NULL, and set `last_accessed_at` to now.
- `SPEC-6.18.2` `touch` must set `last_accessed_at` to now for the digest; `find` must return the row or `None`.
- `SPEC-6.18.3` `total_size_bytes` must return the sum of `size_bytes` as a non-NULL `i64` (0 for an empty table),
  casting the NUMERIC sum back to BIGINT so the row decodes.
- `SPEC-6.18.4` `oldest(limit)` must return at most `limit` rows ordered by `last_accessed_at` ascending (LRU order).
- `SPEC-6.18.5` `delete` must remove one digest; `delete_except(keep)` must delete every row whose digest is not in
  `keep` and return the deleted digests so the caller can unlink their files.
- `SPEC-6.18.6` Every repository method must return the database error to its caller; none may swallow it.

### 6.19 Pull counter repository

- `SPEC-6.19.1` `OciPullDailyCountRepository::increment(user, day)` must atomically insert a count of 1 or add 1 to the
  row for (user, UTC day) and return the new count.
- `SPEC-6.19.2` `decrement` must lower the count by 1 for (user, day) and must never take it below 0; it must be a
  no-op when no row exists.
- `SPEC-6.19.3` `current` must return the stored count, or 0 when no row exists for that user and day (absence by
  contract, since a day with no pulls has no row).
- `SPEC-6.19.4` Rows must be removed with their user (foreign key cascade, see SPEC-4.8.4).

### 6.20 Error wire format

- `SPEC-6.20.1` Registry errors must be rendered as the OCI error envelope (`application/json`) with this status map:
  `UNAUTHORIZED` 401, `DENIED` 403, `NAME_UNKNOWN`/`MANIFEST_UNKNOWN`/`BLOB_UNKNOWN` 404, `TOOMANYREQUESTS` 429,
  `UPSTREAM` 502, `UNSUPPORTED` 405, internal 500.
- `SPEC-6.20.2` A 429 carrying a retry window must set the `Retry-After` header to that many seconds.
- `SPEC-6.20.3` Every 401 on the registry surface must carry `WWW-Authenticate: Bearer realm="<token endpoint
  URL>",service="<registry host>"`, added by the `WwwAuthenticate` middleware the binary wraps around the registry App.
- `SPEC-6.20.4` An unexpected failure must be converted to the internal OCI error only through `internal_fault` or
  `OciErrorContext::internal_ctx`, which log the underlying cause (naming the operation and id) before collapsing it.

## 7. Domain crate core (root, models, repositories, middleware)

### 7.1 Domain crate root

Covers the `bunyip-domain` crate root, manifest, application configuration, environment inventory, configuration
providers, system settings file layer, feature registry, device labels and the transactional email templates.

#### Crate root, manifest and test support

- `SPEC-7.1.1` The crate root must re-export the `dunite_core` modules `errors`, `responses` and `validation` under
  those same names, so domain sources keep resolving `crate::errors`, `crate::responses` and `crate::validation`.
- `SPEC-7.1.2` The crate root must re-export `Config`, `AppError`, `ApiResponse` and `ResponseMeta` at the top level.
- `SPEC-7.1.3` Test builds must provide one crate-wide `env_lock` (a mutex whose poisoning is recovered, not
  propagated), and every test that sets or removes a process environment variable must hold it for its whole duration.
  The module must not be compiled outside `cfg(test)`.
- `SPEC-7.1.4` Every `dunite-*` git dependency in the crate manifest must be pinned by `rev`, never by `branch`, so a
  dunite bump is an explicit manifest diff.
- `SPEC-7.1.5` The graph crates `dunite-core`, `dunite-download`, `dunite-oidc-op`, `dunite-webhook`,
  `dunite-argon2-offload` and `dunite-mailer` must be pinned to the same `rev`, so bunyip-domain and the dunite crates
  share one `AppError` type.
- `SPEC-7.1.6` `dunite-stripe-core` and `dunite-stripe` must be pinned to the same `rev` as each other, so one
  `dunite-stripe-core` exists in the dependency tree.
- `SPEC-7.1.7` The crate manifest must inherit `version`, `edition`, `authors`, `license`, `repository` and the lint
  table from the workspace (`workspace = true`), and must not set them locally.

#### Environment inventory and the startup audit

- `SPEC-7.1.8` `ENV_INVENTORY` must be the written inventory followed by, for every entry of `rate_limit_vars()`, two
  `Defaulted` specs named by that entry's `max_requests` and `window_seconds` variables, with the entry's setting text as
  the feature text.
- `SPEC-7.1.9` Every `ENV_INVENTORY` name must be unique, every entry must have a non-empty `feature` text, every entry
  that is not `Defaulted` must have a non-empty `remedy`, and every `gate` must name another classified inventory entry.
- `SPEC-7.1.10` `DATABASE_URL` and `SECRETS_STORAGE` must be classified `Required`: absence is a startup failure in every
  environment.
- `SPEC-7.1.11` `JWT_SECRET`, `APP_ENCRYPTION_KEY` and `BUNYIP_WEBHOOK_SIGNING_SECRET` must be classified
  `RequiredInProduction`, and `OIDC_JWT_PRIVATE_KEY_PATH` and `OIDC_JWT_ACTIVE_KID` must be `RequiredInProduction` gated
  by `OIDC_ISSUER`, so an OIDC-less deployment is not asked for key material.
- `SPEC-7.1.12` No integration variable may be classified `Required` or `RequiredInProduction`: at least `SMTP_HOST`,
  `FORGEJO_BASE_URL`, `FORGEJO_API_TOKEN`, `OCI_REGISTRY_ENABLED`, `OCI_REGISTRY_SERVICE`, `INFISICAL_ENABLED`,
  `IP2LOCATION_DB_PATH`, `IP2PROXY_DB_PATH`, `BUNYIP_UPDATE_CHECK_URL` and `MOKOSH_BACKUP_API_URL` must stay optional so a
  deployment with every integration off boots.
- `SPEC-7.1.13` These variables must be classified `FeatureGating`, each with the functionality that is off and a remedy:
  `APP_DATABASE_URL`, `BUNYIP_APP_PASSWORD`, `MAILER_WEBHOOK_SECRET`, `SETUP_DEFAULT_ADMIN`, `BOOTSTRAP_ADMIN_EMAIL`,
  `TRUSTED_PROXY_CIDR`, `OIDC_ISSUER`, `FORGEJO_BASE_URL`, `FORGEJO_API_TOKEN`, `MOKOSH_PROVIDER_STATUS_URL`,
  `DRILLMARK_PROVIDER_STATUS_URL`, `PROVIDER_STATUS_CLIENT_ID`, `PROVIDER_STATUS_CLIENT_SECRET`, `OCI_REGISTRY_ENABLED`,
  `SMTP_HOST`, `IP2LOCATION_DB_PATH`, `IP2PROXY_DB_PATH`, `BUNYIP_UPDATE_CHECK_URL`, `INFISICAL_ENABLED`,
  `MOKOSH_APPS_REDIRECT_URIS`, `MOKOSH_APPS_AUDIENCE`, `DRILLMARK_REDIRECT_URIS`, `DRILLMARK_AUDIENCE`,
  `LETS_CHAT_REDIRECT_URIS`, `LETS_CHAT_AUDIENCE`, `MOKOSH_WEBHOOK_URL` and `MOKOSH_BACKUP_API_URL`.
- `SPEC-7.1.14` These `FeatureGating` variables must be gated, so they are reported only when the gate variable is set:
  `OCI_REGISTRY_SERVICE` by `OCI_REGISTRY_ENABLED`; `ADMIN_NOTIFICATION_EMAILS` by `SMTP_HOST`;
  `BUNYIP_UPDATE_CHECK_TOKEN` by `BUNYIP_UPDATE_CHECK_URL`; `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`,
  `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET` by `INFISICAL_ENABLED`; `MOKOSH_APPS_POST_LOGOUT_REDIRECT_URIS` and
  `MOKOSH_APPS_BACKCHANNEL_LOGOUT_URI` by `MOKOSH_APPS_REDIRECT_URIS`; `DRILLMARK_POST_LOGOUT_REDIRECT_URIS` and
  `DRILLMARK_BACKCHANNEL_LOGOUT_URI` by `DRILLMARK_REDIRECT_URIS`; `LETS_CHAT_POST_LOGOUT_REDIRECT_URIS` and
  `LETS_CHAT_CLIENT_SECRET_HASH` by `LETS_CHAT_REDIRECT_URIS`.
- `SPEC-7.1.15` Every other variable bunyip-api or bunyip-web reads must be classified `Defaulted`, including all
  bunyip-web variables (`BUNYIP_API_URL`, `BUNYIP_API_PUBLIC_ORIGIN`, `BUNYIP_BIND_ADDR`, `BUNYIP_OIDC_ISSUER`,
  `BUNYIP_APP_DOMAIN`, `BUNYIP_COMMUNITY_URL`, `CSP_CONNECT_SRC`, `CSP_FORM_ACTION`), so an absent value never blocks
  startup and never logs at boot. A new variable must be added to the inventory in the same change as its first read.
- `SPEC-7.1.16` `audit_required(is_production)` must return one `ConfigFailure` per inventory entry that is `Required`,
  or `RequiredInProduction` when `is_production` is true, whose gate (if any) is set, and whose own value is absent;
  `FeatureGating` and `Defaulted` entries must never appear.
- `SPEC-7.1.17` A variable must count as present only when it resolves to a non-empty value, through the plain variable
  or its `{NAME}_FILE` indirection.
- `SPEC-7.1.18` The failure for an absent required entry must carry `var` = the variable name, `reason` = the entry's
  feature text and `remedy` = the entry's remedy text.
- `SPEC-7.1.19` `feature_gaps()` must return, in inventory order, every `FeatureGating` entry whose gate (if any) is set
  and whose value is absent. `log_feature_gaps()` must emit exactly one `warn` per such entry, with field `env_var` and
  the message `"{name} is not set: {feature}. {remedy}"`, and must log nothing for `Defaulted` entries.
- `SPEC-7.1.20` `env_spec(name)` must return the inventory entry or `None`. `required_failure(name)` for a name with no
  entry must return a failure with reason `"is required but missing"` and remedy `"Set it in the api environment."`.
- `SPEC-7.1.21` `finish_startup_audit` must return `Ok` for an empty failure list, and otherwise
  `Err(ConfigError::Startup)` holding one failure per variable name (the first reported), so a variable reported by both
  the presence audit and a value check appears once.
- `SPEC-7.1.22` `secret_env` must stay re-exported from this module (`crate::config::secret_env`), reading a secret from
  `{NAME}_FILE` (trimmed file contents) or the plain variable.

#### Startup configuration load

- `SPEC-7.1.23` `Config::from_env` must load a `.env` file when present and then parse the process environment;
  `Config::from_env_inner` must parse only the variables already in the process environment and never load a `.env`
  file.
- `SPEC-7.1.24` `ENVIRONMENT` must default to `production`, and `Config::is_production` must be true only when the value
  equals `production` exactly.
- `SPEC-7.1.25` Loading must collect every startup failure in one pass (presence audit, `APP_PORT`, `SECRETS_STORAGE`,
  `APP_ENCRYPTION_KEY`, `APP_ENCRYPTION_KEY_PREV`, the production `dev-` kid check) and return
  `Err(ConfigError::Startup(failures))` with all of them. It must not return early on a single failure and must not
  panic on a missing or malformed required value.
- `SPEC-7.1.26` `APP_PORT` must default to `4000`. A value that does not parse as a `u16` must add a failure for
  `APP_PORT` whose reason carries the parse error and whose remedy says to use a TCP port in `1..=65535`.
- `SPEC-7.1.27` `HOST_IP` must default to `0.0.0.0` and `RUST_LOG` to `info`. `Config::server_addr` must return
  `"{host}:{port}"`.
- `SPEC-7.1.28` `DATABASE_URL`, `APP_DATABASE_URL` and `BUNYIP_APP_PASSWORD` must be read through `secret_env` (plain or
  `_FILE`). `app_database_url` and `app_password` must be `None` when unset.
- `SPEC-7.1.29` `cors_origin`, `web_origin` and `cookie_domain` must come from the system-level environment layer only
  (`CORS_ORIGIN` default `http://localhost:5173`, `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`). When `BUNYIP_WEB_ORIGIN` is
  unset, `web_origin` must be the first non-empty trimmed entry of `cors_origin`, else `http://localhost:5173`.
- `SPEC-7.1.30` `APP_NAME` must default to `localhost`.
- `SPEC-7.1.31` `SECRETS_STORAGE` must be parsed with `SecretsProvider::parse`. A present value that is not one of
  `environment`, `database`, `infisical` must add a failure for `SECRETS_STORAGE` that quotes the value and lists the legal
  values; an absent value is reported by the presence audit. Neither case may produce a usable `Config`.
- `SPEC-7.1.32` In production, when the resolved email configuration is not enabled, loading must log one `warn` that
  transactional email is disabled and must still succeed; it must not add a startup failure for `SMTP_HOST`.
- `SPEC-7.1.33` `cookie_shared_domain` must be true only for `BUNYIP_COOKIE_SHARED_DOMAIN` equal to `true` or `1`, and
  false by default. When `cookie_domain` is set and `cookie_shared_domain` is false, loading must log one `warn` that
  the OP session cookie is host-only.
- `SPEC-7.1.34` `TRUSTED_PROXY_CIDR` must be parsed as a comma-separated list of CIDR ranges. Blank entries must be
  skipped, each unparseable entry must be skipped with a `warn` naming the entry and the parse error, and an unset or
  all-invalid list must yield no trusted proxy.
- `SPEC-7.1.35` `APP_ENCRYPTION_KEY` must be read through `secret_env` and decoded as 32 hex-encoded bytes. When absent
  in production it must add the required failure; when absent elsewhere it must use the all-zero development key and log
  a `warn` that secrets encrypted with it are not protected.
- `SPEC-7.1.36` `APP_ENCRYPTION_KEY_PREV` must be read through `secret_env` as a comma-separated list of 32-byte hex
  keys, in order (newest first), skipping blank entries; unset must yield an empty list.
- `SPEC-7.1.37` A key that is not valid hex must produce a failure with reason `"the value is not valid hex ({error})"`,
  and one that decodes to other than 32 bytes must produce reason `"the value decodes to {n} bytes, not the required
  32"`; both must carry a remedy naming 32 hex-encoded bytes and must not panic.
- `SPEC-7.1.38` `APP_KEY_VERSION` must be the `i16` stamped on rows written under the current key, default `1`.
- `SPEC-7.1.39` In production with OIDC enabled, an `OIDC_JWT_ACTIVE_KID` that starts with `dev-` (case-insensitive) must
  add a failure for `OIDC_JWT_ACTIVE_KID`.
- `SPEC-7.1.40` `BOOTSTRAP_ADMIN_EMAIL` must be trimmed and lowercased, and an empty result must be `None`.
- `SPEC-7.1.41` `IP2LOCATION_DB_PATH` and `IP2PROXY_DB_PATH` must be trimmed, and an empty result must be `None`
  (the feature is then disabled).
- `SPEC-7.1.42` `login_approval_enabled`, `signup_bot_guard_enabled`, `country_allow` and `country_deny` must be taken
  from the resolved system settings (file layer, then environment, then built-in default false/false/empty/empty).
- `SPEC-7.1.43` After a successful load, one `info` line `"Configuration loaded"` must be logged with `host`, `port`,
  `environment`, `bootstrap_admin_configured` and `secrets_provider`, and with no secret value.
- `SPEC-7.1.44` `Config::app_key_set` must return an `EncryptionKeySet` whose current key, current version and previous
  keys are `app_encryption_key`, `app_key_version` and `app_encryption_key_prev`.
- `SPEC-7.1.45` `Config::trusts_forwarded_client_ip` must be true only when at least one trusted proxy is configured.
- `SPEC-7.1.46` `Config::cookies_secure(req)` must return true when the environment is production, when the request
  transport is TLS, or when the request line is absolute-form `https`; otherwise only when the immediate socket peer is
  inside a trusted proxy range and the first `X-Forwarded-Proto` value equals `https` (case-insensitive). It must never
  honour `X-Forwarded-Proto` from an untrusted peer.
- `SPEC-7.1.47` `Config::op_session_cookie_domain` must return `cookie_domain` only when `cookie_shared_domain` is true,
  and `None` otherwise.
- `SPEC-7.1.48` `Config::e2e_purge_enabled` must be true only when the environment is a non-empty name other than
  `production` (case-insensitive) and the secret `BUNYIP_E2E_BOOTSTRAP_ALLOW` trims to `true`.
- `SPEC-7.1.49` `ConfigError` must have the variants `MissingEnv(name)`, `InvalidValue(name, reason)` and
  `Startup(failures)`; the `Startup` display must give the failure count and the comma-joined variable names.
- `SPEC-7.1.50` `ConfigError::log_startup_report` must emit one `error` per `Startup` failure with field `env_var` and the
  message `"Startup configuration error: {var} is not usable - {reason}. {remedy}"`, and one `error` for any other
  variant. It must not panic.
- `SPEC-7.1.51` A `ConfigFailure` must carry the variable name (`var`), why the api cannot start (`reason`) and what the
  operator must do (`remedy`).

#### Secrets provider and governed secrets

- `SPEC-7.1.52` `SecretsProvider` must have exactly the values `environment`, `database` and `infisical`, in that order
  in `ALL`; `parse` must accept them trimmed and case-insensitively and return `None` for anything else;
  `LEGAL_VALUES` must be `"environment, database, infisical"`.
- `SPEC-7.1.53` `SecretsProvider::is_writable` must be false for `environment` and true for `database` and `infisical`.
- `SPEC-7.1.54` `GovernedSecret::ALL` must list, in order, `SmtpPassword`, `StripeSecretKey`, `StripeWebhookSecret`,
  `SupportImapPassword`, `MirzamApiToken` and `MokoshGoogleClientSecret`, with `name()` returning `SMTP_PASSWORD`,
  `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SUPPORT_IMAP_PASSWORD`, `MIRZAM_API_TOKEN` and
  `MOKOSH_GOOGLE_CLIENT_SECRET`.
- `SPEC-7.1.55` `GovernedSecret::form_field` must return `smtp_password`, `secret_key`, `webhook_secret`,
  `imap_password`, `api_token` and `google_client_secret`, and `secret_file` must return `smtp_password`,
  `stripe_secret_key`, `stripe_webhook_secret`, `support_imap_password`, `mirzam_api_token` and
  `mokosh_google_client_secret`, in the order of `SPEC-7.1.54`.
- `SPEC-7.1.56` `GovernedSecret::feature` must return a non-empty operator-facing sentence naming the capability that
  stops working when no provider holds the secret.
- `SPEC-7.1.57` `GovernedSecret::read_environment` must read only the `{NAME}_FILE` secret file (trimmed, empty is
  absent) and must never read the plain `{NAME}` variable. An unreadable file path must be logged at `error` with the
  variable, path and cause, and treated as absent.
- `SPEC-7.1.58` `InfisicalSettings::from_env` must read `INFISICAL_ENABLED` (true only for `true` or `1`, default false),
  `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID` (default empty), `INFISICAL_ENVIRONMENT` (trimmed, no legacy alias, default
  empty), `INFISICAL_SECRET_PATH` (default `/`), and `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET` through
  `secret_env` (default empty).

#### Email configuration

- `SPEC-7.1.59` `EmailConfig::from_env(is_production)` must equal `EmailConfig::resolve` over an environment-only stack
  with no SMTP password.
- `SPEC-7.1.60` `EmailConfig::resolve` must take `smtp_password` as an argument already resolved from the one declared
  provider (empty string when `None`), and must never read it as a configuration key.
- `SPEC-7.1.61` `SMTP_TLS` must resolve to `Starttls` only when the value equals `starttls` case-insensitively; every
  other value, including absent, must resolve to `Implicit`. `SmtpTls::as_str` must return `implicit` or `starttls`.
- `SPEC-7.1.62` `smtp_host` must default to `localhost`. `smtp_port` must default to 465 for implicit and 587 for
  starttls, where the TLS mode used for the default is the one the providers below the database declare; an unparseable
  or unusable `SMTP_PORT` must fall through to the next provider and then to that default.
- `SPEC-7.1.63` `EmailConfig.enabled` must be the `EMAIL_ENABLED` value (true only for `true` or `1`) from the database
  or file provider when one holds it; otherwise it must be true when the deployment is production with an `smtp_host`
  that is neither empty nor `localhost`, or when the environment's `EMAIL_ENABLED` is `true` or `1`. An environment
  `EMAIL_ENABLED=false` must not force sending off.
- `SPEC-7.1.64` `EmailConfig.log_tokens` must be true only outside production and only when `EMAIL_LOG_TOKENS` is
  `true` or `1`, so single-use tokens never reach a production log.
- `SPEC-7.1.65` `from_email` must default to `noreply@localhost` and `from_name` to `localhost`; `smtp_username` must
  default to empty; `base_url` must be `APP_URL`, else `CORS_ORIGIN`, else `http://localhost:5173`; `app_name` must be
  `APP_NAME` defaulting to `localhost`.
- `SPEC-7.1.66` `admin_notification_emails` must be the comma-split of `ADMIN_NOTIFICATION_EMAILS`, trimmed, with blank
  entries dropped; absent yields an empty list.
- `SPEC-7.1.67` `smtp_ehlo_name` and `support_inbox_email` must be read from `SMTP_EHLO_NAME` and `SUPPORT_INBOX_EMAIL`
  (environment only), trimmed, with an empty result as `None`.
- `SPEC-7.1.68` The IMAP fields must resolve as: `imap_host` and `imap_username` default empty; `imap_port` defaults to
  993; `imap_mailbox` defaults to `INBOX` and an empty value counts as unset; `imap_enabled` is true only for `true` or
  `1`, default false; `imap_poll_secs` is the environment-only `SUPPORT_IMAP_POLL_SECS`, default 60.
- `SPEC-7.1.69` `EmailConfig::database_provider(row)` must hold a column only when it would have won the previous
  per-field fallback: a NULL, an empty `smtp_host`/`from_email`/`from_name`/`imap_host`/`imap_mailbox`, an `smtp_tls`
  other than `starttls` or `implicit`, and an `smtp_port`/`imap_port` outside `u16` must not be held. It must not hold
  the encrypted password columns. A refused key must return a `ConfigFailure`.
- `SPEC-7.1.70` `EmailConfig::db_smtp_password` and `db_imap_password` must return `None` when the row has no ciphertext
  and nonce, and the decrypted value when `APP_ENCRYPTION_KEY` or a previous key decrypts it. A ciphertext no key
  decrypts must be logged at `error` with the cause and `key_version` and returned as `None`; it must not fail boot.
- `SPEC-7.1.71` `EmailConfig::ehlo_name` must return, in order: the trimmed non-empty `smtp_ehlo_name`; the host of
  `base_url`; the domain part of `from_email`; else the mail library default. An IP literal must be sent as an address
  literal (IPv4 or IPv6 client id), with surrounding brackets accepted and ignored, and any other host as a domain.
- `SPEC-7.1.72` `SMTP_FROM` must be parsed into two keys: the address is the text between the first `<` and the first
  `>`, trimmed, else the whole trimmed value; the display name is the trimmed text before `<`, or `localhost` when
  absent or empty.

#### Auto-ban, tier, download, OCI and OIDC configuration

- `SPEC-7.1.73` `AutoBanConfig::database_provider(row)` must not hold a NULL column, and must not hold a negative
  `threshold` or a negative `window_secs`/`ban_duration_secs` (narrowing to `u32`/`u64` must fail closed to absent).
- `SPEC-7.1.74` `AutoBanConfig::resolve` must default `enabled` to true (false only for `false` or `0`), `threshold` to 5,
  `window_secs` to 3600 and `ban_duration_secs` to 86400, reading `AUTO_BAN_ENABLED`, `AUTO_BAN_THRESHOLD`,
  `AUTO_BAN_WINDOW_SECS` and `AUTO_BAN_DURATION_SECS` through the stack. `AutoBanConfig` must be `Copy`.
- `SPEC-7.1.75` `TierConfig::database_provider(row)` must hold only `TIER_LIFETIME_SLOTS`, `TIER_EARLY_ADOPTER_SLOTS`,
  `TIER_EARLY_ADOPTER_TRIAL_DAYS` and `TIER_STANDARD_TRIAL_DAYS`, and no other tier column.
- `SPEC-7.1.76` `TierConfig::resolve` must default `lifetime_slots` to 5, `early_adopter_slots` to 5,
  `early_adopter_trial_days` to 90 and `standard_trial_days` to 30. The price ids, product ids, `pricing_enabled` and
  `orgs_enabled` must come only from the `tier_config` row (`None`/false when no row); each `*_visible` flag must be true
  when no row exists.
- `SPEC-7.1.77` `DownloadConfig::from_env` must trim `FORGEJO_BASE_URL` (empty is `None`), read `FORGEJO_API_TOKEN`
  through `secret_env`, and default `DOWNLOAD_CACHE_DIR` to `/var/cache/bunyip-downloads`, `DOWNLOAD_CACHE_MAX_BYTES` to
  10737418240, `DOWNLOAD_CONCURRENCY_PER_USER` to 2, `DOWNLOAD_DAILY_LIMIT_PER_USER` to 50 and
  `FORGEJO_RELEASE_CACHE_TTL_SECS` to 300. `DownloadConfig::enabled` must be true only when both the base URL and the
  token are set.
- `SPEC-7.1.78` `OciConfig::from_env` must default `OCI_REGISTRY_ENABLED` to false (true only for `true` or `1`),
  `OCI_REGISTRY_PORT` to 18081, `OCI_REGISTRY_SERVICE` to `oci.example.com`, `OCI_REGISTRY_REALM` to `None` (empty is
  `None`), `OCI_BLOB_CACHE_DIR` to `/var/cache/bunyip-oci`, `OCI_BLOB_CACHE_MAX_BYTES` to 53687091200,
  `OCI_MANIFEST_CACHE_TTL_SECS` to 300, `OCI_CONCURRENT_MANIFESTS_PER_USER` to 2, `OCI_PULLS_PER_USER_PER_DAY` to 50 and
  `OCI_TOKEN_TTL_SECS` to 900.
- `SPEC-7.1.79` `OciConfig::realm_url` must return the configured realm, else `https://{service}/auth/token`.
- `SPEC-7.1.80` `OciConfig::validate` must return `Err(message)` when the service host (before any `:`) is empty, when
  the realm contains a double quote or a control character, when the realm is not a valid URL, and when the realm has no
  host. When the realm host differs from the service host it must succeed and log one `warn` naming both.
- `SPEC-7.1.81` `OidcConfig::from_env` must treat an unset or empty `OIDC_ISSUER` as `None` and default
  `OIDC_JWT_PRIVATE_KEY_PATH` to `secrets/jwt_private.pem`, `OIDC_JWT_ACTIVE_KID` to `dev-key`,
  `OIDC_JWT_PUBLIC_KEYS_DIR` to `secrets`, `OIDC_REFRESH_TOKEN_TTL_SECONDS` to 2592000, `OIDC_REFRESH_IDLE_TTL_SECONDS` to
  1209600, `SESSION_IDLE_TTL_SECONDS` to 28800, `SESSION_IDLE_TTL_REMEMBER_SECONDS` to 1209600,
  `OIDC_LIFECYCLE_EVENT_KEY` to `urn:bunyip:event:user-lifecycle` and `OIDC_RS_AUDIENCE` to `urn:bunyip:rs` (an empty
  value counts as unset for the last two).
- `SPEC-7.1.82` `OIDC_ACCESS_TOKEN_TTL_SECONDS` must default to 600 and be clamped to `60..=900`, and
  `OIDC_CODE_TTL_SECONDS` must default to 60 and be capped at 120.
- `SPEC-7.1.83` `OidcConfig::enabled` must be true only when `issuer` is `Some`; with it unset, the OIDC endpoints are
  disabled.

#### Configuration providers and the stack

- `SPEC-7.1.84` The configuration providers must be `database` (priority 1), `file` (priority 2) and `environment`
  (priority 3), `BY_PRIORITY` must list them in that order, and their report spelling must be the lowercase names.
- `SPEC-7.1.85` A provider's `enumerate` must return `Keys(list)` when it can list its keys and `Unsupported` when it
  cannot, and `Unsupported` must never be reported as "holds nothing". The trait defaults must be: `has` is
  `get().is_some()`, `enumerate` is `Unsupported`, `unreadable` and `location` are `None`.
- `SPEC-7.1.86` `CONFIG_KEYS` must be the written key list followed by the generated `RATE_LIMIT_{ACTION}_*` pair per
  `rate_limit_vars()` entry, and `config_key(key)` must return the spec or `None`. Every key's `source_var` must name an
  `ENV_INVENTORY` variable.
- `SPEC-7.1.87` The written declared keys must be `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`, `SMTP_USERNAME`,
  `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`, `ADMIN_NOTIFICATION_EMAILS`, `EMAIL_ENABLED`, `SUPPORT_IMAP_HOST`,
  `SUPPORT_IMAP_PORT`, `SUPPORT_IMAP_USERNAME`, `SUPPORT_IMAP_MAILBOX`, `SUPPORT_IMAP_ENABLED`, `AUTO_BAN_ENABLED`,
  `AUTO_BAN_THRESHOLD`, `AUTO_BAN_WINDOW_SECS`, `AUTO_BAN_DURATION_SECS`, `TIER_LIFETIME_SLOTS`,
  `TIER_EARLY_ADOPTER_SLOTS`, `TIER_EARLY_ADOPTER_TRIAL_DAYS`, `TIER_STANDARD_TRIAL_DAYS`, `LOGIN_APPROVAL_ENABLED`,
  `SIGNUP_BOT_GUARD_ENABLED`, `COUNTRY_ALLOW` and `COUNTRY_DENY`. A setting with exactly one possible provider must not
  be declared.
- `SPEC-7.1.88` `SMTP_FROM_EMAIL` and `SMTP_FROM_NAME` must both be carried by the variable `SMTP_FROM` and derived from it
  as in `SPEC-7.1.72`; every other key must be carried by the variable of the same name, verbatim.
- `SPEC-7.1.89` The section key lists must be: `EMAIL_KEYS` (the 13 email keys), `AUTO_BAN_KEYS` (the 4 auto-ban keys),
  `TIER_KEYS` (the 4 tier keys), `SYSTEM_SETTINGS_KEYS` (`LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED`,
  `COUNTRY_ALLOW`, `COUNTRY_DENY`) and `RATE_LIMIT_KEYS` (every generated rate-limit key).
- `SPEC-7.1.90` `GROUP_ONE_KEYS` must be `DATABASE_URL`, `APP_DATABASE_URL`, `BUNYIP_APP_PASSWORD`, `JWT_SECRET`,
  `APP_ENCRYPTION_KEY`, `APP_ENCRYPTION_KEY_PREV`, `APP_KEY_VERSION`, `BUNYIP_WEBHOOK_SIGNING_SECRET`,
  `SECRETS_STORAGE`, `INFISICAL_ADDRESS`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_PROJECT_ID` and
  `INFISICAL_ENVIRONMENT`, and `is_group_one(key)` must be true exactly for them.
- `SPEC-7.1.91` `EnvironmentProvider::get(key)` must return `None` for an undeclared key, and otherwise the value of the
  key's `source_var` passed through the key's derivation. An empty variable must be a value, not an absence, and the
  `{NAME}_FILE` indirection must not be consulted. `enumerate` must list the declared keys it holds.
- `SPEC-7.1.92` The file layer directory must be `BUNYIP_CONFIG_DIR` (trimmed, non-empty) and otherwise `/app/config`.
- `SPEC-7.1.93` `FileProvider::from_env` must return `None` (no file layer) when `BUNYIP_CONFIG_DIR` is unset, the default
  directory does not exist and no legacy YAML file exists. Otherwise it must first migrate the legacy file, then load the
  directory, and serve any value the migration could not write from memory for that boot without overriding a per-key
  file.
- `SPEC-7.1.94` `FileProvider::load` must read each regular file in the directory as one key: the trimmed contents are
  the value and an empty file is absent. A file named neither for a declared key nor for a declared `source_var` must be
  ignored with a `warn` naming the directory and file; the legacy YAML file and its migrated form must be skipped
  silently; subdirectories must be skipped.
- `SPEC-7.1.95` When the directory cannot be read, the file provider must log an `error` naming the directory and cause,
  hold no values, report the cause through `unreadable()`, and return `Unsupported` from `enumerate`, so it never reads
  as an empty layer. An unreadable entry or file must be logged at `error` and skipped.
- `SPEC-7.1.96` `FileProvider::get(key)` must prefer a file named for the key over one named for its `source_var`, apply
  the key's derivation, and treat an empty derived value as absent. `location()` must return the directory.
- `SPEC-7.1.97` `DatabaseProvider::set(key, value)` must return a `ConfigFailure` naming the key when the key is in
  `GROUP_ONE_KEYS` or is not a declared key, and must otherwise hold the value.
- `SPEC-7.1.98` `DatabaseProvider::set_opt` must hold nothing for `None`; `set_non_empty` must additionally hold nothing
  for an empty string; `is_empty` must be true exactly when nothing is held; `merge` must add another provider's keys,
  the other provider's value winning on a clash; `enumerate` must list the held keys.
- `SPEC-7.1.99` `ConfigStack::new` must sort the providers by priority regardless of the order given.
- `SPEC-7.1.100` `ConfigStack::environment_only` must hold only the environment provider. `ConfigStack::deployment` must
  hold the environment provider plus the file provider when `FileProvider::from_env` returns one, and no database
  provider.
- `SPEC-7.1.101` `ConfigStack::deployment_cached` must build the deployment stack once per process and return the same
  stack thereafter.
- `SPEC-7.1.102` `ConfigStack::with_database` and `database_over` must put the database provider on top of the deployment
  or given lower stack, sorted by priority so an already-present database provider cannot reorder the stack.
- `SPEC-7.1.103` `ConfigStack::get(key)` must return the value from the highest-priority provider that holds the key,
  `get_above(kind, key)` only from providers of strictly higher priority than `kind`, and `get_below(kind, key)` only from
  providers of strictly lower priority; `None` means the caller's built-in default stands.
- `SPEC-7.1.104` `ConfigStack::get_parsed` and `get_parsed_where` must trim and parse each provider's value in priority
  order. A value that fails to parse, or fails the validity rule, must be logged at `warn` with the key and the provider
  and then skipped so the next provider or the caller's default serves it.
- `SPEC-7.1.105` `ConfigStack::top` must return the highest-priority provider kind, `holders(key)` every provider that
  holds the key (highest first), and `serving_any(keys)` the highest-priority provider holding any of `keys`, or `None`.
- `SPEC-7.1.106` `ConfigStack::log_shadowed_providers` must log one `warn` per ignored provider for every declared key
  whose verdict is `Overridden`, naming the key, the serving provider, the ignored provider and the setting it
  configures; it must log nothing for `Use`, `Default` and `Shadowed`.
- `SPEC-7.1.107` `classify(top, holders)` must return: `Default` when there is no top provider or no holder;
  `Use(top)` when only the top provider holds the key; `Overridden { serving: top, ignored }` when the top provider and
  others hold it; `Shadowed { serving, absent_from: top, ignored }` when the top provider does not and a lower one does,
  where `serving` is the highest-priority holder and `ignored` the still-lower holders.
- `SPEC-7.1.108` `ConfigVerdict::serving` must return the supplying provider (`None` for `Default`), and `condition`
  must return `use`, `default`, `overridden` or `shadowed`.
- `SPEC-7.1.109` `status_report(stack)` must list every declared key with its `source_var`, its holders, its serving
  provider, its condition and an operator-facing note, plus the provider priority list, the file provider directory when
  the file provider is in the stack, and every provider that reports itself unreadable. It must not contain any
  configuration value and must not mutate any provider.
- `SPEC-7.1.110` The verdict note must state: for `Use`, that the provider holds it and no other does; for `Default`,
  that the built-in default configures the setting; for `Overridden`, which providers hold it and that their value is
  ignored today; for `Shadowed`, which provider does not hold it and that the lower-priority provider serves it, naming
  any still-lower ignored holders.
- `SPEC-7.1.111` `render_status(report)` must print the priority line, the `BUNYIP_CONFIG_DIR` line when a file directory
  exists, one `warning:` line per unreadable provider, and per key its source variable, holders (`(none)` when empty),
  serving provider (`(none: the built-in default)` when `None`), condition and note, and never a value.

#### System settings and the file layer

- `SPEC-7.1.112` The system-level environment variables (`CORS_ORIGIN`, `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`,
  `DATABASE_URL`, `APP_DATABASE_URL`, `BUNYIP_APP_PASSWORD`, `SECRETS_STORAGE`, the five `INFISICAL_*` connection keys,
  `JWT_SECRET`, `APP_ENCRYPTION_KEY`, `APP_ENCRYPTION_KEY_PREV` and `APP_KEY_VERSION`) must be read from the process
  environment only. None may be a key `SystemSettings::entries` writes or a declared configuration key the file layer
  could serve.
- `SPEC-7.1.113` `SystemSettings` must have exactly the fields `login_approval_enabled`, `signup_bot_guard_enabled`,
  `country_allow` and `country_deny`, and `entries()` must return exactly those four declared keys with the text to
  store; no other key may be written to the file layer.
- `SPEC-7.1.114` `SystemSettings::resolve(stack)` must read the effective values through the stack. A boolean setting
  must be true only for `true` (case-insensitive) or `1` after trimming; a country list must be split on commas and
  whitespace, trimmed, upper-cased, with blank entries dropped.
- `SPEC-7.1.115` The stored text of a boolean key must be `true` or `false`; the stored text of a country list must be
  the comma-joined normalized codes, and an empty list must be absent (`None`) so saving removes its file.
- `SPEC-7.1.116` `SystemSettings::save` must create the file layer directory, write one file per declared key
  containing the value and a trailing newline, and remove the file of a cleared key (a missing file is not an error). Any
  other I/O failure must be returned to the caller.
- `SPEC-7.1.117` Each key file must be written atomically: the value written to a sibling `.tmp` file and renamed over
  the target.
- `SPEC-7.1.118` A caller must hold `SAVE_LOCK` across the whole `SystemSettings::current()` to `save()` span of an admin
  system-config save and around every other `save()` (including the settings-archive restore), so overlapping saves
  cannot drop each other's changes. The lock is sufficient only for a single API process.
- `SPEC-7.1.119` `SysConfig::load` must resolve `cors_origin` (default `http://localhost:5173`), `web_origin` and
  `cookie_domain` from the environment layer only, trimmed with empty as unset, where the environment layer is the plain
  `{NAME}` variable when non-empty, else the trimmed non-empty contents of the file named by `{NAME}_FILE`; the four
  application-level settings come from the provider stack.
- `SPEC-7.1.120` An unreadable `{NAME}_FILE` path must be logged at `error` with the variable and cause and treated as
  absent.
- `SPEC-7.1.121` The legacy YAML file path must be `BUNYIP_CONFIG_FILE` (trimmed, non-empty), else `config.yaml` inside
  the file layer directory; `is_legacy_file_name` must be true for `config.yaml`, `config.yaml.migrated`, and the file
  name of `BUNYIP_CONFIG_FILE` with and without the `.migrated` suffix.
- `SPEC-7.1.122` `migrate_legacy_file(dir, legacy)` must do nothing when the legacy file does not exist, and must log an
  `error` and migrate nothing when it cannot be read or does not parse.
- `SPEC-7.1.123` For each legacy value (`features.login_approval_enabled`, `features.signup_bot_guard_enabled`,
  `country_access.allow`, `country_access.deny`, countries normalized as in `SPEC-7.1.114`) the migration must skip an
  absent value, drop with an `info` a key whose file already exists, and drop with a `warn` a key whose non-blank value
  the environment also holds, so a resolved value never changes. Otherwise it must write the key file.
- `SPEC-7.1.124` A value the migration cannot write must be logged at `error`, returned to the caller, and the legacy file
  must be left in place so the migration is retried on the next start.
- `SPEC-7.1.125` When every value was written or deliberately dropped, the migration must rename the legacy file to the
  same name plus `.migrated` and log it at `info`; a rename failure must be logged at `error` and must not fail the boot.
  The legacy file must never be deleted, and no code may write the legacy YAML format.

#### Feature registry

- `SPEC-7.1.126` The `Feature` registry must hold exactly `Pricing` (key `pricing`) and `TenantHostnames` (key
  `tenant_hostnames`) in that order in `ALL`; every key must be unique, lowercase snake_case and never renamed (a renamed
  key reads as a new, off feature).
- `SPEC-7.1.127` Each feature must have a non-empty admin `label` (`Pricing`, `Tenant Hostnames`) and `help`, and an
  `issue` identifier starting with `BUNYIP-` that is used only in code and logs, never in user-facing copy.
- `SPEC-7.1.128` `Feature::from_key` must return the matching variant or `None` for a key no variant has.
- `SPEC-7.1.129` `FeatureToggles::from_rows` must turn a feature on only when a row for its key has `enabled = true`; a
  feature with no row, or with `enabled = false`, must be off.
- `SPEC-7.1.130` A row whose key matches no `Feature` must be ignored and must log one `warn` naming the key, at most
  once per key per process.
- `SPEC-7.1.131` `FeatureToggles::as_map` must return every registered key with its state and no unregistered key;
  `FeatureToggles::default()` must have every feature off.
- `SPEC-7.1.132` No environment variable, declared configuration key or file-provider key may be named after a feature
  key, so no provider other than the `feature_toggles` rows can turn a feature on.

#### Device label

- `SPEC-7.1.133` `device_label(ua)` must return `None` when the user agent is absent, empty or whitespace only, or when
  neither a browser nor an OS is recognized.
- `SPEC-7.1.134` The browser must be the first match in this order: `Edge` (`Edg/` or `Edge/`), `Opera` (`OPR/` or
  `Opera`), `Firefox` (`Firefox/` or `FxiOS/`), `Chrome` (`Chrome/` or `CriOS/`), `Safari` (`Safari/`).
- `SPEC-7.1.135` The OS must be the first match in this order: `iOS` (`iPhone`, `iPad`, `iPod`), `Android`, `Windows`
  (`Windows NT` or `Windows`), `macOS` (`Mac OS X` or `Macintosh`), `ChromeOS` (`CrOS`), `Linux` (`Linux`).
- `SPEC-7.1.136` The label must be `"{browser} on {os}"` when both are known, the browser alone, or the OS alone.

#### Email templates

- `SPEC-7.1.137` Every transactional email must have an HTML template and a text template of the same base name under
  `templates/emails`, both extending `base.html` and `base.txt` respectively, and carrying the same links and the same
  stated facts.
- `SPEC-7.1.138` `base.html` and `base.txt` must render `app_name`, `year` and `base_url`, with footer links to
  `{base_url}/privacy` and `{base_url}/terms`; the HTML base must link the header to `base_url` and use fixed hex colors
  (mail clients cannot evaluate CSS variables).
- `SPEC-7.1.139` `magic_link` must render `magic_link_url` as the sign-in link and state that it expires in 15 minutes
  and works once.
- `SPEC-7.1.140` `password_reset` must render `reset_url`, state that it expires in 1 hour, and mention the request
  country only when `country` is non-empty.
- `SPEC-7.1.141` `email_verify` and `email_change_verify` must render `verify_url` and state that the link expires in 1
  hour; `email_change_verify` must also say that ignoring it leaves the account on its current address.
- `SPEC-7.1.142` `email_change_notification` must render `new_email` and `dashboard_url` and tell the recipient to reply
  to the email if they did not make the change.
- `SPEC-7.1.143` `password_changed` must render `dashboard_url` and tell the recipient to reply to the email if they did
  not make the change.
- `SPEC-7.1.144` `welcome` must render `price` and `dashboard_url`; `account_created` must render `dashboard_url` and
  `email_verified`, and mention verifying the email only when `email_verified` is false.
- `SPEC-7.1.145` `payment_succeeded` must render `amount` and `dashboard_url`; `payment_failed` must render
  `days_remaining` and `billing_url`; `grace_period_reminder` must render `days_remaining` and `billing_url` and show
  the access-suspension warning only when `days_remaining` is 7 or fewer.
- `SPEC-7.1.146` `membership_canceled` must render `end_date` and `resubscribe_url`.
- `SPEC-7.1.147` `new_login_location` must render `country`, `ip`, `when`, `user_agent` and `dashboard_url`;
  `login_approval` must render `location`, `code`, `ttl_minutes` and `dashboard_url`, and warn the recipient not to share
  the code.
- `SPEC-7.1.148` `admin_invite` must render `invite_url` and state that the invitation expires in 7 days.
- `SPEC-7.1.149` `admin_feedback_notification` must render `admin_url`; `feedback_response` must render `subject_line`,
  `original_message` and `response_message`; `support_reply` must render `response_message` preserving its line breaks.
- `SPEC-7.1.150` `smtp_test` must render `smtp_host` and `sent_at` and say it was sent by an administrator's test action.

#### Release metadata for environment variables

- `SPEC-7.1.151` `config/variables.toml` must hold exactly one `[[variable]]` record, with `name`, `since` (a `vX.Y.Z`
  release) and `required`, for every variable in the written environment inventory, and no record for any other name.
- `SPEC-7.1.152` A record's `required` must be true exactly when the inventory classifies the variable `Required` or
  `RequiredInProduction`.
- `SPEC-7.1.153` A variable the server no longer reads must move to a `[[removed]]` record keeping its original `since`,
  and a breaking change later than `since` must be a `[[change]]` record naming the operator action and the originating
  issue.

### 7.2 Domain models

The `models` module of the domain crate holds database row types, request and response DTOs, enums, constants and the
pure validation that goes with them. Row types derive `sqlx::FromRow`; response types derive `Serialize`; request types
derive `Deserialize`.

#### Module surface and shared-crate re-exports

- `SPEC-7.2.1` The `models` module must declare the public submodules `application`, `application_doc`,
  `application_group`, `audit`, `auto_ban`, `branding`, `download`, `email`, `entitlement`, `feedback`, `membership`,
  `mirzam`, `mokosh`, `oauth_client_user_tenant`, `rate_limit`, `stripe`, `support`, `tier`, `token`, `totp` and `user`,
  and must re-export their API types and constants so that `crate::models::<Name>` resolves for each of them.
- `SPEC-7.2.2` The `feedback` submodule must define no types of its own and must re-export every public item of the
  shared feedback crate's `models` module, so `crate::models::feedback::*` and `crate::models::*` paths are the same
  across the domain crate and the API crate.
- `SPEC-7.2.3` The `download` submodule must re-export `ArtifactSource`, `DownloadCacheRow`, `NewCachedAsset`,
  `ReleaseAsset` and `ReleaseMetadata` from the shared download engine, so callers keep using
  `crate::models::download::*`.
- `SPEC-7.2.4` The `stripe` submodule must re-export `StripeCheckoutPrice`, `StripeInvoiceResponse`,
  `StripePriceResponse`, `StripeProductResponse`, `StripeSubscriptionItemResponse`, `StripeSubscriptionResponse` and
  `StripeWebhookEndpointResponse` from the shared Stripe crate, and must keep `StripeConfig`, the secret encryption
  helpers and `StripeConfigResponse` local.
- `SPEC-7.2.5` The `user` submodule must re-export `UserRole` and `MembershipStatus` from the shared user crate and
  must expose that crate's `SubscriptionTier` under the name `MembershipTier`, so the string values and the
  tier-selection boundary are the ones shared with the other consumer of that crate.
- `SPEC-7.2.6` The `tier` submodule must re-export `TierConfigResponse` from the shared user crate and must keep
  `TierConfigRow` local, because the row derives `sqlx::FromRow`.

#### Applications

- `SPEC-7.2.7` The `Application` row must carry the columns `id`, `name`, `slug`, `display_name`, `description`,
  `icon_url`, `is_active`, `is_hosted`, `requires_entitlement`, `maintenance_mode`, `maintenance_message`, `subdomain`,
  `container_name`, `health_check_url`, `webhook_url`, `version`, `source_code_url`, `release_notes_url`,
  `forgejo_owner`, `forgejo_repo`, `pinned_release_tag`, `artifact_source`, `forgejo_package`, `oci_image_owner`,
  `oci_image_name`, `pinned_image_tag`, `sort_order`, `group_id`, `created_at` and `updated_at`; `artifact_source` is a
  non-null string and `group_id` is a nullable reference to an application group.
- `SPEC-7.2.8` The constants `ARTIFACT_SOURCE_RELEASE` and `ARTIFACT_SOURCE_GENERIC_PACKAGE` must equal `"release"` and
  `"generic_package"`; these are the only two values an application's `artifact_source` may hold.
- `SPEC-7.2.9` `Application::valid_artifact_source(value)` must return true only when `value` is exactly `"release"` or
  exactly `"generic_package"` (case-sensitive, no trimming, empty string rejected).
- `SPEC-7.2.10` `Application::entitlement_satisfied(is_admin, is_entitled)` must return true when
  `requires_entitlement` is false, or `is_admin` is true, or `is_entitled` is true, and false otherwise. It is the one
  definition of the per-product access decision used by the OCI, download and web gates.
- `SPEC-7.2.11` `Application::download_source()` must return `None` when `pinned_release_tag` is unset; otherwise it must
  return the result of `download_source_for(pinned_release_tag)`.
- `SPEC-7.2.12` `Application::download_source_for(version)` must return `None` when `forgejo_owner` is unset.
- `SPEC-7.2.13` For `artifact_source = "release"`, `download_source_for(version)` must return
  `ArtifactSource::Release { owner: forgejo_owner, repo: forgejo_repo, tag: version }` and must return `None` when
  `forgejo_repo` is unset.
- `SPEC-7.2.14` For `artifact_source = "generic_package"`, `download_source_for(version)` must return
  `ArtifactSource::GenericPackage { owner: forgejo_owner, package, version }` where `package` is `forgejo_package`
  when set and otherwise `forgejo_repo`, and must return `None` when both are unset.
- `SPEC-7.2.15` For any other `artifact_source` value, `download_source_for` must return `None` and must emit a `warn`
  log carrying the application `slug` and the offending `artifact_source`; it must not fall back to the release source.
- `SPEC-7.2.16` `download_source_for` must perform no check that `version` is a recorded version; callers must gate the
  version against the version-history allow-list before serving it.
- `SPEC-7.2.17` `Application::is_downloadable()` must be true exactly when `download_source()` returns `Some`.
- `SPEC-7.2.18` `Application::is_pullable()` must be true only when `is_active` is true and `oci_image_owner`,
  `oci_image_name` and `pinned_image_tag` are all set.
- `SPEC-7.2.19` `Application::oci_pull_image(registry_host)` must return `None` when the application is not pullable;
  otherwise it must return `AppOciImage` with `registry = registry_host`, `repository = slug` (not `oci_image_name`),
  `tag = pinned_image_tag` and `reference = "{registry_host}/{slug}:{tag}"`. It is the single place that builds a pull
  reference, because the registry resolves repositories by application slug.
- `SPEC-7.2.20` `ApplicationResponse::from_application(app, has_access)` must set `is_accessible` to
  `has_access && app.is_active && !app.maintenance_mode`.
- `SPEC-7.2.21` `ApplicationResponse::from_application` must carry `maintenance_message` only when `maintenance_mode` is
  true and must set it to `None` otherwise, even when a stale message is stored.
- `SPEC-7.2.22` `ApplicationResponse` must expose only `id`, `slug`, `display_name`, `description`, `icon_url`,
  `version`, `source_code_url`, `release_notes_url`, `subdomain`, `is_accessible`, `maintenance_mode`,
  `maintenance_message` and `group_id`, copied unchanged from the application; it must not expose the container name,
  health-check URL, webhook URL, Forgejo or OCI coordinates, `artifact_source`, `is_active`, `is_hosted`,
  `requires_entitlement` or `sort_order`.
- `SPEC-7.2.23` `DistributionConfig::validate()` must return `Err((field, message))` for the first rule that fails, in
  this order, and `Ok(())` when none fails: (1) empty or whitespace-only value, (2) unknown `artifact_source`,
  (3) `forgejo_package` on a non-generic source, (4) incomplete Forgejo group, (5) incomplete OCI group.
- `SPEC-7.2.24` `DistributionConfig::validate()` must reject any of `artifact_source`, `forgejo_owner`, `forgejo_repo`,
  `forgejo_package`, `pinned_release_tag`, `oci_image_owner`, `oci_image_name` and `pinned_image_tag` that is `Some` of an
  empty or whitespace-only string, checking the fields in that order, with the field name as the error field and the
  message `"{field} must not be empty; omit the field or send null"`.
- `SPEC-7.2.25` `DistributionConfig::validate()` must reject a set `artifact_source` that is not a valid source with
  field `artifact_source` and message `"artifact_source must be 'release' or 'generic_package'"`.
- `SPEC-7.2.26` `DistributionConfig::validate()` must reject a set `forgejo_package` unless `artifact_source` is
  `generic_package` (an omitted source counts as not generic), with field `forgejo_package` and message
  `"forgejo_package requires artifact_source = 'generic_package'"`.
- `SPEC-7.2.27` When any of `forgejo_owner`, `forgejo_repo`, `forgejo_package` or `pinned_release_tag` is set,
  `DistributionConfig::validate()` must require, for a release source, `forgejo_owner`, `forgejo_repo` and
  `pinned_release_tag`, and for a generic-package source, `forgejo_owner`, `pinned_release_tag` and one of
  `forgejo_package` or `forgejo_repo`; otherwise it must fail with field `forgejo` and the message that names the
  required set for that source type.
- `SPEC-7.2.28` When any of `oci_image_owner`, `oci_image_name` or `pinned_image_tag` is set,
  `DistributionConfig::validate()` must require all three, otherwise fail with field `oci` and message
  `"oci_image_owner, oci_image_name, and pinned_image_tag must all be set together"`. A configuration with no
  distribution field set must validate.
- `SPEC-7.2.29` `CreateApplication::distribution()` must map the request's eight distribution fields one-to-one into a
  `DistributionConfig` borrowing from the request, so create and update handlers validate through the same rules.
- `SPEC-7.2.30` `UpdateApplication::distribution_merged(old)` must set `artifact_source` to the request value when
  present and otherwise to `old.artifact_source` (always `Some`), and must set every other distribution field to the
  request value when present and otherwise to the stored value.
- `SPEC-7.2.31` In `UpdateApplication::distribution_merged`, a request `forgejo_package` of the empty string must be
  treated as cleared (`None`) and must not fall back to the stored value; any other request value must be used as given
  and an omitted or null value must keep the stored one. An empty string in any other merged field must be kept as
  `Some("")` so that `validate()` rejects it.
- `SPEC-7.2.32` `CreateApplication` must require `name`, `slug`, `display_name` and `container_name`, and must treat
  `description`, `icon_url`, `health_check_url`, `subdomain`, `webhook_url`, `version`, `source_code_url`,
  `release_notes_url`, `is_hosted`, `maintenance_message`, the Forgejo and OCI coordinates and `artifact_source` as
  optional; an omitted `is_hosted` or `artifact_source` means the column default (hosted, `release`).
- `SPEC-7.2.33` `UpdateApplication` must treat every field as optional, where an omitted or null value keeps the stored
  value, with the single exception that `forgejo_package` set to `""` clears it back to NULL.
- `SPEC-7.2.34` `DeleteApplicationRequest` must require both `password` and `totp_code` as strings; a body missing
  either must fail deserialization.
- `SPEC-7.2.35` `ReorderApplicationsRequest` must deserialize from `{"ordered_ids": [<uuid>, ...]}` where `ordered_ids`
  is the full list of application ids in the new display order; a body without `ordered_ids` must fail
  deserialization.

#### Application documentation and groups

- `SPEC-7.2.36` `ApplicationDoc` must carry `id`, `application_id`, `slug`, `title`, `body` (markdown), `sort_order`,
  `created_at` and `updated_at`; `ApplicationDocSummary` must carry only `slug`, `title` and `sort_order`, with no body.
- `SPEC-7.2.37` `DocumentedApplication` must carry only `slug` and `display_name`, and is the shape of an active
  application that has at least one documentation page, sourced from the docs side rather than the application catalog.
- `SPEC-7.2.38` `CreateApplicationDoc` must require `slug`, `title` and `body`, and must default `sort_order` to `0` when
  omitted.
- `SPEC-7.2.39` `UpdateApplicationDoc` must treat `slug`, `title`, `body` and `sort_order` as optional, each omitted
  field meaning "leave unchanged".
- `SPEC-7.2.40` `ApplicationGroup` must carry `id`, `name`, `slug`, `display_name`, `description`, `icon_url`,
  `sort_order`, `created_at` and `updated_at`; an application belongs to at most one group through the nullable
  `applications.group_id`.
- `SPEC-7.2.41` `CreateApplicationGroup` must require `name`, `slug` and `display_name` and treat `description`,
  `icon_url` and `sort_order` as optional; `UpdateApplicationGroup` must treat every field as optional, where `None`
  leaves the stored column unchanged.
- `SPEC-7.2.42` `SetApplicationGroupRequest.group_id` must default to `None` when omitted, and `None` (null or omitted)
  must mean "remove the application from its group".

#### Entitlements and membership

- `SPEC-7.2.43` The `entitlement_source` constants must equal `"admin"`, `"stripe"`, `"backfill"` and `"seed"`, and
  these are the only values an entitlement's `source` may hold (the `application_entitlements_source_check`
  constraint); provenance exists so a Stripe-driven revoke does not clobber an admin grant and the reverse.
- `SPEC-7.2.44` `ApplicationEntitlement` must carry `user_id`, `application_id`, `granted_at`, `granted_by`, `source` and
  `revoked_at`; a revoked grant is retained with `revoked_at` set rather than deleted.
- `SPEC-7.2.45` `UserEntitlementRow` must carry `application_id`, `slug`, `display_name`, `requires_entitlement`,
  `granted_at` and `source`, the join of an entitlement with its product's display fields.
- `SPEC-7.2.46` `MembershipResponse` must carry exactly `status`, `price_locked`, `locked_price_amount`,
  `current_period_end`, `cancel_at_period_end` and `grace_period_end`.
- `SPEC-7.2.47` `AdminMembershipResponse` must carry `user_id`, `user_email`, `stripe_customer_id`, `status`,
  `membership_tier`, `membership_override_by` and `created_at`.

#### OAuth client user-tenant assignments

- `SPEC-7.2.48` `OAuthClientUserTenant` must carry `id`, `oauth_client_id`, `user_id`, `tenant_id`, `role`, `created_at`
  and `created_by`; `tenant_id` is an opaque UUID that bunyip does not interpret, and `role` is relying-party-defined
  free text that bunyip does not interpret.
- `SPEC-7.2.49` `CreateUserTenantAssignment` (the body of `POST /v1/admin/oauth-clients/{client_id}/user-tenants`) must
  require `user_id` and `tenant_id` as UUIDs and treat `role` as optional, defaulting to `None`.

#### Configuration singleton rows and responses

- `SPEC-7.2.50` In `AutoBanConfigRow` and `EmailConfigRow`, every tunable column must be nullable, and a NULL must mean
  that the row's provider does not hold that key so the next configuration provider serves it.
- `SPEC-7.2.51` `AutoBanConfigResponse` must carry resolved (non-null) `enabled`, `threshold`, `window_secs` and
  `ban_duration_secs`, a `source` of `"database"` or `"environment"`, `updated_at` and `updated_by`.
- `SPEC-7.2.52` `EmailConfigRow` must store the SMTP password and the IMAP password each as ciphertext plus nonce, both
  versioned by the single `key_version` column.
- `SPEC-7.2.53` `EmailConfigResponse` must never contain either password or any masked or truncated form of it; it must
  expose only the booleans `has_smtp_password` and `has_imap_password`.
- `SPEC-7.2.54` `EmailConfigResponse` must carry the resolved SMTP settings (`enabled`, `smtp_host`, `smtp_port`,
  `smtp_tls` as `"implicit"` or `"starttls"`, `smtp_username`, `from_email`, `from_name`,
  `admin_notification_emails` as a list), the IMAP settings (`imap_host`, `imap_port`, `imap_username`, `imap_mailbox`,
  `imap_enabled`), `source` (`"database"` or `"environment"`), `secrets_storage` (`"environment"`, `"database"` or
  `"infisical"`), `smtp_password_editable`, `imap_password_editable`, `updated_at` and `updated_by`.
- `SPEC-7.2.55` The wire key `secrets_storage` in `EmailConfigResponse`, `MirzamConfigResponse`, `MokoshConfigResponse`
  and `StripeConfigResponse` must keep that exact name, matching the `SECRETS_STORAGE` variable it reports.
- `SPEC-7.2.56` The `*_editable` flags must be false when the declared secrets provider is `environment` (the one
  read-only provider), so the admin form is read-only instead of accepting a save that lands nowhere.
- `SPEC-7.2.57` `TierConfigRow` must carry nullable `lifetime_slots`, `early_adopter_slots`, `early_adopter_trial_days`,
  `standard_trial_days`, the six nullable Stripe price and product id columns, and the non-null booleans
  `pricing_enabled` (default false), `lifetime_visible`, `early_adopter_visible`, `standard_visible` (each default true)
  and `orgs_enabled` (default false); the non-null booleans have no environment fallback.
- `SPEC-7.2.58` `TierConfigWithPricing` must serialize as the shared `TierConfigResponse` flattened to the top level,
  followed by `pricing_enabled`, `lifetime_visible`, `early_adopter_visible`, `standard_visible` and `orgs_enabled`, so
  the wire shape is the shared one with those fields appended.
- `SPEC-7.2.59` `DownloadAsset` must carry `asset_name`, `size_bytes`, `content_type` and `download_url`.
- `SPEC-7.2.60` `AppDownloadsResponse` (response of `GET /v1/applications/{slug}/downloads`) must serialize the version
  under the JSON key `release_tag` (not `version`), carrying the package version for generic-package sources, as
  `Option<String>` plus the `assets` list.
- `SPEC-7.2.61` `AppOciImage` must carry `registry`, `repository`, `tag` and `reference`, where `reference` is
  `{registry}/{repository}:{tag}`.
- `SPEC-7.2.62` `AppDownloadGroup.release_tag` must be a plain string that is the empty string (never null) for a product
  with only an OCI image, so deployed web clients that require a string keep parsing the whole response.
- `SPEC-7.2.63` An `AppDownloadGroup` for a restricted product the caller is not entitled to must have
  `has_access = false`, `oci = None` and an empty `assets` list, so download coordinates never reach a caller without
  access; such a group may be emitted only when `has_docs` is true.
- `SPEC-7.2.64` `AppDownloadGroup` must carry `app_slug`, `app_display_name`, `icon_url`, `release_tag`, `assets`, `oci`,
  `has_docs` and `has_access`.

#### TOTP models

- `SPEC-7.2.65` `UserTotp` must store the TOTP secret only as `encrypted_secret` plus `nonce` with `key_version`, never
  as plaintext.
- `SPEC-7.2.66` `UserTotp` must carry the staged re-key columns `pending_encrypted_secret`, `pending_nonce`,
  `pending_key_version` and `pending_created_at`, all NULL unless an authenticator reset is in progress, so the active
  secret keeps working until the staged one is confirmed.
- `SPEC-7.2.67` `UserTotp.last_used_step` must be NULL until the first successful verification and then hold the highest
  consumed TOTP step for that user; a code whose step is at or below it must be refused as a replay.
- `SPEC-7.2.68` `UserTotp` must carry `setup_token_hash` (hex SHA-256 of the one-time setup token) and
  `setup_token_expires_at`, both NULL when no setup is in progress.
- `SPEC-7.2.69` `RecoveryCode` must store only `code_hash` (never the code), with `used_at` NULL until the code is
  consumed.

#### Audit log and admin notifications

- `SPEC-7.2.70` `AuditAction` must serialize in `snake_case`, and `AuditAction::as_str()` must return exactly that
  snake_case spelling of the variant name for every variant (for example `UserLogin` is `"user_login"` and
  `OauthUserTenantAssigned` is `"oauth_user_tenant_assigned"`); two variants must never share a string.
- `SPEC-7.2.71` `AuditAction::is_admin_action()` must be true for every variant whose name begins with `Admin`, and for
  `ApplicationMaintenanceToggled`, `ApplicationCreated`, `ApplicationDeleted`, `ApplicationUpdated`, `FeedbackResponded`,
  `FeedbackDeleted`, `FeedbackRestored`, `FeedbackMarkedSpam`, `FeedbackUnmarkedSpam`, `FeedbackArchived`,
  `OauthUserTenantAssigned`, `OauthUserTenantUnassigned`, `AccountBackupCreated`, `AccountRestored` and
  `SystemConfigUpdated`, and false for every other variant.
- `SPEC-7.2.72` The download and OCI audit actions (`DownloadRequested`, `DownloadCompleted`, `DownloadDenied*`,
  `DownloadFailedUpstream`, `OciLoginSucceeded`, `OciLoginFailed`, `OciPull*`) and `AuthRefreshReuseDetected` must not be
  classified as admin actions.
- `SPEC-7.2.73` `AuditSeverity` must have the variants `Info`, `Warning`, `Error` and `Critical`, serialize in
  `snake_case`, default to `Info`, and `as_str()` must return `"info"`, `"warning"`, `"error"` and `"critical"`.
- `SPEC-7.2.74` `AuditSeverity::parse(raw)` must trim `raw`, compare case-insensitively against the four lowercase
  spellings, and return `None` for any other input; `AuditSeverity::ALL` must list the four variants in the order
  info, warning, error, critical.
- `SPEC-7.2.75` `CreateAuditLog::new(action)` must produce an entry with every actor, resource, old/new value and
  metadata field unset and severity `Info`; the builder methods `with_actor`, `with_ip`, `with_resource`,
  `with_old_values`, `with_new_values`, `with_metadata` and `with_severity` must each set only their own fields, and
  `with_actor` must set actor id, email and role together.
- `SPEC-7.2.76` An `AuditLog` row must carry `actor_id`, `actor_email`, `actor_role`, `actor_ip_address`, `action` (the
  `as_str` spelling), `resource_type`, `resource_id`, `old_values`, `new_values`, `metadata`, `is_admin_action`,
  `severity` and `created_at`; the actor and resource fields are nullable so system-originated events can be recorded.
- `SPEC-7.2.77` Audit metadata for the following actions must never contain secrets or raw credentials:
  `AdminEmailConnectionTested` (no password), `AdminTestEmailSent` (no recipient address), `AdminMirzamConfigUpdated`
  (no token), `AdminMokoshConfigUpdated` (no secret; only the client id, whether the secret changed and the SHA-256 of a
  changed secret), `AccountBackupCreated` and `AccountRestored` (no PII).
- `SPEC-7.2.78` `NotificationType::as_str()` must return `"new_signup"`, `"payment_failed"`, `"membership_canceled"`,
  `"grace_period_expiring"`, `"system_alert"` and `"new_feedback"` for the six variants, which also serialize in
  `snake_case`.
- `SPEC-7.2.79` `AdminNotification` must map its `notification_type` field to the database column named `type`, and must
  carry `title`, `message`, `metadata`, `user_id`, `is_read`, `read_by`, `read_at` and `created_at`.

#### Branding

- `SPEC-7.2.80` `Branding.brand_name` must be the row value when non-empty after trimming and otherwise the bootstrap
  application name; `tagline`, `meta_description`, `og_image_url`, `newsletter_url`, `theme_css`, `theme_color_light`
  and `theme_color_dark` must be the trimmed row value or the empty string, and an empty value must mean the markup is
  omitted; no literal default may ever be substituted.
- `SPEC-7.2.81` `Branding.mark_version`, `favicon_version` and `mascot_version` must be the slot's `*_updated_at`
  timestamp as decimal milliseconds since the Unix epoch, or the empty string when the slot is unset; an empty version
  must mean "no uploaded asset" so readers fall back to the committed file or render nothing.
- `SPEC-7.2.82` `UpdateBrandingRequest` must default every field to the empty string when omitted, and every field must
  be a full replacement (not a COALESCE), so that clearing a field to empty is distinguishable from leaving it.
- `SPEC-7.2.83` `validate_branding` must trim every field and return the trimmed values to persist, or a
  `BrandingFieldError { field, message }` for the first failing check, in this order: `brand_name`, `tagline`,
  `meta_description`, `og_image_url`, `newsletter_url`, `theme_css`, `theme_color_light`, `theme_color_dark`.
- `SPEC-7.2.84` `validate_branding` must enforce these maximum lengths counted in characters after trimming:
  `brand_name` 120, `tagline` 200, `meta_description` 320, `og_image_url` 2048, `newsletter_url` 2048, `theme_css`
  4096, with message `"{label} must be {max} characters or fewer."` where the labels are `Brand name`, `Tagline`,
  `Meta description`, `Open Graph image URL`, `Newsletter signup URL` and `Theme CSS`.
- `SPEC-7.2.85` `validate_branding` must reject a non-empty `og_image_url` and a non-empty `newsletter_url` that does not
  start with `https://` or `http://`, with field `og_image_url` or `newsletter_url` respectively; an empty value must
  pass.
- `SPEC-7.2.86` `validate_branding` must reject `theme_css` that contains `<` or `>` with field `theme_css`, because the
  value is emitted verbatim inside a `<style>` element.
- `SPEC-7.2.87` `validate_branding` must reject a non-empty `theme_color_light` or `theme_color_dark` that is not a `#`
  followed by 3, 4, 6 or 8 ASCII hex digits, with the message `"{label} must be a hex colour such as #2f4e2e, or blank
  to omit the meta tag."` where the labels are `Light theme colour` and `Dark theme colour`; an empty value must pass.
- `SPEC-7.2.88` `validate_branding` must report a rejected save as a returned `BrandingFieldError` (field plus the
  message the admin form renders) and must not panic, so the caller can answer one 4xx and never a 5xx.
- `SPEC-7.2.89` `BrandingAssetSlot` must have the variants `Mark`, `Favicon` and `Mascot`; `as_str()` must return
  `"mark"`, `"favicon"` and `"mascot"`, `parse` must accept exactly those three lowercase strings and return `None` for
  anything else, and `version_column()` must return `mark_updated_at`, `favicon_updated_at` and `mascot_updated_at`.
- `SPEC-7.2.90` `BrandingAssetSlot::storage_kinds()` must return every storage key the slot owns: for `Mark`,
  `mark-source` and `mark`; for `Mascot`, `mascot-source` plus the kinds in `DERIVED_MASCOTS`; for `Favicon`,
  `favicon-source` plus the kinds in `DERIVED_FAVICONS`; clearing a slot must delete all of them so a derived image never
  outlives its source.
- `SPEC-7.2.91` `DERIVED_FAVICONS` must be exactly: `favicon-16` (16 px), `favicon-32` (32), `favicon-48` (48),
  `favicon-192` (192), `favicon-512` (512), `apple-touch-icon` (180), all `image/png`, and `favicon-ico` (48,
  `image/x-icon`).
- `SPEC-7.2.92` `DERIVED_MASCOTS` must be exactly `mascot` (long edge 448) and `mascot-2x` (long edge 896), the short edge
  following the source aspect ratio; `MARK_DERIVED_SIZE` must be 64 (pixels, square); the source storage keys must be
  `favicon-source`, `mark-source` and `mascot-source`.
- `SPEC-7.2.93` `is_servable_asset_kind(kind)` must return true only for `mark`, `mark-source`, `mascot-source`, the
  `DERIVED_MASCOTS` kinds, `favicon-source` and the `DERIVED_FAVICONS` kinds, so `GET /v1/branding/assets/{kind}`
  answers 404 for any other key before running a query.
- `SPEC-7.2.94` `BrandingCache::new(fallback)` must start with a `Branding` whose `brand_name` is the fallback and every
  other field empty; `store(row)` must resolve the row, replace the cached value, and return it; `get()` must return the
  current value; `brand_name()` must return the current resolved name.
- `SPEC-7.2.95` `BrandingCache` must recover from a poisoned lock by using the inner value instead of panicking, since
  the cached data is structurally intact.
- `SPEC-7.2.96` `BrandingResponse` must serialize the `Branding` fields flattened at the top level followed by
  `updated_at` and `updated_by`.
- `SPEC-7.2.97` `BrandingRow` must keep the `mark_updated_at`, `favicon_updated_at` and `mascot_updated_at` markers on the
  singleton row so the hot `GET /v1/branding` path learns which slots are filled without reading image bytes.

#### Mirzam integration settings

- `SPEC-7.2.98` `MirzamConfigRow::settings_complete()` must be true only when `base_url`, `updates_list` and
  `notices_list` are each non-empty after trimming.
- `SPEC-7.2.99` `MirzamConfigRow::db_api_token(key_set)` must return `None` when the ciphertext or nonce column is NULL,
  must return the decrypted token on success, and on decryption failure must log at `error` the cause and the
  `key_version` (never the token) and return `None` so a stale row does not block boot.
- `SPEC-7.2.100` `UpdateMirzamConfigRequest` (the body of `PUT /v1/admin/mirzam`) must default `enabled` to false and the
  three string settings to empty when omitted, replace the four settings whole, and leave the stored token unchanged
  when `api_token` is absent or empty.
- `SPEC-7.2.101` `MirzamConfigResponse` must never carry the API token; it must carry `has_api_token`,
  `api_token_editable`, `secrets_storage`, `last_error` and `last_error_at` (both `None` once a later sync call
  succeeded) alongside the four settings, `updated_at` and `updated_by`.
- `SPEC-7.2.102` `validate_mirzam_settings(enabled, base_url, updates_list, notices_list)` must trim all three strings,
  strip trailing `/` characters from `base_url`, and return the normalised `MirzamSettings` or a
  `MirzamFieldError { field, message }`.
- `SPEC-7.2.103` `validate_mirzam_settings` must reject an empty `base_url` when `enabled` is true with field `base_url`
  and message `"Enter the Mirzam site address before switching the integration on."`, and must accept it when `enabled`
  is false.
- `SPEC-7.2.104` For a non-empty `base_url`, `validate_mirzam_settings` must reject: a length over 2048 bytes; a value
  that does not parse as an absolute URL; a scheme other than `http` or `https` or a missing host; and a URL with a
  username, password, query or fragment; each with field `base_url`.
- `SPEC-7.2.105` `valid_list_slug(slug)` must be true only for a non-empty string of at most 64 bytes made of one or more
  non-empty words of ASCII lowercase letters and digits joined by single `-` characters (no leading, trailing or doubled
  dash).
- `SPEC-7.2.106` `validate_mirzam_settings` must, for each of `updates_list` and `notices_list`, reject an empty slug when
  `enabled` is true, accept it when `enabled` is false, and reject a non-empty slug for which `valid_list_slug` is false,
  with the field named for the setting.
- `SPEC-7.2.107` `validate_mirzam_settings` must reject a non-empty `updates_list` equal to `notices_list` with field
  `notices_list` and message `"Must be a different list from the product-updates list."`.

#### Mokosh host settings

- `SPEC-7.2.108` `MokoshConfigRow::db_google_client_secret(key_set)` must return `None` when the ciphertext or nonce is
  NULL, the decrypted secret on success, and on decryption failure must log at `error` the cause and `key_version`
  (never the secret) and return `None`.
- `SPEC-7.2.109` `UpdateMokoshConfigRequest` (the body of `PUT /v1/admin/mokosh`) must default `google_client_id` to the
  empty string, `google_client_secret` to `None` and `confirm_client_id_change` to false; an absent or empty secret must
  leave the stored secret unchanged, and a changed client id without `confirm_client_id_change = true` must be refused.
- `SPEC-7.2.110` `MokoshConfigResponse` must never carry the client secret; it must carry `google_client_id`,
  `has_google_client_secret`, `google_client_secret_editable`, `secrets_storage`, `updated_at` and `updated_by`.
- `SPEC-7.2.111` `validate_google_client_id(raw)` must trim `raw`, return the empty string for an empty input (unsetting
  the id), reject a length over 256 bytes, and otherwise accept only `<digits>-<token>.apps.googleusercontent.com`
  where digits are one or more ASCII digits and token is one or more ASCII lowercase letters or digits; any other value
  must fail with field `google_client_id`.
- `SPEC-7.2.112` `validate_google_client_secret(raw)` must trim `raw`, reject an empty result with message
  `"must not be empty"`, reject a length over 1024 bytes, and impose no other shape rule; failures use field
  `google_client_secret`.

#### Stripe configuration

- `SPEC-7.2.113` `StripeConfig` must store the Stripe secret key and the webhook secret each as ciphertext plus nonce
  versioned by `key_version`, with nullable `app_tag`, `success_url`, `cancel_url` and `trial_period_days`.
- `SPEC-7.2.114` `encrypt_secret(key_set, plaintext)` must encrypt the UTF-8 bytes with the current key and return
  `(ciphertext, nonce, key_version)` with a fresh nonce per call; `decrypt_secret` must decrypt with the key set
  (including previous keys), return the plaintext, and return an internal error when decryption fails or the plaintext is
  not valid UTF-8.
- `SPEC-7.2.115` `mask_secret(s)` must return `"***"` when `s` is 4 bytes or fewer; otherwise it must return the text up
  to and including the last `_`, then `***`, then the last 4 characters, and when there is no `_` or fewer than 4
  characters follow it, it must return `***` followed by the last 4 characters.
- `SPEC-7.2.116` `StripeConfigResponse` must expose the secret key and webhook secret only as `mask_secret` hints plus
  `has_secret_key` and `has_webhook_secret`, never in full.
- `SPEC-7.2.117` `StripeConfigResponse::from_provider(config, provider, secret_key, webhook_secret)` must compute the
  masked hints and `has_*` flags from the secret values as the declared provider holds them, not from the database
  columns; `source` must be the provider name when at least one secret is present and `"unconfigured"` otherwise;
  `secrets_storage` must be the provider name and `secrets_editable` must be whether that provider is writable.
- `SPEC-7.2.118` `StripeConfigResponse` must resolve `app_tag`, `success_url`, `cancel_url` and `trial_period_days` to
  the stored value when present and otherwise to the derived default (`bunyip`, the default checkout URLs, the
  environment trial length).
- `SPEC-7.2.119` `StripeConfigResponse::from_db(config, key_set)` must decrypt the row's own ciphertext columns, return an
  error if either decryption fails, and report `source = "database"`, `secrets_storage = "database"` and
  `secrets_editable = true`.
- `SPEC-7.2.120` `StripeConfigResponse::unconfigured(provider)` must report no secrets, `updated_at = None`,
  `source = "unconfigured"`, and the derived defaults for the non-secret fields.

#### Rate limit models

- `SPEC-7.2.121` `RateLimit` must carry `id`, `key`, `action`, `count` and `window_start`.
- `SPEC-7.2.122` `RateLimit::active_retry_after(config, now)` must return `Some(seconds)` only when
  `now < window_start + config.window_seconds` and `count >= config.max_requests`, where `seconds` is the whole seconds
  remaining until the window ends, floored at 0; otherwise it must return `None`.
- `SPEC-7.2.123` `RateLimitConfig` must carry `action`, `max_requests`, `window_seconds` and `key_kind`, and the
  built-in presets must have exactly these values (action: cap per window seconds, key kind): `login` 10 per 60 (email);
  `magic_link` 3 per 600 (email); `password_reset` 3 per 3600 (email); `api_auth` 100 per 60 (user id); `api_unauth` 60
  per 60 (IP); `registration` 10 per 3600 (IP); `oci_token_failures` 5 per 60 (email); `oci_token_throughput` 60 per 60
  (email); `two_factor_verify_failures` 5 per 900 (two-factor user id); `oci_token_ip_failures` 20 per 60 (IP);
  `oauth_token` 60 per 60 (IP); `oauth_authorize` 120 per 60 (IP); `oauth_userinfo` 240 per 60 (IP); `oauth_revoke` 60
  per 60 (IP); `oauth_discovery` 120 per 60 (IP); `feedback_submit` 20 per 3600 (IP); `smtp_test` 6 per 300 (user id);
  `mailer_send` 60 per 60 (client id); `mailer_auth_failures` 10 per 60 (IP); `host_secret_read` 30 per 60 (client id);
  `host_secret_auth_failures` 10 per 60 (IP); `host_config_read` 30 per 60 (client id); `host_config_auth_failures` 10
  per 60 (IP); `admin_diagnostics` 60 per 60 (user id).
- `SPEC-7.2.124` `RateLimitConfig::ALL` must list every preset, each action string must be unique, and a preset added as
  a constant must be added to `ALL` in the same change.
- `SPEC-7.2.125` `TWO_FACTOR_KEY_PREFIX` must equal `"2fa_verify_user:"`, and the per-account 2FA failure counter key must
  be that prefix followed by the user id.
- `SPEC-7.2.126` `RateLimitConfig::by_action(action)` must return `None` for an action with no preset and otherwise the
  preset with the deployment providers (file, then environment) already applied.
- `SPEC-7.2.127` `RateLimitConfig::resolve(stack)` must take the cap from `RATE_LIMIT_{ACTION}_MAX_REQUESTS` and the
  window from `RATE_LIMIT_{ACTION}_WINDOW_SECONDS` through the configuration stack in the declared provider order, each
  independently; a held value that does not parse (`i32` for the cap, `i64` for the window) or is not greater than zero
  must be skipped in favour of the next provider, and the built-in preset must stand when no provider holds a usable
  value.
- `SPEC-7.2.128` `RateLimitConfig::env_var_names(action)` must return `RATE_LIMIT_{ACTION}_MAX_REQUESTS` and
  `RATE_LIMIT_{ACTION}_WINDOW_SECONDS` with `ACTION` the upper-cased action; `rate_limit_vars()` must generate one
  `RateLimitVars` per preset from those names once per process, so the operator-facing variable name, the config-status
  key and the inventory entry cannot disagree.
- `SPEC-7.2.129` `RateLimitConfig::with_overrides(max, window)` must replace each field for which the argument is `Some`
  and keep the other unchanged.
- `SPEC-7.2.130` `RateLimitConfig::subject(key)` must interpret a stored key per `key_kind`: `Email` yields
  `KeySubject::Email(key)`; `UserId` yields `UserId` when the key parses as a UUID; `TwoFactorUserId` yields `UserId`
  when the key is `TWO_FACTOR_KEY_PREFIX` followed by a UUID; `Ip` yields `Ip(key)`; `ClientId` yields `ClientId` when the
  key parses as a UUID; a key that does not parse must yield `KeySubject::Unknown(key)` carrying the raw key and never
  panic.

#### Support tickets

- `SPEC-7.2.131` `TicketStatus` must have the variants `Open` (awaiting the team), `Pending` (awaiting the requester) and
  `Closed`, stored as the lowercase strings `"open"`, `"pending"` and `"closed"` in `support_tickets.status`.
- `SPEC-7.2.132` `TicketStatus::from_str_lenient(s)` must map `"pending"` to `Pending`, `"closed"` to `Closed` and any
  other string to `Open`.
- `SPEC-7.2.133` `MessageDirection` must have the variants `Inbound` and `Outbound`, stored as `"inbound"` and
  `"outbound"`.
- `SPEC-7.2.134` `SupportTicket` must carry `id`, `subject`, `requester_email`, `requester_name`, `status` (raw string),
  `created_at`, `updated_at` and `last_message_at`; `SupportMessage` must carry `id`, `ticket_id`, `direction`,
  `from_email`, `to_email`, `body_text`, `body_html`, `message_id`, `in_reply_to`, `mail_references`, `created_at`.
- `SPEC-7.2.135` `NewInboundMessage.references` must be the split References chain as a list, and the repository must
  join it into one string for storage in `mail_references`; `NewMessage` must carry the already-joined
  `mail_references` as an optional string.

#### Token and session models

- `SPEC-7.2.136` Every token-bearing model (`RefreshToken`, `MagicLinkToken`, `PasswordResetToken`, `LoginApprovalCode`,
  `LoginDevice`, `EmailChangeRequest`, `EmailVerificationToken`, `AdminInvite`, `TrustedDevice`) must store only a hash
  (`token_hash`, `code_hash` or `device_hash`) and never the secret, and that hash field must be skipped on serialization.
- `SPEC-7.2.137` `RefreshToken.op_session_id` must be skipped on serialization and be `None` for a token minted without an
  OP session; a `None` value must fall back to the legacy absolute-TTL behaviour.
- `SPEC-7.2.138` For `RefreshToken`, `is_expired()` must be true when `expires_at` is before now, `is_revoked()` must be
  true when `revoked_at` is set, and `is_valid()` must be true only when it is neither expired nor revoked.
- `SPEC-7.2.139` For `MagicLinkToken`, `PasswordResetToken`, `EmailVerificationToken` and `LoginApprovalCode`,
  `is_expired()` must be true when `expires_at` is before now, `is_used()` must be true when `used_at` is set, and
  `is_valid()` must be true only when the token is neither expired nor used.
- `SPEC-7.2.140` For `EmailChangeRequest`, `is_valid()` must be true only when the request is not expired, not
  confirmed (`confirmed_at` unset) and not canceled (`canceled_at` unset).
- `SPEC-7.2.141` For `AdminInvite`, `is_valid()` must be true only when the invite is not expired, not accepted
  (`accepted_at` unset) and not revoked (`revoked_at` unset).
- `SPEC-7.2.142` For `TrustedDevice`, `is_valid()` must be true only when the device is not expired and not revoked, and
  only a valid row may let a subscriber skip the TOTP prompt at login.
- `SPEC-7.2.143` `LoginApprovalCode` must record the `challenge_jti` of the challenge token it was minted for,
  `attempts`, and the resolved `country` and `device_hash`, so completion resolves exactly that row and persists the
  baseline without re-deriving it; `CreateLoginApprovalCode.challenge_jti` is required.
- `SPEC-7.2.144` `LoginDevice.device_hash` must be the SHA-256 hash of a client-supplied device id, and the raw id must
  never be stored.
- `SPEC-7.2.145` `SessionInfo::from(RefreshToken)` must copy `id`, `device_info`, `created_at` and `last_used_at`, render
  `ip_address` as text, and set `is_current` to false for the caller to set.
- `SPEC-7.2.146` `TrustedDeviceInfo::from(TrustedDevice)` must expose `id`, `label`, `created_at`, `last_used_at` and
  `expires_at`, render `ip_address` as the bare address text without a prefix length, and omit the token hash.

#### User models

- `SPEC-7.2.147` `User.password_hash` must be skipped on serialization and be nullable.
- `SPEC-7.2.148` `User.role`, `membership_status` and `membership_tier` must be stored as strings, and
  `role_enum()`, `membership_status_enum()` and `membership_tier_enum()` must convert them with the shared crate's
  string conversions.
- `SPEC-7.2.149` `User::is_admin()` must be true only when `role` equals `"admin"`; `is_deleted()` must be true when
  `deleted_at` is set; `has_active_membership()` must be the shared `has_access()` of the membership status;
  `trial_eligible()` must be true only when `has_used_trial` is false.
- `SPEC-7.2.150` `User::is_access_allowed()` must return true for an admin; then true for a `lifetime_member`; then true
  when `trial_ends_at` is in the future; then, when `membership_status` is `"grace_period"`, true only when
  `grace_period_end` is set and in the future (a missing deadline counts as expired); otherwise the shared
  `has_access()` of the membership status.
- `SPEC-7.2.151` `normalize_email(email)` must return the email lower-cased and must not trim or otherwise alter it, and
  every write to `users.email` must go through it.
- `SPEC-7.2.152` `UserResponse::from(User)` must omit `password_hash`, Stripe customer and payment-method ids,
  `locked_price_id`, `last_login_country`, `login_location_alerts`, `has_used_trial` and `membership_override_by`; set
  `suspended` to whether `deleted_at` is set; and copy `is_super_admin`, `avatar_updated_at`, `first_name`, `last_name`,
  `phone`, `membership_tier`, `trial_ends_at` and `lifetime_member` unchanged.
- `SPEC-7.2.153` `User.avatar_updated_at` must be NULL when no avatar is set and otherwise the time of the latest upload;
  it is the marker that an avatar exists and the cache-busting version of the avatar URL, so the user fetch never loads
  the image bytes.
- `SPEC-7.2.154` `User.is_super_admin` must be set on the bootstrap admin when it is promoted and gates the rate-limit
  and IP-ban management surfaces.
- `SPEC-7.2.155` `CreateUser` must carry `email`, an optional `password_hash` and a `UserRole`.

### 7.3 Domain repositories

The repositories are in `crates/bunyip-domain/src/repositories`. Each is a stateless struct of associated async
functions taking a pool or executor, except `DownloadCacheRepository` and `DownloadDailyCountRepository`, which own a
pool. All queries are runtime-checked `sqlx` calls (no compile-time macros).

#### Cross-cutting rules

- `SPEC-7.3.1` Every repository function must return `Result<_, AppError>` and propagate a failed database call with
  `?` through the shared `From<sqlx::Error>` conversion, and must not replace a failure with a default value. The one
  exception is the re-exported feedback repository, whose functions return `sqlx::Error` that the caller converts the
  same way.
- `SPEC-7.3.2` The shared conversion from a database failure to `AppError` must log the underlying error at error level
  and map `RowNotFound` to `NotFound` with resource `record`, SQLSTATE `23505` (unique violation) to `Conflict` with
  message `Resource already exists`, pool acquire timeout and closed pool to `DatabaseError` with distinct messages,
  and every other failure to `DatabaseError` with message `A database error occurred`. This mapping is implemented in
  the shared kernel crate, and repositories must rely on it for uniqueness handling instead of pre-checking.
- `SPEC-7.3.3` Every paginated listing that takes `page` and `per_page` must compute its offset as
  `max(0, (page - 1) * per_page)` in 64-bit saturating arithmetic, so an oversized `page` cannot panic or produce a
  negative offset, and must build its page query and count query from the same filter predicates.
- `SPEC-7.3.4` Filter values in listings must be bound as query parameters. A value interpolated into SQL text must
  come only from a fixed set owned by the repository (branding version columns, user sort expressions, the audit and
  feedback bucket predicates), never from request input.
- `SPEC-7.3.5` A multi-statement write whose parts must succeed or fail together must run in one transaction that
  rolls back on any failure (dropping an uncommitted transaction rolls it back). A function that a caller must be able
  to compose into its own transaction must take a generic executor.
- `SPEC-7.3.6` A lookup by key must return `Option` and `None` for absence, without error. An update or delete that
  the contract says must hit an existing row must return `AppError::not_found(...)` when it affected no row, as
  specified per function below. A function that returns `bool` must return true only when a row was changed.
- `SPEC-7.3.7` A single-use or state-claiming update must be one conditional statement whose guard excludes
  already-claimed rows, and must report through its return value whether this caller changed a row, so concurrent
  callers cannot both succeed.
- `SPEC-7.3.8` Secrets stored in configuration or credential rows must be written and read only as caller-supplied
  ciphertext, nonce and `key_version`. Repositories must not encrypt or decrypt, and the re-encryption variants must
  not change `updated_by`.
- `SPEC-7.3.9` Singleton configuration tables (`auto_ban_config`, `branding`, `email_config`, `mirzam_config`,
  `mokosh_config`, `stripe_config`, `tier_config`) must be read and written through the row with `id = 1` only.

#### Dead-letter and singleton configuration tables

- `SPEC-7.3.11` `AccountDeleteDispatchFailureRepository::record` must insert one new `account_delete_dispatch_failures`
  row per call for `(user_id, app_slug, last_error)` and return the inserted row, and must not upsert or overwrite an
  earlier row for the same pair, so a later failed replay stays a distinct event. A database failure must be returned
  as `AppError`.
- `SPEC-7.3.12` `AutoBanConfigRepository::get` must read the singleton `auto_ban_config` row with `id = 1`, and must
  return an error (not a default configuration) when that row is absent.
- `SPEC-7.3.13` `AutoBanConfigRepository::update` must change only the fields passed as `Some` (`enabled`,
  `threshold`, `window_secs`, `ban_duration_secs`), leave a `None` field at its stored value, always set `updated_at`
  to the current time and `updated_by` to the caller, and return the updated row. It must target `id = 1` only and
  return an error when that row is absent.
- `SPEC-7.3.14` `FeatureToggleRepository::get_all` must return every `feature_toggles` row ordered by `key`
  ascending, including rows whose key names a feature this build does not know.
- `SPEC-7.3.15` `FeatureToggleRepository::load` must resolve all stored rows through `FeatureToggles::from_rows`, and
  must return the database error rather than an all-defaults set when the read fails.
- `SPEC-7.3.16` `FeatureToggleRepository::set` must upsert one toggle on `key` (insert, or on conflict replace
  `enabled` and `updated_by` and set `updated_at` to the current time) and return the stored row. It must accept any
  executor so the caller can run it in the same transaction as its audit row.
- `SPEC-7.3.17` `BrandingRepository::get` must read the singleton `branding` row with `id = 1` and return an error
  when it is absent.
- `SPEC-7.3.18` `BrandingRepository::update` must overwrite every editable text field (brand name, tagline, meta
  description, Open Graph image URL, newsletter URL, theme CSS, light and dark theme colors) with the supplied values
  including empty strings, which clear the field, must not use COALESCE semantics, must not modify the asset version
  markers, and must set `updated_at` and `updated_by`.
- `SPEC-7.3.19` `BrandingRepository::get_asset` must return `Some((mime_type, data))` for the `branding_assets` row
  with the given `kind` and `None` when the slot is unset.
- `SPEC-7.3.20` `BrandingRepository::set_asset` must, in one transaction, delete every `branding_assets` key the slot
  owns, insert each supplied file (storing `size_bytes` as the byte length), and stamp the slot's version column on
  `branding` row `id = 1` with the current time and `updated_by`, then commit. A failure at any step must roll back
  all earlier steps and return the error, so a partial icon set or half-replaced brand is never observable.
- `SPEC-7.3.21` `BrandingRepository::clear_asset` must, in one transaction, delete every `branding_assets` key the
  slot owns and set the slot's version column to NULL, and must succeed when the slot was already empty.
- `SPEC-7.3.22` The version column interpolated into the `set_asset` and `clear_asset` statements must come only from
  `BrandingAssetSlot::version_column`, whose values are exactly `mark_updated_at`, `favicon_updated_at` and
  `mascot_updated_at`, and must never come from request input.

#### Applications, groups and documentation pages

- `SPEC-7.3.31` `ApplicationGroupRepository::list` must return all groups ordered by `sort_order` ascending, then
  `display_name` ascending.
- `SPEC-7.3.32` `ApplicationGroupRepository::find_by_id` and `find_by_slug` must return `None` when no group matches.
- `SPEC-7.3.33` `ApplicationGroupRepository::create` must insert a group and return it, storing `sort_order` 0 when
  none is supplied. A duplicate of a unique column must surface as the conflict error produced by the shared
  database-error mapping.
- `SPEC-7.3.34` `ApplicationGroupRepository::update` must change only the fields supplied (name, slug, display name,
  description, icon URL, sort order), set `updated_at`, and return an error when the id matches no group.
- `SPEC-7.3.35` `ApplicationGroupRepository::delete` must remove the group row only, so member applications are
  ungrouped (`applications.group_id` becomes NULL) and not deleted. Deleting an id that matches no row returns `Ok`.
- `SPEC-7.3.36` `ApplicationRepository::list_active` must return applications with `is_active = TRUE`, and
  `list_active_hosted` must additionally require `is_hosted = TRUE`. `list_all` must return every application. All
  three must order by `sort_order` ascending, then `display_name` ascending.
- `SPEC-7.3.37` `ApplicationRepository::find_by_id` and `find_by_slug` must return `None` when no application
  matches, and `find_active_by_slug` must also return `None` for an application with `is_active = FALSE`.
- `SPEC-7.3.38` `ApplicationRepository::set_requires_entitlement`, `set_maintenance_mode`, `set_active`, `set_group`
  and `update_version` must each update exactly the named column(s) of the application with the given id, set
  `updated_at`, and return `AppError::not_found("Application")` when no row was affected.
- `SPEC-7.3.39` `ApplicationRepository::set_requires_entitlement` must accept any executor so the caller can run it in
  one transaction with the entitlement backfill.
- `SPEC-7.3.40` `ApplicationRepository::set_maintenance_mode` must store the supplied message as given, so `None`
  clears `maintenance_message` to NULL.
- `SPEC-7.3.41` `ApplicationRepository::set_group` must assign `group_id` directly, so `None` clears the group. It
  must remain separate from `update`, which cannot clear `group_id`.
- `SPEC-7.3.42` `ApplicationRepository::update` must change only the fields supplied (a `None` leaves the stored
  value), set `updated_at`, and return the updated row. An empty string for `forgejo_package` must store NULL, and it
  must return an error when the id matches no application.
- `SPEC-7.3.43` `ApplicationRepository::create` must insert the application and return it, storing `is_hosted` TRUE
  when none is supplied, `artifact_source` `release` when none is supplied, and `sort_order` equal to the current
  maximum `sort_order` plus one (1 when the table is empty). The `sort_order` is computed in the insert statement
  without a lock, so concurrent creates may receive the same value.
- `SPEC-7.3.44` `ApplicationRepository::delete` must remove the application by id and return
  `AppError::not_found("Application")` when no row was removed.
- `SPEC-7.3.45` `ApplicationRepository::set_order` must do nothing and return `Ok` for an empty list. Otherwise it
  must, in one statement, set each listed application's `sort_order` to its 1-based position in the list and
  `updated_at` to the current time, leave unlisted applications unchanged, and ignore listed ids that match no
  application.
- `SPEC-7.3.46` `ApplicationRepository::record_version` must insert `(application_id, version_tag, artifact_digest)`
  into `application_versions`. On a repeated `(application_id, version_tag)` it must not add a row, must fill a
  previously NULL digest, and must never overwrite a recorded digest.
- `SPEC-7.3.47` `ApplicationRepository::is_pullable_version` must return true only when an `application_versions` row
  exists for the application and tag with `yanked` false, and false otherwise.
- `SPEC-7.3.51` `ApplicationDocRepository::list_by_app_slug` must return only summary columns (slug, title,
  sort_order, no body) for the application with the given slug, only when that application has `is_active = TRUE`,
  ordered by `sort_order` ascending then `title` ascending.
- `SPEC-7.3.52` `ApplicationDocRepository::get_by_app_and_slug` must return the page for the application slug and
  doc slug only when the application has `is_active = TRUE`, and `None` otherwise.
- `SPEC-7.3.53` `ApplicationDocRepository::list_by_app_id` must return all full page rows of an application by id
  regardless of its `is_active` value, ordered by `sort_order` ascending then `title` ascending. `get` must return
  one page by id or `None`.
- `SPEC-7.3.54` `ApplicationDocRepository::create` must insert a page for the application id with the supplied slug,
  title, body and sort order and return it. A duplicate unique key must surface as the conflict error produced by the
  shared database-error mapping.
- `SPEC-7.3.55` `ApplicationDocRepository::update` must change only the supplied fields (slug, title, body, sort
  order), set `updated_at`, and return an error when the id matches no page.
- `SPEC-7.3.56` `ApplicationDocRepository::delete` must return `true` when a row was removed and `false` when the id
  matched none, without raising an error.
- `SPEC-7.3.57` `ApplicationDocRepository::app_ids_with_docs` must return the distinct set of `application_id` values
  having at least one page, in one query.
- `SPEC-7.3.58` `ApplicationDocRepository::list_documented_apps` must return the distinct `(slug, display_name)` of
  applications with `is_active = TRUE` that have at least one page, ordered by `display_name` ascending, and the
  active filter and the join to `application_docs` must both remain in the query.

#### Counters, spam reasons and audit log

- `SPEC-7.3.61` `DownloadDailyCountRepository::increment` must atomically upsert the `download_daily_counts` row for
  `(user_id, day)`, adding 1 (inserting with 1 when absent), and return the new count.
- `SPEC-7.3.62` `DownloadDailyCountRepository::decrement` must subtract 1 from the `(user_id, day)` count without
  going below 0, must do nothing and return `Ok` when no row exists, and must return a database failure as
  `AppError`.
- `SPEC-7.3.63` `FeedbackSpamReasonsRepository::insert` must upsert the reason on `feedback_id`, replacing the stored
  reason when a row already exists. `find` must return `None` for a feedback id with no stored reason.
- `SPEC-7.3.64` `AuditLogRepository::create` and `create_in_tx` must insert one `audit_logs` row and return it, with
  `action` stored as the action's string form, `is_admin_action` derived from the action, and `severity` stored as
  its string form. `create_in_tx` must accept any executor so a caller can commit the audit row in the same
  transaction as its own writes.
- `SPEC-7.3.65` `AuditLogRepository::list_paginated` must build the page query and the count query from the same
  filter predicates joined by `AND`, binding every value as a parameter: exact `actor_id`, exact `action`, exact
  `severity`, `is_admin_action = TRUE` when `admin_only`, `created_at >= start_date`, `created_at <= end_date`, and a
  case-insensitive substring match of `search` against `actor_email` or the text of `resource_id`.
- `SPEC-7.3.66` `AuditLogRepository::list_paginated` must order rows by `created_at` descending, return
  `per_page` rows at offset `max(0, (page - 1) * per_page)` computed in 64-bit saturating arithmetic so a huge `page`
  cannot panic or wrap negative, and return the total count of matching rows as the second tuple element.
- `SPEC-7.3.67` `AuditLogRepository::list_by_actor` must return the newest `limit` rows for the actor, ordered by
  `created_at` descending.
- `SPEC-7.3.68` `AuditLogRepository::list_security_events` must return the newest `limit` rows whose action is one of
  `user_login`, `user_logout`, `password_changed`, `password_reset_completed` or `admin_user_impersonated`, ordered by
  `created_at` descending.

#### Download cache

- `SPEC-7.3.71` `DownloadCacheRepository::find` must return the `download_cache` row for the exact
  `(application_id, version, asset_name)` triple, or `None`.
- `SPEC-7.3.72` `DownloadCacheRepository::upsert` must, in one transaction, first lock any existing row for the triple
  with `SELECT ... FOR UPDATE`, then insert the row or on conflict on `(application_id, version, asset_name)` replace
  `content_sha256`, `size_bytes` and `content_type` and set `last_accessed_at` to the current time, then commit. A
  failure must roll back and return the error.
- `SPEC-7.3.73` `DownloadCacheRepository::upsert` must return the stored row together with the previous
  `content_sha256` only when a prior row existed and its SHA differs from the new one, and `None` otherwise, so the
  caller can remove the now-orphaned file.
- `SPEC-7.3.74` `DownloadCacheRepository::touch` must set `last_accessed_at` to the current time for the row id. When
  no row matches it must log a warning naming the id and still return `Ok`, because a concurrent eviction is an
  expected race.
- `SPEC-7.3.75` `DownloadCacheRepository::delete_for_version` must delete every row for `(application_id, version)`
  and return the `content_sha256` of each deleted row.
- `SPEC-7.3.76` `DownloadCacheRepository::sha_referenced` must return true when at least one `download_cache` row
  holds the SHA-256, and false otherwise.
- `SPEC-7.3.77` `DownloadCacheRepository::total_size_bytes` must return the sum of `size_bytes` as an `i64`, 0 for an
  empty table, by casting the `SUM` result to `BIGINT`, because the NUMERIC result does not decode into `i64`.
- `SPEC-7.3.78` `DownloadCacheRepository::oldest` must return at most `limit` rows ordered by `last_accessed_at`
  ascending.
- `SPEC-7.3.79` `DownloadCacheRepository::delete` must delete the row by id and return `Ok` whether or not a row
  matched.
- `SPEC-7.3.80` `DownloadCacheRepository` and `DownloadDailyCountRepository` must implement the download engine's
  `AssetStore` and `DownloadCounter` traits by delegating each method to the inherent method of the same name, with
  no additional behavior.

#### Email configuration

- `SPEC-7.3.81` `EmailConfigRepository::get` must read the singleton `email_config` row with `id = 1` and return an
  error when it is absent.
- `SPEC-7.3.82` `EmailConfigRepository::update` must change only the fields passed as `Some`, set `updated_at` and
  `updated_by`, and return the updated row. It must target `id = 1` only and return an error when that row is absent.
- `SPEC-7.3.83` `EmailConfigRepository::update` must write `smtp_password`, `smtp_password_nonce` and `key_version`
  together, and only when a new `smtp_password` ciphertext is supplied. When it is `None` all three must keep their
  stored values.
- `SPEC-7.3.84` `EmailConfigRepository::clear_password` must set `smtp_password` and `smtp_password_nonce` to NULL
  and update `updated_at` on row `id = 1`, and must not change `updated_by`.
- `SPEC-7.3.85` `EmailConfigRepository::update_password_encryption` and `update_imap_password_encryption` must replace
  only the stored ciphertext, nonce and `key_version` of the SMTP or IMAP password respectively and `updated_at`, and
  must not change `updated_by`, because re-encryption is not an operator edit.
- `SPEC-7.3.86` `EmailConfigRepository::update_imap_password` must replace the IMAP password ciphertext, nonce and
  `key_version`, set `updated_at` and `updated_by`, leave all other IMAP columns unchanged, and return the updated
  row.
- `SPEC-7.3.87` `EmailConfigRepository::update_imap_settings` must change only the IMAP host, port, username, mailbox
  and enabled fields passed as `Some`, never the password columns, set `updated_at` and `updated_by`, and return the
  updated row.

#### Entitlements

- `SPEC-7.3.91` `EntitlementRepository::is_allowed` must return true without querying the database when the
  application does not require an entitlement or the user is an admin, and must otherwise return the result of
  `is_entitled`.
- `SPEC-7.3.92` `EntitlementRepository::is_entitled` must return true only when an `application_entitlements` row
  exists for the user and application with `revoked_at` NULL.
- `SPEC-7.3.93` `EntitlementRepository::backfill_for_application` must insert an `application_entitlements` row with
  source `backfill` and no grantor for every user who is not deleted (`deleted_at` NULL), is not an admin, and is a
  lifetime member, has `trial_ends_at` in the future, or has `membership_status` `active` or `grace_period`. It must
  leave existing rows untouched (`ON CONFLICT DO NOTHING`), return the number of rows inserted, and accept any
  executor so it can share a transaction with `set_requires_entitlement`.
- `SPEC-7.3.94` `EntitlementRepository::grant` must upsert on `(user_id, application_id)`, and for an existing row,
  including a revoked one, must set `granted_by`, `source` and `granted_at` to the new values and clear `revoked_at`,
  without raising an error.
- `SPEC-7.3.95` `EntitlementRepository::revoke` must set `revoked_at` only on a row that is not already revoked and
  return true only when a row was changed.
- `SPEC-7.3.96` `EntitlementRepository::revoke_all_for_user_by_source` must set `revoked_at` on only the user's
  not-yet-revoked rows whose `source` equals the argument and return the application ids revoked.
- `SPEC-7.3.97` `EntitlementRepository::list_for_user` must return the user's not-revoked entitlements joined to the
  application (id, slug, display name, `requires_entitlement`, `granted_at`, `source`) ordered by `display_name`
  ascending.
- `SPEC-7.3.98` `EntitlementRepository::active_application_ids` must return the application ids of the user's
  not-revoked entitlements and must accept any Postgres executor so it can run inside a per-user row-level-security
  transaction.
- `SPEC-7.3.99` `EntitlementRepository::applications_for_price` must return the application ids mapped to the Stripe
  price id whose application has `is_active = TRUE`.
- `SPEC-7.3.100` `EntitlementRepository::add_price_mapping` must insert the `(stripe_price_id, application_id)` pair
  and succeed without a change when it already exists. `remove_price_mapping` must delete the pair and succeed when
  it does not exist.

#### Feedback, invites, suppression list, notifications

- `SPEC-7.3.111` `FeedbackRepository` must be the shared feedback repository re-exported unchanged, returning
  `sqlx::Error`. Callers must map that error to `AppError` through the shared conversion, and must treat a `false`
  result from its `delete` and `archive_one` as "not found" by raising `AppError::not_found("Feedback")`.
- `SPEC-7.3.112` `list_paginated_filtered` must treat an absent bucket as `active` and select by bucket: `active` is
  `is_spam = FALSE AND status <> 'closed'`, `closed` is `is_spam = FALSE AND status = 'closed'`, and `spam` is
  `is_spam = TRUE`. The caller must pass only those three values.
- `SPEC-7.3.113` `list_paginated_filtered` must apply the optional filters joined by `AND` with every value bound as a
  parameter: `tag` must be an element of `tags`, `has_attachment` must test for existence of a `feedback_attachments`
  row, `has_response` true must require a non-blank `admin_response` and false must match a NULL or blank one, and
  `search` must match case-insensitively as a substring of `subject`, `message` or `email`.
- `SPEC-7.3.114` `list_paginated_filtered` must order by `created_at` descending, apply `LIMIT per_page` at offset
  `max(0, (page - 1) * per_page)` computed in 64-bit saturating arithmetic, and return the count of rows matching the
  same predicates as the second tuple element.
- `SPEC-7.3.115` `count_new_feedback` must count rows with `status = 'new'` and `is_spam = FALSE`.
- `SPEC-7.3.116` `InviteRepository::create` must insert the invite and return it. The `token_hash` column is unique,
  so a duplicate hash must surface as the conflict error produced by the shared database-error mapping.
- `SPEC-7.3.117` `InviteRepository::find_valid_by_token_hash` must return the invite with the given token hash only
  when `revoked_at` is NULL, `accepted_at` is NULL and `expires_at` is in the future, and `None` otherwise.
- `SPEC-7.3.118` `InviteRepository::find_pending_by_email` must match the email case-insensitively, apply the same
  pending predicate as `find_valid_by_token_hash`, and return the newest such invite by `created_at`, or `None`.
- `SPEC-7.3.119` `InviteRepository::mark_accepted` and `mark_revoked` must set `accepted_at` or `revoked_at` to the
  current time on the invite id, and return `Ok` even when no row matched.
- `SPEC-7.3.120` `InviteRepository::revoke_pending_by_email` must set `revoked_at` to the current time on every
  invite for the email (case-insensitive) that is not revoked, not accepted and not expired.
- `SPEC-7.3.121` `InviteRepository::list_all` and `list_filtered` must return invites ordered by `created_at`
  descending with `per_page` rows at offset `max(0, (page - 1) * per_page)` computed in 64-bit saturating arithmetic,
  plus the count of invites matching the same predicates.
- `SPEC-7.3.122` `InviteRepository::list_filtered` must classify status as `pending` (not accepted, not revoked,
  `expires_at` in the future), `accepted` (accepted), `revoked` (`revoked_at` set) or `expired` (not accepted, not
  revoked, `expires_at` not in the future), and `email` as a case-insensitive substring match. Acceptance must be
  tested with the `accepted_at` column, the only acceptance column of `admin_invites`. The caller must pass only those
  four status values.
- `SPEC-7.3.123` `MailerSuppressionRepository::is_suppressed`, `upsert` and `delete` must normalize the address with
  `normalize_address` (trim and lowercase) before use, so the caller may pass the raw recipient.
- `SPEC-7.3.124` `MailerSuppressionRepository::upsert` must insert `(address, reason, detail)` or, when the address is
  already present, replace its reason and detail and set `updated_at`, and must not return an error for a repeated
  address.
- `SPEC-7.3.125` `MailerSuppressionRepository::count` must return the total number of suppressed addresses, and
  `list` must return rows ordered by `created_at` descending with the supplied `limit` and `offset`.
- `SPEC-7.3.126` `MailerSuppressionRepository::delete` must remove the normalized address and return true only when a
  row existed.
- `SPEC-7.3.127` `NotificationRepository::create` must insert an `admin_notifications` row with the type's string form
  and return it.
- `SPEC-7.3.128` `NotificationRepository::list_unread` must return rows with `is_read = FALSE` ordered by
  `created_at` descending. `count_unread` must return their count.
- `SPEC-7.3.129` `NotificationRepository::list_paginated` must return rows ordered by `created_at` descending with
  `per_page` rows at offset `max(0, (page - 1) * per_page)` computed in 64-bit saturating arithmetic, plus the total
  row count from a separate query.
- `SPEC-7.3.130` `NotificationRepository::mark_as_read` must set `is_read`, `read_by` and `read_at` on the given id,
  and `mark_all_as_read` must do so for every row with `is_read = FALSE`. Neither may fail when no row matched.
- `SPEC-7.3.131` `NotificationRepository::delete_old` must delete notifications with `created_at` older than `days`
  days before now and return the number of rows deleted.

#### Upstream-integration singleton configuration

- `SPEC-7.3.141` `MirzamConfigRepository::get` and `MokoshConfigRepository::get` must read the singleton row with
  `id = 1` of `mirzam_config` or `mokosh_config` and return an error when it is absent.
- `SPEC-7.3.142` `MirzamConfigRepository::update_settings` must overwrite `enabled`, `base_url`, `updates_list` and
  `notices_list`, set `updated_at` and `updated_by`, leave the API token columns unchanged, and return the updated
  row.
- `SPEC-7.3.143` `MirzamConfigRepository::update_api_token` must write the token ciphertext, nonce and `key_version`
  with `updated_at` and `updated_by`. `update_api_token_encryption` must write the same three columns and
  `updated_at` only, leaving `updated_by` unchanged.
- `SPEC-7.3.144` `MirzamConfigRepository::record_sync_error` must set `last_error` and `last_error_at` without
  changing `updated_at` or `updated_by`. `clear_sync_error` must set both columns to NULL only when `last_error` is
  not NULL.
- `SPEC-7.3.145` `MokoshConfigRepository::update_client_id` must overwrite `google_client_id` with `updated_at` and
  `updated_by`, leave the secret columns unchanged, and return the updated row.
- `SPEC-7.3.146` `MokoshConfigRepository::update_client_secret` must write the secret ciphertext, nonce and
  `key_version` with `updated_at` and `updated_by`. `update_client_secret_encryption` must write the same three
  columns and `updated_at` only, leaving `updated_by` unchanged.

#### OIDC tenant assignments

- `SPEC-7.3.151` `OAuthClientUserTenantRepository::assignments_for` must return every assignment for the
  `(oauth_client_id, user_id)` pair ordered by `created_at` ascending, and an empty vector (not an error) when there
  are none. `list_for_client` must return every assignment of the client, unpaginated, in the same order.
- `SPEC-7.3.152` `OAuthClientUserTenantRepository::assign` must insert the assignment and, when the
  `(oauth_client_id, user_id, tenant_id)` triple already exists, return the existing row, replacing its `role` only
  when the new role is not NULL, so a retry that omits the role must not clear a stored one. `created_by` is `None`
  for system-issued assignments.
- `SPEC-7.3.153` `OAuthClientUserTenantRepository::unassign` must delete only the row matching both the assignment id
  and the `oauth_client_id`, return the deleted row, and return `Ok(None)` when no such row exists, so a retry or a
  client mismatch deletes nothing and is not an error.

#### Stripe, tier and rate-limit history/traffic

- `SPEC-7.3.161` `StripeConfigRepository::get` and `TierConfigRepository::get` must read the singleton row with
  `id = 1` of `stripe_config` or `tier_config` and return an error when it is absent.
- `SPEC-7.3.162` `StripeConfigRepository::clear_secrets` must set `secret_key`, `secret_key_nonce`, `webhook_secret`
  and `webhook_secret_nonce` to NULL and update `updated_at` on row `id = 1`, without changing `updated_by`.
- `SPEC-7.3.163` `StripeConfigRepository::update_secret_encryption` must replace each secret ciphertext together with
  its nonce only when that ciphertext is `Some`, always set `key_version`, set `updated_at`, and not change
  `updated_by`.
- `SPEC-7.3.164` `StripeConfigRepository::update` must replace the secret key pair and the webhook secret pair each
  only when its ciphertext is `Some`, set `key_version` only when at least one ciphertext is `Some`, change
  `app_tag`, `success_url`, `cancel_url` and `trial_period_days` only when `Some`, always set `updated_at` and
  `updated_by`, and return the updated row.
- `SPEC-7.3.165` `TierConfigRepository::update` must change the slot counts, trial days, switches and visibility
  flags only when passed as `Some`, set `updated_at` and `updated_by`, and return the updated row. For each of the six
  Stripe id columns `None` must keep the stored value, `Some("")` must set NULL and `Some(id)` must set the id.
- `SPEC-7.3.166` `RateLimitHistoryRepository::record` must insert one `rate_limit_history` row holding the action,
  key, `fired_at` and `expires_at` equal to `window_start` plus the config's `window_seconds`.
- `SPEC-7.3.167` `RateLimitHistoryRepository::list` must return rows with `fired_at >= since` ordered by `fired_at`
  descending, at most `limit` rows.
- `SPEC-7.3.168` `RateLimitHistoryRepository::sweep` must delete rows with `fired_at` older than now minus
  `retention_seconds` and return the number deleted.
- `SPEC-7.3.169` `RateLimitTrafficRepository::record` must upsert one `rate_limit_traffic` row keyed by the action,
  the 32-byte SHA-256 of the key (the key itself is never stored) and the start of the 900-second bucket containing
  `now`, inserting count 1 or incrementing the existing count by 1.
- `SPEC-7.3.170` `RateLimitTrafficRepository::read` must return, for one action, the summed `count` per
  `bucket_start >= since` ordered by `bucket_start` descending. `read_batch` must return the same per-bucket sums for
  every listed action in one query ordered by action then `bucket_start` descending, and must return an empty vector
  without querying when the action list is empty.
- `SPEC-7.3.171` `RateLimitTrafficRepository::sweep` must delete rows with `bucket_start` older than now minus
  `retention_seconds` and return the number deleted. The default retention is `DEFAULT_RETENTION_SECS` (86400
  seconds) and the bucket width is `BUCKET_WIDTH_SECS` (900 seconds).

#### Rate-limit counters

- `SPEC-7.3.181` `RateLimitRepository::check_and_increment` must first return `(0, false)` without touching any
  counter, history row or traffic row when `RateLimitWhitelistRepository::is_whitelisted` is true for the key, and
  must return the whitelist lookup error to the caller when that lookup fails.
- `SPEC-7.3.182` `RateLimitRepository::check_and_increment` must enforce the effective configuration resolved through
  `RateLimitConfigRepository::effective` (not the caller's preset), and must atomically upsert the `rate_limits` row
  for `(key, action)` in one statement: a new row starts at count 1, a row whose `window_start` is older than now
  minus the effective window is reset to count 1 with `window_start` set to now, and any other row has its count
  incremented by 1. It must return the resulting count and `exceeded = count > max_requests`.
- `SPEC-7.3.183` `RateLimitRepository::check_and_increment` must record one request in `rate_limit_traffic` on every
  non-whitelisted call, over the cap or not, in a spawned task off the request path. A failure of that record must be
  logged at warn naming the action and must not change the returned result.
- `SPEC-7.3.184` `RateLimitRepository::check_and_increment` must write one `rate_limit_history` row only for the
  request whose resulting count equals `max_requests + 1` (the first request over the cap in a window), using the
  `window_start` returned by the upsert. A failure of that write must be logged at warn naming the action and must not
  change the returned result.
- `SPEC-7.3.185` `RateLimitRepository::check` must return the current count (0 when no row or when the row's window is
  older than the effective window) and `count > max_requests`, without modifying any row.
- `SPEC-7.3.186` `RateLimitRepository::check_rate_limit` must return `Ok(())` when `check_and_increment` reports the
  cap is not exceeded, and `AppError::RateLimited { retry_after }` with the value from `get_retry_after` when it is.
- `SPEC-7.3.187` `RateLimitRepository::get_retry_after` must return the whole seconds from now until the stored
  `window_start` plus the effective window, never below 0, and 0 when no row exists for the key and action.
- `SPEC-7.3.188` `RateLimitRepository::reset` must delete the `rate_limits` row for `(key, action)` and succeed when
  none exists.
- `SPEC-7.3.189` `RateLimitRepository::max_window_seconds` must return the largest `window_seconds` among the effective
  configurations of all known actions, and `cleanup_expired` must delete `rate_limits` rows with `window_start` older
  than now minus that value and return the number deleted.
- `SPEC-7.3.190` `RateLimitRepository::list_active` must return `rate_limits` rows with `window_start` newer than now
  minus `max_window_seconds`, newest `window_start` first, leaving the decision of which rows are actually throttled to
  the caller.
- `SPEC-7.3.191` `RateLimitRepository::list_approaching` must resolve the action's effective configuration and return
  rows for that action whose window is still open and whose `count` is at least
  `ceil(max_requests * ratio)` and at most `max_requests`, with `ratio` clamped to 0.1..=1.0 and the row limit clamped
  to 1..=100, ordered by `count` descending then `window_start` descending.
- `SPEC-7.3.192` `RateLimitRepository::list_approaching_batch` must return an empty vector without querying for an empty
  action list, and otherwise all rows for the listed actions with `window_start` newer than `horizon`, ordered by
  `count` descending then `window_start` descending, leaving per-action filtering to the caller.

#### Rate-limit configuration and whitelist

- `SPEC-7.3.201` `RateLimitConfigRepository::list` must return every `rate_limit_configs` row ordered by `action`, and
  `get` must return the row for an action or `None`.
- `SPEC-7.3.202` `RateLimitConfigRepository::upsert` must insert or, on conflict on `action`, replace
  `max_requests` and `window_seconds` and set `updated_at` and `updated_by`, return the stored row, and after the
  write succeeds invalidate the process-wide snapshot. `delete` must remove the row, invalidate the snapshot, and
  return true only when a row was removed.
- `SPEC-7.3.203` `RateLimitConfigRepository::overrides` and `effective` must read the process-wide snapshot cache
  (time-to-live `RATE_LIMIT_CONFIG_CACHE_TTL_SECS`, 30 seconds) and must not query one `rate_limit_configs` row per
  decision. `effective` must return the preset resolved through the configuration provider stack in which the table
  rows are the database provider, and must return the preset unchanged for an action that has no declared
  configuration.
- `SPEC-7.3.204` `RateLimitConfigCache::get_or_load` must return the cached snapshot while its age is under the
  time-to-live and otherwise call the loader and replace the snapshot. When the loader fails and a previous snapshot
  exists it must log at error with the cause and the override count and return the previous snapshot; when no previous
  snapshot exists it must return the loader's error. It must never fall back to the built-in caps on failure.
- `SPEC-7.3.205` `database_provider` must hold a row's `max_requests` and `window_seconds` as provider values only when
  the action has a preset and the value is greater than 0. A row for an action with no preset must be skipped with a
  warning naming the action, and a provider refusal of a generated key must be logged at error naming the key.
- `SPEC-7.3.206` `RateLimitWhitelistRepository::list` must return all `rate_limit_whitelist` rows ordered by `added_at`
  descending.
- `SPEC-7.3.207` `RateLimitWhitelistRepository::insert` must insert a `(kind, value, reason, added_by)` row with
  `kind` stored as `user`, `email` or `ip`, return `Some(row)` for a new pair and `None` without changing the stored
  row when the `(kind, value)` pair already exists, and invalidate the snapshot after the statement succeeds.
- `SPEC-7.3.208` `RateLimitWhitelistRepository::delete` must delete by id, invalidate the snapshot, and return true
  only when a row was removed.
- `SPEC-7.3.209` `RateLimitWhitelistRepository::is_whitelisted` must return false for a key with no `:` or whose prefix
  is not `user`, `email` or `ip`, and otherwise return whether the `(kind, value)` split on the first colon is in the
  cached whitelist set, without a per-call query, and must return the loader error when the set cannot be loaded and
  no earlier snapshot exists.
- `SPEC-7.3.210` `WhitelistCache::get_or_load` must behave as `RateLimitConfigCache::get_or_load` with time-to-live
  `RATE_LIMIT_WHITELIST_CACHE_TTL_SECS` (30 seconds): serve a fresh snapshot, reload when stale, on a failed reload
  serve the previous snapshot with an error log naming the cause and entry count, and return the error when no
  previous snapshot exists. It must never treat a failed load as an empty or an all-principals whitelist.

#### Support queue

- `SPEC-7.3.221` `SupportRepository::create_ticket` must insert a `support_tickets` row with status `open` inside a
  transaction and return it.
- `SPEC-7.3.222` `SupportRepository::add_message` must, in one transaction, insert the `support_messages` row and set
  `last_message_at` and `updated_at` of its ticket to the current time, so the ticket timestamps cannot drift from its
  message set. A failure of either statement must roll back both.
- `SPEC-7.3.223` `SupportRepository::find_message_by_id` must return the message whose mail `message_id` equals the
  argument, or `None`.
- `SPEC-7.3.224` `SupportRepository::find_ticket_by_message_ids` must return `None` without querying for an empty
  candidate list, and otherwise the `ticket_id` of the newest (by `created_at`) message whose `message_id` is in the
  list, or `None`.
- `SPEC-7.3.225` `SupportRepository::ingest_inbound` must, when the inbound `message_id` is already stored, return that
  message's existing ticket without creating a ticket or message, and must return an internal error when that ticket
  no longer exists.
- `SPEC-7.3.226` `SupportRepository::ingest_inbound` must otherwise match candidates `In-Reply-To` first, then the
  `References` chain, thread the message onto the matched ticket (returning an internal error when the matched ticket
  is gone) or open a new ticket from the sender's subject, address and name, store the message as inbound with
  `References` joined by a single space (NULL when empty), and perform the ticket creation and message insert in one
  transaction so a failed message insert leaves no orphan ticket.
- `SPEC-7.3.227` `SupportRepository::get_ticket` must return the ticket or `None`. `latest_message` must return the
  newest message of a ticket by `created_at` or `None`. `list_messages` must return all messages of a ticket ordered by
  `created_at` ascending.
- `SPEC-7.3.228` `SupportRepository::list_tickets` must return tickets ordered by `last_message_at` descending with the
  supplied `limit` and `offset`, and `count_tickets` must return the total number of tickets.
- `SPEC-7.3.229` `SupportRepository::set_status` must set the ticket's status string and `updated_at`, and return `Ok`
  even when no ticket matched.

#### Trusted devices

- `SPEC-7.3.231` `TrustedDeviceRepository::create` must insert a trusted-device row (user, token hash, label, IP
  address, expiry) and return it. Only the token hash is stored, never the cookie secret.
- `SPEC-7.3.232` `TrustedDeviceRepository::find_valid_by_hash` must return the device with the token hash only when
  `revoked_at` is NULL and `expires_at` is in the future, and `None` otherwise, because this lookup gates skipping
  TOTP.
- `SPEC-7.3.233` `TrustedDeviceRepository::find_user_devices` must return the user's devices with `revoked_at` NULL and
  `expires_at` in the future ordered by `created_at` descending. `find_user_devices_paginated` must return the same set
  with the supplied `per_page` and `offset`, and `count_user_devices` its count. The paginated and count functions must
  accept any Postgres executor so they can run in a per-user row-level-security transaction.
- `SPEC-7.3.234` `TrustedDeviceRepository::find_by_id` must return the device by id in any state (revoked or expired
  included), or `None`, and must accept any Postgres executor.
- `SPEC-7.3.235` `TrustedDeviceRepository::touch_last_used` must set `last_used_at` to the current time for the id and
  return `Ok` even when no row matched.
- `SPEC-7.3.236` `TrustedDeviceRepository::revoke` must set `revoked_at` to the current time for the id, accept any
  Postgres executor, and return `Ok` even when no row matched. `revoke_all_for_user` must set `revoked_at` on only the
  user's not-yet-revoked devices and return the number revoked.

#### Tokens, approvals and email-change records

- `SPEC-7.3.241` `TokenRepository::create_refresh_token`, `create_magic_link_token`, `create_password_reset_token`,
  `create_email_change_request`, `create_email_verification_token` and `create_login_approval_code` must each insert
  one row with the supplied hash and expiry and return it. Only hashes of token secrets are stored.
- `SPEC-7.3.242` `TokenRepository::link_refresh_to_op_session` must set `op_session_id` only on the refresh token
  matching both `token_hash` and `user_id` whose `op_session_id` is still NULL, and return `Ok` when no row matched.
- `SPEC-7.3.243` `TokenRepository::find_refresh_token_by_hash` must return the token only when `revoked_at` is NULL
  and `expires_at` is in the future. `find_refresh_token_by_hash_any` and `find_refresh_token_by_id` must return the
  row in any state.
- `SPEC-7.3.244` `TokenRepository::find_user_refresh_tokens` must return the user's refresh tokens with `revoked_at`
  NULL and `expires_at` in the future ordered by `created_at` descending. `find_user_refresh_tokens_paginated` must
  return the same set with the supplied `per_page` and `offset`, and `count_user_refresh_tokens` its count.
- `SPEC-7.3.245` `TokenRepository::update_refresh_token_last_used`, `revoke_refresh_token` and
  `revoke_refresh_token_by_hash` must set `last_used_at` or `revoked_at` to the current time on the matching row and
  return `Ok` even when no row matched.
- `SPEC-7.3.246` `TokenRepository::revoke_all_user_refresh_tokens` must, in one transaction (a savepoint when given an
  open transaction), set `revoked_at` on the user's not-yet-revoked rows of `refresh_tokens`, set `revoked_at` and
  `revoke_reason` `security_event` on the user's not-yet-revoked `refresh_token_families`, and set `revoked_at` on the
  user's not-yet-revoked `refresh_tokens_v2`. A failure of any statement must roll back all three.
- `SPEC-7.3.247` `TokenRepository::revoke_client_user_refresh_tokens` must, in one transaction, set `revoked_at` and
  `revoke_reason` `tenant_reassigned` on the not-yet-revoked refresh-token families of the `(user_id, client_id)` pair,
  set `revoked_at` on the pair's not-yet-revoked `refresh_tokens_v2` rows, and return the number of families revoked.
  It must not touch the legacy `refresh_tokens` table.
- `SPEC-7.3.248` `TokenRepository::revoke_other_user_refresh_tokens` must set `revoked_at` on every not-yet-revoked
  legacy refresh token of the user except `keep_token_id` and return the number revoked.
- `SPEC-7.3.249` `TokenRepository::find_magic_link_token_by_hash`, `find_password_reset_token_by_hash` and
  `find_email_verification_token_by_hash` must return the token only when `used_at` is NULL and `expires_at` is in the
  future. `find_email_change_request_by_hash` must return the request only when `confirmed_at` and `canceled_at` are
  NULL and `expires_at` is in the future.
- `SPEC-7.3.250` `TokenRepository::mark_magic_link_token_used`, `mark_password_reset_token_used` and
  `mark_email_verification_token_used` must claim a token with `UPDATE ... SET used_at = NOW() WHERE id = $1 AND
  used_at IS NULL` and return true only when a row was changed, so exactly one of any number of concurrent
  consumers of one token receives true. Callers must refuse the operation on false.
- `SPEC-7.3.251` `TokenRepository::mark_email_verification_token_used` and `confirm_email_change_request` must accept
  any executor so the claim can share the caller's transaction with the write it guards.
- `SPEC-7.3.252` `TokenRepository::confirm_email_change_request` must set `confirmed_at` only on a request that is
  not yet confirmed and report whether it did, so that two concurrent confirmations of one request cannot both
  succeed.
- `SPEC-7.3.253` `TokenRepository::count_recent_magic_link_tokens` must count tokens created after `since` for the
  email compared case-insensitively. `count_recent_password_reset_tokens`, `count_recent_email_change_requests` and
  `count_recent_email_verification_tokens` must count rows created after `since` for the user.
- `SPEC-7.3.254` `TokenRepository::oldest_recent_email_change_request` and `oldest_recent_email_verification_token`
  must return the minimum `created_at` among the user's rows created after `since`, or `None` when there are none.
- `SPEC-7.3.255` `TokenRepository::revoke_pending_password_reset_tokens` must set `used_at` on every unused,
  unexpired password reset token of the user and return the number changed, so at most the newest request's token
  remains valid.
- `SPEC-7.3.256` `TokenRepository::cancel_pending_email_change_requests` must set `canceled_at` on every request of the
  user that is not confirmed, not canceled and not expired.
- `SPEC-7.3.257` `TokenRepository::find_valid_login_approval_code_by_jti` must return the approval code matching both
  `user_id` and `challenge_jti` only when `used_at` is NULL and `expires_at` is in the future.
- `SPEC-7.3.258` `TokenRepository::increment_login_approval_attempts` must add 1 to `attempts` in one statement
  guarded by `attempts < max` and `used_at IS NULL`, and return the new count, or `None` when the guard failed, so
  concurrent wrong guesses cannot push the counter past `max`.
- `SPEC-7.3.259` `TokenRepository::claim_login_approval_code` must set `used_at` in one statement guarded by
  `used_at IS NULL`, `attempts < max` and `expires_at` in the future, and return true only for the caller whose
  statement changed the row, so a used, expired, capped or concurrently claimed code returns false.
- `SPEC-7.3.260` `TokenRepository::count_login_devices` must return the number of `login_devices` rows of the user, and
  `find_login_device` must return the row for `(user_id, device_hash)` or `None`.
- `SPEC-7.3.261` `TokenRepository::record_login_device` must upsert on `(user_id, device_hash)`, inserting the device
  with its user agent or, for an existing device, setting only `last_seen_at` to the current time, and must not raise a
  duplicate error on a repeated login.
- `SPEC-7.3.262` `TokenRepository::list_email_verification_over_limit` and `list_email_change_over_limit` must return,
  for each non-deleted user (`deleted_at` NULL) with at least `threshold` rows created after `since`, the user id,
  email, row count and oldest `created_at`, ordered by count descending.
- `SPEC-7.3.263` `TokenRepository::delete_recent_email_verification_tokens` and `delete_recent_email_change_requests`
  must delete the user's rows created after `since` and return the number deleted.
- `SPEC-7.3.264` `TokenRepository::cleanup_expired_tokens` must delete `refresh_tokens`, `magic_link_tokens`,
  `password_reset_tokens`, `email_change_requests` and `email_verification_tokens` rows whose `expires_at` has
  passed, and `login_approval_codes` rows that are expired or used, must leave `login_devices` untouched, and must
  return the total number of rows deleted.

#### Two-factor authentication

- `SPEC-7.3.271` `TotpRepository::upsert_totp` must insert the user's `user_totp` row with an unverified secret and the
  setup token hash and expiry, or, for an existing row, replace the secret, reset `verified` to FALSE, clear
  `enabled_at` and set the new setup token, only when the existing row has `verified = FALSE`. It must return
  `Some(row)` on success and `None` when the existing row is verified, and must never replace a verified row.
- `SPEC-7.3.272` `TotpRepository::replace_totp` must upsert the user's row unconditionally, replacing even a verified
  secret, setting `verified` FALSE and clearing `enabled_at` and the setup token. It is for trusted provisioning only
  and must not be called from a request handler.
- `SPEC-7.3.273` `TotpRepository::complete_setup` must, in one transaction, set `verified = TRUE`, set `enabled_at`
  and clear the setup token only on a row with `verified = FALSE` and a `setup_token_hash` equal to the argument, then
  set `users.two_factor_enabled` to TRUE, and return true. When no row matched the guard it must change nothing and
  return false.
- `SPEC-7.3.274` `TotpRepository::update_encryption` must replace the active ciphertext, nonce and `key_version` of
  the row with the given id, and `update_pending_encryption` must replace the `pending_*` ciphertext, nonce and key
  version of that row, for key rotation, without changing any other column except `updated_at`.
- `SPEC-7.3.275` `TotpRepository::stage_pending_secret` must write a re-keyed secret to the `pending_*` columns and
  `pending_created_at` of the user's row without changing the active secret or `verified`, overwriting any earlier
  pending secret.
- `SPEC-7.3.276` `TotpRepository::promote_pending_secret` must copy the pending ciphertext, nonce and key version
  into the active columns and clear the pending columns, keep `verified` unchanged, run only when all three pending
  values are present, and return the number of rows updated (0 when there is no complete pending secret).
- `SPEC-7.3.277` `TotpRepository::claim_totp_step` must set `last_used_step` to the step in one conditional statement
  that matches only when `last_used_step` is NULL or less than the step, and return the number of rows updated, so a
  replayed or older step and all but one concurrent submission of the same step return 0. Callers must treat 0 as a
  failed verification.
- `SPEC-7.3.278` `TotpRepository::find_by_user_id` must return the user's `user_totp` row or `None`.
- `SPEC-7.3.279` `TotpRepository::mark_verified` must, in one transaction, set `verified`, `enabled_at` and
  `updated_at` on the user's TOTP row and set `users.two_factor_enabled` to TRUE.
- `SPEC-7.3.280` `TotpRepository::delete_by_user_id` must, in one transaction, delete the user's `user_totp` row and
  all of the user's `recovery_codes`, and set `users.two_factor_enabled` to FALSE.
- `SPEC-7.3.281` `TotpRepository::insert_recovery_codes` must, in one transaction, delete all of the user's existing
  recovery codes and insert the supplied hashes in one multi-row statement (inserting nothing for an empty list), so
  the old and new sets are never visible together.
- `SPEC-7.3.282` `TotpRepository::find_all_unused_recovery_codes` and `count_unused_recovery_codes` must return
  the rows or the count of the user's recovery codes with `used_at` NULL, and `find_unused_recovery_code` must return
  the unused code matching the user and hash or `None`.
- `SPEC-7.3.283` `TotpRepository::mark_recovery_code_used` must set `used_at` with a guard on `used_at IS NULL` and
  return true only when a row was changed, so exactly one of any number of concurrent redemptions of one code
  receives true.

#### Users: lookup and account fields

- `SPEC-7.3.301` `UserRepository::create` must insert the user with the email lowercased by `normalize_email`, so
  that is the single insert path and no mixed-case address is stored. A duplicate email must surface as the conflict
  error produced by the shared database-error mapping.
- `SPEC-7.3.302` `UserRepository::find_by_id`, `find_by_email`, `find_by_stripe_customer_id`, `find_by_id_batch`,
  `find_by_email_batch` and `find_by_id_for_update` must return only users with `deleted_at` NULL. Email matching
  must be case-insensitive.
- `SPEC-7.3.303` `UserRepository::find_by_id_batch` and `find_by_email_batch` must return an empty vector without
  querying for an empty input, and must return rows in no guaranteed order.
- `SPEC-7.3.304` `UserRepository::list_verified` must return users with `email_verified` true and `deleted_at` NULL
  ordered by `created_at` then `id` ascending.
- `SPEC-7.3.305` `UserRepository::email_exists` must return true when a user with `deleted_at` NULL has the email
  (case-insensitive), and `email_reserved` must return true when any user, deleted or not, has it, so a deleted
  account's email stays locked against re-registration. Both must accept any executor.
- `SPEC-7.3.306` `UserRepository::update_email` must write the email lowercased by `normalize_email` together with
  `email_verified` set to the `set_verified` argument, and accept any executor.
- `SPEC-7.3.307` `UserRepository::update_profile` must treat each of first name, last name and phone as three states
  resolved in the one `UPDATE`: outer `None` leaves the column unchanged, `Some(None)` sets NULL, `Some(Some(v))`
  writes `v` verbatim. It must update only a user with `deleted_at` NULL, return the updated row, and return
  `AppError::not_found("User")` when no such user exists.
- `SPEC-7.3.308` `UserRepository::set_avatar` must, in one transaction, upsert the user's `user_avatars` row (MIME type,
  size, bytes) and set `users.avatar_updated_at` for a user with `deleted_at` NULL, and return the updated user. It
  must return a validation error for field `avatar` ("Avatar is too large") when the data length does not fit in
  an `i32`, and `AppError::not_found("User")` (rolling back the avatar write) when no live user matched.
- `SPEC-7.3.309` `UserRepository::clear_avatar` must, in one transaction, delete the user's `user_avatars` row and set
  `users.avatar_updated_at` to NULL, returning the user, and must succeed when no avatar existed. It must return
  `AppError::not_found("User")` when no live user matched.
- `SPEC-7.3.310` `UserRepository::get_avatar` must return `Some((mime_type, bytes))` or `None` when the user has no
  avatar.
- `SPEC-7.3.311` `UserRepository::set_email_verified` and `set_email_verified_in` must set `email_verified` TRUE only
  on a user whose flag is FALSE and return true only when that transition happened, so a caller acts on the
  transition and not on every sign-in. `set_email_verified_in` must accept any executor.
- `SPEC-7.3.312` `UserRepository::update_password` must set `password_hash` and `updated_at` for the user id and
  return `Ok` even when no row matched.
- `SPEC-7.3.313` `UserRepository::update_last_login` must set `last_login_at` and `updated_at`.
  `set_last_login_country` must store the country (or NULL). `set_login_location_alerts` must set the flag only for a
  user with `deleted_at` NULL. None of the three fails when no row matched.
- `SPEC-7.3.314` `UserRepository::lock_for_update` must lock the user row with `SELECT ... FOR UPDATE` and return true
  when a row was locked and false when none exists, and `find_by_id_for_update` must lock and return the user only
  when `deleted_at` is NULL. Both must be called inside a transaction and accept any executor.

#### Users: membership and Stripe fields

- `SPEC-7.3.321` `UserRepository::update_membership_status` must set `membership_status` to the status's string form
  for the user id and accept any executor. `activate_membership` must set it to `active` for a user with `deleted_at`
  NULL, return the updated row, and return `AppError::not_found("User")` when none matched.
- `SPEC-7.3.322` `UserRepository::mark_trial_used` must set `has_used_trial` TRUE for the user id and accept any
  executor, and a repeated call must leave it TRUE without an error.
- `SPEC-7.3.323` `UserRepository::update_stripe_customer_id` must set `stripe_customer_id` and accept any executor.
  `update_stripe_registration_info` must set `stripe_customer_id` and `stripe_payment_method_id`. `lock_price` must
  set `price_locked` TRUE with the locked price id and amount.
- `SPEC-7.3.324` `UserRepository::set_grace_period` must set `grace_period_start` and `grace_period_end`, and
  `clear_grace_period` must set both to NULL. Both must accept any executor.
- `SPEC-7.3.325` `UserRepository::reset_membership_tier` must set `membership_tier` to `standard`, `lifetime_member`
  FALSE, and `trial_ends_at` and `membership_override_by` NULL for the user id, freeing the lifetime or early-adopter
  slot, and accept any executor.
- `SPEC-7.3.326` `UserRepository::upgrade_membership_tier` must set `membership_tier` to the tier's string form,
  `lifetime_member` to true exactly when the tier is `Lifetime` or `Free`, and `trial_ends_at` to NULL, without
  changing `membership_status`, and accept any executor.

#### Users: lifecycle, roles, tiers and listings

- `SPEC-7.3.331` `UserRepository::soft_delete` must set `deleted_at` and `updated_at` on the user id and return `Ok`
  even when no row matched. `restore` must clear `deleted_at` only on a soft-deleted user and return true only when a
  row was restored.
- `SPEC-7.3.332` `UserRepository::hard_delete`, `hard_delete_by_email`, `hard_delete_seed_users` and
  `hard_delete_stale_disposable` must each run in one transaction that first deletes the targets' `audit_logs` rows
  (by `actor_id`) and `admin_notifications` rows (by `user_id`), sets `admin_notifications.read_by` to NULL where it
  names a target, and then deletes the `users` rows, and must roll back everything on any failure. They are reserved
  for non-production test-data cleanup and must not be reachable from a production code path.
- `SPEC-7.3.333` `UserRepository::hard_delete` and `hard_delete_by_email` must return the number of user rows removed.
  `hard_delete_by_email` must match the exact email (including soft-deleted rows sharing it).
- `SPEC-7.3.334` `UserRepository::hard_delete_seed_users` and `list_seed_users` must match users whose lowercased
  email ends with `@` plus the lowercased domain by exact suffix comparison, not `LIKE`, so `_` or `%` in the domain
  cannot widen the match. `list_seed_users` must return only users with `deleted_at` NULL ordered by `email`.
- `SPEC-7.3.335` `UserRepository::hard_delete_stale_disposable` must select users whose email matches the `LIKE`
  pattern and whose `created_at` is older than `max_age_secs` before the transaction's timestamp, delete them, and
  return for each removed user `(id, email, email_verified, was_already_soft_deleted)` as read before the delete.
- `SPEC-7.3.336` `UserRepository::apply_seed_membership` must set `membership_status`, `membership_tier`,
  `lifetime_member`, `price_locked`, `locked_price_amount` and `trial_ends_at` for the user id in one statement. It is
  a seed-data shortcut and must not be used for production membership changes.
- `SPEC-7.3.337` `UserRepository::set_two_factor_enabled` must set `two_factor_enabled` only for a user with
  `deleted_at` NULL and return `Ok` even when no row matched.
- `SPEC-7.3.338` `UserRepository::update_role` and `set_super_admin` must update `role` or `is_super_admin` only for a
  user with `deleted_at` NULL, return the updated row, and return `AppError::not_found("User")` when none matched.
- `SPEC-7.3.339` `UserRepository::list_paginated` must return `per_page` users at offset
  `max(0, (page - 1) * per_page)` computed in 64-bit saturating arithmetic, and the total count of users matching the
  same filters, with every filter value bound as a parameter on both queries.
- `SPEC-7.3.340` `UserRepository::list_paginated` must apply `active` as `Some(true)` live users only, `Some(false)`
  soft-deleted users only and `None` both, and must apply, when supplied, a case-insensitive substring match of
  `search` on email, an exact `membership_status`, an exact tier compared as `COALESCE(membership_tier, 'standard')`,
  and an exact `email_verified`.
- `SPEC-7.3.341` `UserRepository::list_paginated` must order by a fixed expression chosen from `sort_by`:
  `email` is `LOWER(email)`, `tier` is `COALESCE(membership_tier, 'standard')`, `verified` is `email_verified`, and
  `joined`, absent or any other value is `created_at`. It must direction-order by `sort_desc` and always append `id`
  in the same direction as a tiebreak, and must never interpolate the raw `sort_by` value into the SQL.
- `SPEC-7.3.342` `UserRepository::assign_membership_tier` must set `membership_tier`, `lifetime_member` (true exactly
  for `Lifetime` and `Free`), `trial_ends_at` (now plus the tier's configured trial days, NULL when the tier has
  none) and `membership_status` `active`, and accept any executor. It must be called inside a transaction holding an
  advisory lock so concurrent verifications cannot race on the slot count.
- `SPEC-7.3.343` `UserRepository::admin_set_membership_tier` must, in one statement for a user with `deleted_at`
  NULL, set `membership_tier`, `lifetime_member`, `trial_ends_at` as in `assign_membership_tier`, set
  `membership_override_by` to the granting admin and `membership_status` to `active`, return the updated row, and
  return `AppError::not_found("User")` when none matched.
- `SPEC-7.3.344` `UserRepository::count_tier_assignments` must return `(lifetime_count, early_adopter_count)` as the
  number of users with `deleted_at` NULL whose `membership_tier` is `lifetime` or `early_adopter`, counting
  admin-granted and unverified users, and must not filter on `email_verified`.
- `SPEC-7.3.345` `UserRepository::grant_lifetime_membership` and `grant_free_membership` must set the tier to
  `lifetime` or `free`, `lifetime_member` TRUE, `trial_ends_at` NULL, `membership_override_by` to the granting admin and
  `membership_status` `active` for a user with `deleted_at` NULL, return the updated row, and return
  `AppError::not_found("User")` when none matched.
- `SPEC-7.3.346` `UserRepository::revoke_lifetime_membership` must, only for a user with `deleted_at` NULL and
  `lifetime_member` TRUE, set the tier to `standard`, `lifetime_member` FALSE, `trial_ends_at` and
  `membership_override_by` NULL and `membership_status` `none`, return the updated row, and return
  `AppError::not_found("Lifetime membership")` when none matched.
- `SPEC-7.3.347` `UserRepository::find_admin_emails` must return the emails of users with `role = 'admin'` and
  `deleted_at` NULL ordered by `created_at` ascending. `count_active_by_emails` must return the number of users with
  `deleted_at` NULL whose email equals one of the supplied emails exactly.
- `SPEC-7.3.348` `UserRepository::end_expired_grace_periods` must, in one conditional statement, set
  `membership_status` `canceled` and clear the grace-period start and end only for users whose status is
  `grace_period` and whose `grace_period_end` has passed, and return `(id, email, role)` of each user moved, so a
  concurrent payment that cleared the window or a concurrent sweep is not overwritten or repeated.
- `SPEC-7.3.349` `UserRepository::count_members_for_plan` must return the number of users with `deleted_at` NULL who
  either have `COALESCE(membership_tier, 'standard')` in the plan's tiers and `membership_status` in
  `PLAN_MEMBER_STATUSES` (`active`, `grace_period`, `past_due`), or have `locked_price_id` in the plan's price ids
  whatever their status, counting each user once.
- `SPEC-7.3.350` `UserRepository::plan_member_index` must group users with `deleted_at` NULL who are in a
  plan-member status or hold a `locked_price_id` by `(active_tier, locked_price_id)` with a count, where
  `active_tier` is the tier only for a plan-member status and NULL otherwise. `PlanMemberIndex::count_for` must sum
  the buckets whose active tier is one of the given tiers or whose locked price is one of the given price ids,
  counting each bucket once.

### 7.4 Domain middleware

- `SPEC-7.4.1` The `middleware` module must re-export `request_id`, `security_headers`, `CspConfig`,
  `RequestIdMiddleware` and `SecurityHeaders` from `dunite-core`, the `auth` extractors and helpers, and
  `AutoBanMiddleware`, `AutoBanService` and `BanInfo` from `auto_ban`, so `crate::middleware::<name>` paths resolve.
- `SPEC-7.4.2` `extract_token` must return the value of the `access_token` cookie when that cookie is present, even if
  it is invalid; otherwise the part after the case-sensitive prefix `Bearer ` of the `Authorization` header; otherwise
  `None`.
- `SPEC-7.4.3` `verify_once` must route a token whose JWT header `typ` is `at+jwt` (compared case-insensitively) to the
  registered `Arc<BunyipAtJwtVerifier>`, and every other token to the registered `Arc<JwtService>` HS256 verification;
  no code path other than `verify_once` may call the routing function.
- `SPEC-7.4.4` When an `at+jwt` token arrives and no `AtJwtVerifier` is registered, verification must fail with
  `AppError::Unauthorized` and log a debug line; `DisabledAtJwtVerifier` must reject every `at+jwt` with
  `Unauthorized`.
- `SPEC-7.4.5` When a non-`at+jwt` token arrives and no `JwtService` is registered, verification must log an error
  `JwtService not found in app data` and fail with an internal error `Authentication service not available`.
- `SPEC-7.4.6` `verify_once` must cache only successful verifications in the request extensions, keyed by the token,
  so a second verification of the same token in the same request is served from the cache, a different token is
  verified on its own, a failure is never cached, and nothing is carried to another request.
- `SPEC-7.4.7` `VerifiedIdentity.user` must be `Some` only on the `at+jwt` path (which reads the user row), and
  `request_user` must return that row only when an earlier `verify_once` in the same request succeeded for the same
  token, else `None`.
- `SPEC-7.4.8` `resolve_user_for_atjwt` must fail with `AppError::Unauthorized` when `sub` is not a UUID or no such user
  exists, and must propagate repository errors.
- `SPEC-7.4.9` `AccessTokenClaims::from_atjwt_and_user` must copy `sub`, `email`, `role`, `membership_status`,
  `price_locked`, `lifetime_member` from the user, `price_id` from `locked_price_id`, `trial_ends_at` and
  `grace_period_end` as Unix timestamps, and `iss`, `iat`, `exp`, `jti` from the token.
- `SPEC-7.4.10` `AuthenticatedUser` must fail with `AppError::Unauthorized` when no token is present and otherwise
  return the verified claims or the verification error unchanged.
- `SPEC-7.4.11` `OptionalUser` must never fail: it must yield `None` when no token is present, and `None` with a debug
  log naming the error and request path when a token is present but does not verify.
- `SPEC-7.4.12` `AdminUser` must fail with `AppError::Forbidden` (`403`) unless the verified claims' `role` is `admin`,
  and `MemberUser` must fail with `Forbidden` unless the claims grant member access.
- `SPEC-7.4.13` `is_verified` must be true only when both `first_name` and `last_name` are present and non-empty after
  trimming whitespace and `email_verified` is true.
- `SPEC-7.4.14` `VerifiedAdminUser` must apply the `AdminUser` check, then obtain the user row from the verification
  (or, on the HS256 path, from the database pool, failing with an internal error `Database pool not available` when
  no pool is registered and `Unauthorized` when the user is missing), and must refuse a user failing `is_verified`
  with `403` and a JSON error body whose `success` is `false`, `error.code` is `VERIFICATION_REQUIRED`, and
  `error.message` is `VERIFICATION_REQUIRED_MESSAGE`; every other failure must be answered as the underlying
  `AppError`.
- `SPEC-7.4.15` `super_admin_allowed` must be true only for role `admin` with `is_super_admin` true, and
  `SuperAdminUser` must fail with `Forbidden` otherwise, reading the flag per request from the verification's user row
  or, on the HS256 path, from the database (internal error `Database pool not available` when no pool is registered).
- `SPEC-7.4.16` `resolve_rate_limit_subject` must return the verified subject user id through `verify_once`, and
  `None` when no token is present or verification fails, so the caller falls back to the per-IP budget.
- `SPEC-7.4.17` `AuthCookies::access_token` must be named `access_token`, path `/`, `HttpOnly`, `SameSite=Lax`,
  `Secure` as given, `Max-Age` 30 minutes; `refresh_token` the same with name `refresh_token` and `Max-Age` 30 days
  when `remember` is true and 1 day otherwise; `trusted_device` the same with name `bunyip_trusted_device` and
  `Max-Age` 30 days; `op_session` the same with name `bunyip_op_session` and `Max-Age` 7 days; each with a `Domain`
  attribute only when a cookie domain is given.
- `SPEC-7.4.18` `AuthCookies::op_session_set` must return the domain-scoped `op_session` cookie preceded, when a cookie
  domain is given, by a no-domain `bunyip_op_session` cookie with an empty value and `Max-Age` 0; with no domain it
  must return only the set cookie.
- `SPEC-7.4.19` `AuthCookies::clear_op_session_only` must return a no-domain clear of `bunyip_op_session` plus, when a
  domain is given, a domain-scoped clear, and no other cookie.
- `SPEC-7.4.20` `AuthCookies::clear_stale` must return no-domain `Max-Age` 0 clears of `access_token`,
  `refresh_token` and `bunyip_op_session`, and `AuthCookies::clear` must return those plus, only when a domain is
  given, domain-scoped clears of the same three cookies.
- `SPEC-7.4.21` `extract_client_ip` must delegate to the `dunite-core` client-IP resolver with the `trusted_proxies`
  of the registered `Config` (an empty list when none is registered), so forwarding headers are honoured only when the
  socket peer is a trusted proxy and the socket address is used otherwise.
- `SPEC-7.4.22` `extract_device_info` must return the `User-Agent` header truncated to at most 256 bytes, and `None`
  when it is absent or not valid UTF-8.
- `SPEC-7.4.23` `SuspiciousPatterns::matches` must return true when the path equals (case-sensitive) one of
  `/server-info`, `/server-status`, `/xmlrpc.php`, `/database.yml`, `/secrets.json`, `/secrets.yml`, `/docker.sh`,
  `/Dockerfile`, `/package.json`, `/package-lock.json`, `/api/info`, `/api/config`, `/api/debug`, `/api/env`,
  `/graphql`, `/trace`, `/test`; starts with (case-sensitive) one of `/wp-`, `/wordpress/`, `/blog/wp-`, `/joomla/`,
  `/administrator/`, `/drupal/`, `/magento/`, `/downloader/`, `/cms/`, `/phpmyadmin/`, `/pma/`, `/myadmin/`, `/mysql/`,
  `/dbadmin/`, `/phpMyAdmin/`, `/aws-credentials`, `/credentials`, `/config.php`, `/api/swagger`, `/swagger`,
  `/api-docs`, `/actuator`, `/jolokia/`, `/console/`, `/manager/`, `/host-manager/`, `/debug`, `/dump`,
  `/node_modules/`, `/test/`, `/tmp/`, `/backup/`, `/backups/`, `/src/`; contains `../`; or, compared on the
  ASCII-lowercased path, ends with one of `.php`, `.phtml`, `.phar`, `.asp`, `.aspx`, `.ashx`, `.asmx`, `.jsp`,
  `.jspx`, `.do`, `.action`, `.cgi`, `.pl`, `.cfm`, `.cfc`, `.bak`, `.backup`, `.save`, `.old`, `.orig`, `.swp`,
  `.tmp`, `.sql`, `.sql.gz`, `.log`, `.conf`, `.ini`, `.yml`, `.yaml`, `.toml`, `.xml`, `.sh`, `.bash`, `.bat`,
  `.cmd`, `.tar`, `.tar.gz`, `.tgz`, `.zip`, `.rar`, `.7z`, `.gz`, `.bz2`; otherwise false.
- `SPEC-7.4.24` `AutoBanService::is_banned` must return true only for an IP with an unexpired ban entry
  (`now < expires_at`), and must evict an expired entry it finds and return false.
- `SPEC-7.4.25` `record_strike` must reset an IP's strike count to zero with `first_seen` = now when more than
  `window_secs` have elapsed since `first_seen`, then increment it; when the count reaches `threshold` it must remove
  the strikes, insert an in-memory ban expiring at now + `ban_duration_secs` with the reason
  `Auto-banned after {count} suspicious requests (last: {path})`, log a warning `IP auto-banned`, and return `true`;
  otherwise it must return `false`.
- `SPEC-7.4.26` On a newly created automatic ban, `record_strike` must persist the ban to `ip_bans` from a spawned
  task with `strikes` = the configured threshold, and a persistence failure must be logged at error level naming the
  IP and must not undo the in-memory ban.
- `SPEC-7.4.27` Persisting a ban must upsert into `ip_bans` keyed by `ip_address`, replacing `reason`, `strikes` and
  `expires_at` and setting `banned_at` to now on conflict.
- `SPEC-7.4.28` `AutoBanService::ban` must insert the in-memory ban (replacing any existing entry) and clear the IP's
  strikes before persisting to `ip_bans` synchronously with `strikes` 0, return the expiry on success, log a warning,
  and return the database error to the caller on failure while leaving the in-memory ban in force.
- `SPEC-7.4.29` `AutoBanService::unban` must remove the in-memory ban and clear the strikes before deleting the
  `ip_bans` row, return `true` when a ban existed in memory or a row was deleted and `false` otherwise, and return the
  database error to the caller while the in-memory removal still holds.
- `SPEC-7.4.30` `list_bans` must return the unexpired `ip_bans` rows merged with unexpired in-memory entries, one entry
  per IP with the database row taking precedence; a memory-only entry must report `strikes` = the configured threshold
  and `banned_at` = `expires_at` - `ban_duration_secs`; `strikes` from a row must be clamped at zero; a database error
  must be returned. `BanInfo` must serialize `ip` as a string and the timestamps as RFC 3339.
- `SPEC-7.4.31` `load_bans` must insert every given row into the in-memory map (replacing existing entries) and log the
  resulting count; `load_active_bans` must select the rows with `expires_at > now`; `cleanup_expired_bans` must delete
  rows with `expires_at < now` and return the number deleted.
- `SPEC-7.4.32` `cleanup_expired` must remove expired in-memory bans and strike entries whose `first_seen` is older
  than `window_secs`; `reload` must replace the thresholds so that they apply from the next request or strike, without
  altering existing bans.
- `SPEC-7.4.33` `AutoBanMiddleware` must, for a request whose client IP resolves, answer `403` with an empty body when
  the IP is banned, whether or not automatic banning is enabled; and must forward a request whose client IP does not
  resolve to the inner service without any ban check.
- `SPEC-7.4.34` When the IP is not banned, automatic banning is enabled and the request path is suspicious,
  `AutoBanMiddleware` must record a strike, log at info level whether it triggered a ban or only a strike, and answer
  `403` with an empty body without calling the inner service; every other request must be forwarded.

## 8. Domain crate services

### 8.1 Argon2 offload

- `SPEC-8.1.1` Every password hash and verify on a request path must run through `argon2_offload::offload`, which runs the
  closure on the blocking pool gated by the shared concurrency semaphore of `dunite_argon2_offload`, and must return the
  closure's own `Result<T, AppError>` unchanged when the closure runs.
- `SPEC-8.1.2` When the semaphore permit is not obtained within the permit timeout, `offload` must return
  `AppError::internal("Password hashing is overloaded")`; when the blocking task fails to join (including a panic), it
  must return `AppError::internal("Password hashing task failed")`. Neither failure may be mapped to `Ok(false)` on the
  verify path.
- `SPEC-8.1.3` `hash_password` must call `PasswordService::hash` and `verify_password` must call `PasswordService::verify`
  through `offload`, with the operation labels `"hash"` and `"verify"`.
- `SPEC-8.1.4` The concurrency ceiling and permit timeout must be read from `DUNITE_ARGON2_MAX_CONCURRENT` (default 32)
  and `DUNITE_ARGON2_PERMIT_TIMEOUT_SECS` (default 5); the former names `ARGON2_MAX_CONCURRENT` and
  `ARGON2_PERMIT_TIMEOUT_SECS` must not be honoured.

### 8.2 Realtime events

- `SPEC-8.2.1` `services::EventBus` must be an alias of `dunite_events::EventBus<BunyipEvent>`; the bus must deliver an
  event with a target user to that user's channel and an event with no target user to every subscriber.
- `SPEC-8.2.2` `BunyipEvent` must serialize as a JSON object whose `type` field is the snake_case variant name, and the SSE
  `event:` name returned by `SseEvent::name` must equal that same string: `claims_changed`, `profile_changed`,
  `applications_changed`, `session_revoked`, `account_deleted`.
- `SPEC-8.2.3` `SseEvent::target_user` must return the carried `user_id` for `ClaimsChanged`, `ProfileChanged`,
  `SessionRevoked` and `AccountDeleted`, and `None` for `ApplicationsChanged` (the only global event).
- `SPEC-8.2.4` `SessionRevoked` must carry a `reason` that is a static machine-readable string (for example
  `admin_revoke`, `logout_all`, `role_change`); display text must not be carried in the event.

### 8.3 GeoIP resolution

- `SPEC-8.3.1` `services::GeoIpService` and `GeoIpError` must be re-exports of `dunite_geoip`; `GeoIpService::new` must
  return `GeoIpError`, not `AppError`.
- `SPEC-8.3.2` Country lookups must read only the local IP2Location LITE database and must not call an external service or
  send the client IP to a third party.
- `SPEC-8.3.3` A database country code or name that is blank or `"-"` must resolve to `None`, never to a country.

### 8.4 Infisical secret client

- `SPEC-8.4.1` `InfisicalClient::from_settings` must return `None` when any of `address`, `project_id`, `environment`,
  `client_id` or `client_secret` is empty, and otherwise a client; it must not read the `enabled` flag.
- `SPEC-8.4.2` The client must trim trailing `/` characters from `address`, default an empty `secret_path` to `/`, and use
  a 5 second timeout on every HTTP request.
- `SPEC-8.4.3` Every operation must first log in with `POST {address}/api/v1/auth/universal-auth/login` and a JSON body
  `{"clientId", "clientSecret"}`; a transport error, a non-2xx status, or an unparsable body must return
  `InfisicalError::Login` carrying the cause (the status line and URL, or the parse error).
- `SPEC-8.4.4` `fetch_secret` must `GET {address}/api/v3/secrets/raw/{name}` with the bearer token and the query
  parameters `workspaceId`, `environment` and `secretPath`, and return `Ok(Some(secretValue))` on success.
- `SPEC-8.4.5` `fetch_secret` must return `Ok(None)` only for HTTP 404; a transport error must return
  `InfisicalError::Request`, any other non-2xx status must return `InfisicalError::Status { secret, status, body }`, and
  an unparsable 2xx body must return `InfisicalError::Parse { secret, source }`. No failure may be collapsed into `None`.
- `SPEC-8.4.6` `upsert_secret` must send a PATCH with the v3 raw write body (`workspaceId`, `environment`, `secretPath`,
  `secretValue`); on HTTP 404 only, it must send a POST with the same body; any other non-2xx status from either call must
  return `InfisicalError::Status`, and a transport error must return `InfisicalError::Request`.
- `SPEC-8.4.7` `delete_secret` must send `DELETE` with a JSON body of `workspaceId`, `environment` and `secretPath`, and
  must treat 2xx and 404 as success (idempotent); any other status must return `InfisicalError::Status`.
- `SPEC-8.4.8` An error body placed in `InfisicalError::Status` must be trimmed and, when longer than 300 characters,
  cut to 300 characters followed by `...`; it must not be dropped.

### 8.5 Account backup creation

- `SPEC-8.5.1` An account backup must be a single JSON document with `format_version` (currently 1), `created_at` (the
  caller-supplied time), `account.profile` (`email`, `first_name`, `last_name`, `phone`), `account.entitlements` (the
  entitled app slugs) and `apps` (one section per entitled slug, in entitlement order); it must exclude platform-wide
  singleton settings.
- `SPEC-8.5.2` `create_backup` must load the owner profile and then the entitlement slugs from the store, and must return
  the store's error (a missing user is `AppError::not_found("User")`) without producing a partial bundle.
- `SPEC-8.5.3` For an entitled slug with no registered adapter, `create_backup` must emit a section with status
  `skipped`, reason `no backup adapter for this app` and no `bundle`.
- `SPEC-8.5.4` For an entitled slug whose adapter produces a payload, `create_backup` must emit status `included` with the
  payload as `bundle`; when the adapter reports `Unavailable(reason)`, it must emit status `unavailable` with that reason
  and no `bundle`; when the adapter returns an error, `create_backup` must fail with that error.
- `SPEC-8.5.5` `BackupService::new` must key adapters by `AppBackupAdapter::slug()`; when two adapters share a slug, the
  later one must replace the earlier.
- `SPEC-8.5.6` The pending adapter for slug `mokosh` must report `Unavailable("Mokosh backup API not yet available")` on
  backup and `Ok(false)` on restore.
- `SPEC-8.5.7` `PgAccountBackupStore` must read the profile via the user repository, the slugs via the entitlement
  repository, and must report `AppError::not_found("Application")` when a grant names a slug with no application row.

### 8.6 Account restore

- `SPEC-8.6.1` `restore_backup` must reject a bundle whose `format_version` is not 1 with a validation error on field
  `format_version` and message `unsupported backup format_version {n} (expected 1)`, before any write.
- `SPEC-8.6.2` `restore_backup` must overwrite the owner's `first_name`, `last_name` and `phone` from the bundle and must
  not change the account email.
- `SPEC-8.6.3` `restore_backup` must, for each bundle entitlement slug in order, grant the entitlement (attributed to the
  acting admin) only when an application with that slug exists, and must list exactly the granted slugs in
  `entitlements_granted`; a slug with no application must not be granted and must not appear in the report.
- `SPEC-8.6.4` For each app section in order, restore must emit exactly one outcome: `skipped` with reason
  `account not entitled to this app` when the slug is not in `entitlements_granted`; else `skipped` with reason
  `no backup adapter for this app` when no adapter is registered; else `skipped` with reason
  `no bundle captured for this app` when the section has no bundle; else `restored` when the adapter returns `true`, or
  `skipped` with reason `app backup backend not available yet` when it returns `false`.
- `SPEC-8.6.5` Any store or adapter error during restore must abort the restore and be returned to the caller; the report
  must not be returned, and earlier writes are not rolled back.
- `SPEC-8.6.6` A successful restore must return `profile_restored: true` together with `entitlements_granted` and the
  per-app outcomes.

### 8.7 Sessions, token minting and refresh

- `SPEC-8.7.1` The absolute refresh-session lifetime must be 30 days when the sign-in chose "remember me" and 1 day
  otherwise, uniform across roles, and must be fixed at login and carried unchanged across refresh rotation.
- `SPEC-8.7.2` `create_tokens` must mint an access token and a refresh token, store the refresh token hash with the device
  info, client IP and expiry, use the carried deadline as expiry or one day from now when none is carried, and return
  `expires_in` 900 seconds.
- `SPEC-8.7.3` `refresh_tokens` must verify the refresh token signature first and, on failure, log a warning and return
  the verification error.
- `SPEC-8.7.4` When no valid stored row matches the token hash, `refresh_tokens` must return `AppError::InvalidCredentials`
  after logging a warning that says whether the hash is revoked/expired, absent, or whether the diagnostic query failed.
- `SPEC-8.7.5` When the stored row exists but is not valid, `refresh_tokens` must log a warning and return
  `AppError::TokenExpired`; when the user no longer exists it must return `AppError::InvalidCredentials`.
- `SPEC-8.7.6` For a refresh token linked to an op-session, `refresh_tokens` must read, liveness-check and idle-slide the
  op-session row inside one SERIALIZABLE transaction with `SELECT ... FOR UPDATE`.
- `SPEC-8.7.7` In that transaction, a missing session row, a serialization failure (SQLSTATE 40001), or a session that
  `check_op_session_alive` reports revoked, past its absolute deadline or past its idle deadline must return
  `AppError::InvalidCredentials`; any other database error must return `AppError::internal`.
- `SPEC-8.7.8` On a live op-session, `refresh_tokens` must set `idle_expires_at` to the lesser of now plus the session's
  `idle_ttl_seconds` and the session's `expires_at`, update `last_active_at`, and cap the new refresh expiry at the
  session's `expires_at`.
- `SPEC-8.7.9` `refresh_tokens` must revoke the presented refresh token, mint new tokens carrying the old token's expiry
  (capped as above) so the ceiling never rolls forward, and relink the new refresh token to the same op-session; a relink
  failure must be logged as a warning and must not fail the refresh.
- `SPEC-8.7.10` `logout` must revoke the refresh token by hash and write a `UserLogout` audit entry when the user exists;
  `logout_all` must revoke all of the user's refresh tokens and all trusted devices and write a `UserLogout` audit entry
  with `all_sessions: true`.
- `SPEC-8.7.11` `link_refresh_token_to_op_session` must hash the raw refresh token with the service's token hash and bind
  that row to the given op-session; `hash_token` must expose the same hash used for stored tokens.

### 8.8 Country allow/deny gate

- `SPEC-8.8.1` `country_blocked` must trim the country, refuse it when it matches any `deny` entry, and otherwise refuse it
  when `allow` is non-empty and has no matching entry; matching must be ASCII case-insensitive, and deny must win over
  allow.
- `SPEC-8.8.2` A client IP must resolve to no country when there is no geoip service, no IP, or the IP is private,
  loopback, link-local or unspecified.
- `SPEC-8.8.3` With neither list configured, the gate must admit everyone and log nothing; with a resolved country that
  `country_blocked` refuses, it must log a warning naming the country and return `AppError::Forbidden`.
- `SPEC-8.8.4` With an unresolved country and a non-empty allow list, the gate must log a warning and return
  `AppError::Forbidden`; with an unresolved country and only a deny list, it must log a warning and admit.
- `SPEC-8.8.5` `register`, `login` and `verify_magic_link` must call the gate before any credential check, token claim or
  row write, so a refusal never consumes a single-use token; `complete_2fa_login`, `complete_login_approval` and
  `refresh_tokens` inherit the decision of the request that began the sign-in.
- `SPEC-8.8.6` `country_name_for_ip` must return the long country name for a public IP and `None` when there is no
  geoip service, no IP, or a non-public IP.

### 8.9 Registration and signup bot guard

- `SPEC-8.9.1` `create_signup_challenge` must mint a signup challenge token valid for 30 minutes.
- `SPEC-8.9.2` `verify_signup_not_bot` must fail when the honeypot is present and non-blank after trim, when the token is
  missing, forged, wrong-purpose or expired, or when the token was issued less than 2 seconds before the submit; every
  failure must return the same `AppError::bad_request` with message
  `We couldn't complete your registration. Please reload the page and try again.`
- `SPEC-8.9.3` `verify_signup_challenge` must verify signature, issuer, purpose and expiry only (no minimum fill time) and
  return the same uniform bad-request error on any failure.
- `SPEC-8.9.4` `register` must run, in order: country gate; password strength; password not containing the email;
  breached-password check (validation error on field `password`, message
  `Password has appeared in a known data breach - pick a different one.`); soft-delete-aware email reservation check
  (`AppError::conflict("Email already registered")`); Argon2 hash through the offload; creation as a subscriber;
  bootstrap-admin promotion; a `UserRegistered` audit entry with the client IP.
- `SPEC-8.9.5` `register` must not depend on the email service, so account creation succeeds when email is unconfigured.

### 8.10 Password login, second factor and trusted devices

- `SPEC-8.10.1` `login` must return `AppError::InvalidCredentials` identically for an unknown email, a deleted user, a user
  with no password hash, and a wrong password, after the country gate has passed.
- `SPEC-8.10.2` `login` must promote the bootstrap admin only after the password has verified and before any second-factor
  branch or token mint.
- `SPEC-8.10.3` When `two_factor_enabled` is set and a verified TOTP record exists, `login` must either complete via the
  trusted-device skip (SPEC-8.10.4) or return `TwoFactorRequired` with a challenge token that carries the `remember`
  choice and mint no session tokens.
- `SPEC-8.10.4` The trusted-device skip must apply only when the presented cookie hash matches a valid (not revoked, not
  expired) device row owned by the same user and the user's role is `subscriber`; it must then touch the device's
  last-used time, mint tokens, update last login, run the location check and write a `UserLogin` audit entry with method
  `trusted_device`. Admins must never skip the second factor.
- `SPEC-8.10.5` When `two_factor_enabled` is set but no verified TOTP record exists, `login` must set the flag to false and
  continue the login without a challenge.
- `SPEC-8.10.6` A successful non-challenged `login` must mint tokens with the deadline from `remember`, update last login,
  run the location check, record the login device when the approval gate is enabled, and write a `UserLogin` audit entry
  with the device info.
- `SPEC-8.10.7` `complete_2fa_login` must verify the challenge token, return `InvalidCredentials` for a missing or deleted
  user, mint tokens with the deadline from the challenge's `remember`, update last login, run the location check and
  write a `UserLogin` audit entry with method `2fa`; it does not verify a second factor itself, so its caller must have
  verified the TOTP or recovery code first.
- `SPEC-8.10.8` `complete_2fa_login` must create a trusted device and return its secret only when `remember` is set and the
  user is a subscriber, and must return the `remember` value to the caller.
- `SPEC-8.10.9` `issue_trusted_device` must generate a 32-byte random secret, store only its hash, set the expiry to 30
  days after creation without extension on use, and return the raw secret; `revoke_trusted_devices` must revoke all of
  the user's trusted devices.
- `SPEC-8.10.10` `generate_secure_token(n)` must return the unpadded URL-safe base64 encoding of `n` cryptographically
  random bytes.

### 8.11 Suspicious-login approval

- `SPEC-8.11.1` The approval gate must run only when `login_approval_enabled` is set, only for logins that are not
  challenged for a second factor, and must withhold all session tokens when the login is flagged.
- `SPEC-8.11.2` `assess_login` must flag a login when the resolved country differs from the user's last login country, or
  when a non-blank device id hashes to a device not yet recorded for the user while the user already has at least one
  recorded device.
- `SPEC-8.11.3` A blank or whitespace-only device id must be treated as no device id; a failed device lookup must log a
  warning and not flag on the device signal.
- `SPEC-8.11.4` `begin_login_approval` must create a challenge token carrying `remember`, generate a uniformly random
  6-digit zero-padded code, store its hash with the challenge id, country, IP, device hash, device info and a 15 minute
  expiry, and email the code.
- `SPEC-8.11.5` When sending the approval email fails, `begin_login_approval` must log a warning and return an upstream
  error with message `Could not send your sign-in approval code. Please try again.`, and must not return a challenge
  token.
- `SPEC-8.11.6` `complete_login_approval` must verify the challenge token, find the unexpired unused code row by the
  token's id, and return `InvalidCredentials` when none exists or when the row already has 5 or more failed attempts.
- `SPEC-8.11.7` `complete_login_approval` must strip spaces and surrounding whitespace from the submitted code, compare its
  hash to the stored hash in constant time, and on a mismatch increment the attempt counter atomically with a cap of 5
  and return a validation error on field `code` with message `Invalid approval code`.
- `SPEC-8.11.8` On a matching code, `complete_login_approval` must claim the row atomically (single use, cap re-asserted)
  and return `InvalidCredentials` when the claim is lost, so exactly one login completes per challenge.
- `SPEC-8.11.9` After a claimed approval, `complete_login_approval` must mint tokens with the deadline from the challenge's
  `remember`, update last login, write a `UserLogin` audit entry with method `login_approval`, and persist the approved
  country and device as the new baseline; a baseline write failure must be logged as a warning and must not fail the
  login.
- `SPEC-8.11.10` `record_login_device` must do nothing without a device hash and must log a warning, without failing the
  caller, when the write fails.

### 8.12 New-login-location alert

- `SPEC-8.12.1` `check_login_location` must do nothing when there is no geoip service, no IP, a non-public IP, or no
  resolvable country, and must never fail the login it follows.
- `SPEC-8.12.2` When the user has no recorded country, `check_login_location` must record the country without alerting;
  when the country is unchanged it must do nothing.
- `SPEC-8.12.3` When the country changed, `check_login_location` must email the new-sign-in alert (country, IP, a
  `%Y-%m-%d %H:%M UTC` timestamp, and the device info or `unknown`) only when the user's `login_location_alerts` is on,
  log the change, and persist the new country; each send or write failure must be logged as a warning.
- `SPEC-8.12.4` The location check must run after a successful password login, trusted-device login, completed 2FA login,
  magic-link login and admin-invite acceptance.

### 8.13 Magic link

- `SPEC-8.13.1` `request_magic_link` must generate a 32-byte random token, store only its hash with a 15 minute expiry and
  the client IP, return the raw token, and give the same result whether or not the email belongs to a user.
- `SPEC-8.13.2` `request_magic_link` must write a `MagicLinkRequested` audit entry with `email_known` true or false; a
  failure to write it must be logged at error level and must not fail the request.
- `SPEC-8.13.3` `verify_magic_link` must run the country gate first, return `InvalidCredentials` for an unknown token hash
  and `TokenExpired` for an invalid token, and then claim the token with a guarded atomic update, returning
  `InvalidCredentials` when the claim is lost.
- `SPEC-8.13.4` For an existing user `verify_magic_link` must mark the email verified (notifying the account-change sync
  only when newly verified); for an unknown email it must refuse with `AppError::conflict("Email already registered")`
  when the email is reserved by a soft-deleted account, and otherwise create a passwordless subscriber with a verified
  email and report `is_new_user` true.
- `SPEC-8.13.5` With a verified TOTP record, `verify_magic_link` must return `TwoFactorRequired` with a challenge for a
  1-day session; with the flag set and no verified TOTP it must set the flag to false and continue.
- `SPEC-8.13.6` The approval gate must apply to magic-link logins with `remember` false, returning `ApprovalRequired`.
- `SPEC-8.13.7` A clean magic-link login must mint tokens with the default 1-day deadline, update last login, run the
  location check, record the device when the gate is enabled, and write a `MagicLinkUsed` audit entry.

### 8.14 Password reset and change

- `SPEC-8.14.1` `request_password_reset` must return `Ok(None)` for an unknown email and for an account with no password,
  and otherwise revoke the user's pending reset tokens, store a new token hash with a 1 hour expiry and the client IP,
  write a `PasswordResetRequested` audit entry, and return the raw token.
- `SPEC-8.14.2` `verify_reset_token` must return `InvalidCredentials` for an unknown token, `TokenExpired` for an invalid
  one, and the owning user id otherwise, without consuming the token.
- `SPEC-8.14.3` `complete_password_reset` must check password strength, the breached-password list (validation error on
  field `new_password`), the token, the password not containing the user's email, hash the password, claim the token with
  a guarded update before writing the password (returning `InvalidCredentials` when the claim is lost), update the
  password, revoke all refresh tokens and trusted devices, write a `PasswordResetCompleted` audit entry, and return the
  user's email.
- `SPEC-8.14.4` `change_password` must return a validation error on field `password` (`No password set for this account`)
  when the user has no password, and on field `current_password` (`Current password is incorrect`) when the current
  password does not verify.
- `SPEC-8.14.5` `change_password` must check strength, the password not containing the email and the breached-password list
  (field `new_password`), then update the password, revoke all refresh tokens and trusted devices, and write a
  `PasswordChanged` audit entry.

### 8.15 Email change and email verification

- `SPEC-8.15.1` Resend rate limiting for email verification and email change must allow at most `RESEND_LIMIT_MAX` (3)
  requests per rolling `RESEND_LIMIT_WINDOW_SECS` (3600) seconds; the next request must be refused with
  `AppError::RateLimited { retry_after }` and an error-level log with `category = "rate_limit"`, the user id and the
  action (`email_change_resend` or `email_verify_resend`).
- `SPEC-8.15.2` `retry_after` must equal oldest in-window request time plus the window minus now, in seconds, never less
  than 1.
- `SPEC-8.15.3` `request_email_change` must refuse a new email equal (case-insensitive) to the current one with a
  validation error on field `email`, refuse a reserved or taken email (including soft-deleted accounts) with
  `AppError::conflict("Email already registered")`, and, when the user has a password, require the current password
  (validation errors on field `current_password`: `Password is required to change email`, `Current password is
  incorrect`).
- `SPEC-8.15.4` For a verified user, `request_email_change` must apply the rate limit, cancel pending change requests,
  store a new request hash with a 1 hour expiry, write an `EmailChangeRequested` audit entry, and return the old email and
  the raw token.
- `SPEC-8.15.5` For an unverified user, `request_email_change` must, in one transaction holding the user row lock,
  re-check reservation, set the new email as unverified and revoke all refresh tokens, then write an
  `EmailChangeCompleted` audit entry with `immediate: true`, and return the old email with no token.
- `SPEC-8.15.6` `confirm_email_change` must return `InvalidCredentials` for an unknown token and `TokenExpired` for an
  invalid one; then, in one transaction holding the user row lock, re-check reservation (conflict error), set the email
  verified, confirm the request and revoke all refresh tokens; after commit it must notify the account-change sync and
  write an `EmailChangeCompleted` audit entry, and return the old and new email.
- `SPEC-8.15.7` `request_email_verification` must return a validation error on field `email` (`Email is already verified`)
  for a verified user, apply the rate limit, store a new token hash with a 1 hour expiry, write an
  `EmailVerificationRequested` audit entry, and return the raw token.
- `SPEC-8.15.8` `confirm_email_verification` must return `InvalidCredentials` for an unknown token and `TokenExpired` for
  an invalid one, claim the token inside the same transaction as the email-verified write (returning `InvalidCredentials`
  when the claim is lost), notify the account-change sync only when the email was newly verified, write an
  `EmailVerified` audit entry, and then attempt the initial tier grant.
- `SPEC-8.15.9` `confirm_email_verification` must return the user id, the email, and `Some(tier)` only when this call
  performed the tier grant.

### 8.16 Initial membership tier grant

- `SPEC-8.16.1` `maybe_grant_initial_tier` must grant only when the email is verified and both first and last names are
  non-empty after trim, and must return `Ok(None)` otherwise.
- `SPEC-8.16.2` It must be idempotent: it must return `Ok(None)` when the user is a lifetime member, has a trial end date,
  or has a tier other than `standard`, checked once before and once again under the lock.
- `SPEC-8.16.3` The grant must run in a transaction holding the advisory lock `pg_advisory_xact_lock(9999999)` and a row
  lock on the user, count current lifetime and early-adopter assignments, choose the tier with `MembershipTier::select`
  from the configured slot counts, and assign it with the configured early-adopter and standard trial days.
- `SPEC-8.16.4` After commit it must write an `InitialTierGranted` audit entry whose metadata holds `trigger`
  (`email_verified` or `profile_completed`), `membership_tier`, `trial_days` and `trial_label`, and return `Some(tier)`.
- `SPEC-8.16.5` `reload_tier_config` must replace the shared tier configuration used by subsequent grants.

### 8.17 Bootstrap admin and admin invites

- `SPEC-8.17.1` `bootstrap_promotion_needed` must be true only when a bootstrap email is configured, it equals the user's
  email case-insensitively, the user is not already an admin, and no admin exists.
- `SPEC-8.17.2` `ensure_bootstrap_admin` must query for existing admins only for the unpromoted bootstrap-email user; on
  promotion it must set the role to admin, set the super-admin flag, log the user id (not the email) at info level, update
  the in-memory user, and return true.
- `SPEC-8.17.3` `create_admin_invite` must refuse an existing admin with `AppError::conflict("User is already an admin")`,
  revoke pending invites for the email, store a new invite with role `admin` and a 7 day expiry, write an
  `AdminInviteCreated` audit entry, and return the raw token.
- `SPEC-8.17.4` `accept_admin_invite` must return `InvalidCredentials` for an unknown token and `TokenExpired` for an
  invalid one, and `AppError::conflict("User is already an admin")` when the invited user is already an admin.
- `SPEC-8.17.5` For an existing non-admin user, `accept_admin_invite` must mark the invite accepted, set the role to admin,
  mark the email verified, mint tokens with the default deadline, update last login, run the location check, and write an
  `AdminInviteAccepted` audit entry with `existing_user: true` and the previous role.
- `SPEC-8.17.6` For a new user, `accept_admin_invite` must refuse a soft-deleted reserved email with a conflict error;
  return `PasswordRequired { email }` without consuming the invite when no password is supplied; otherwise check strength,
  the password not containing the email and the breached-password list (field `password`), hash it, create an admin with a
  verified email, mark the invite accepted, mint tokens, and write an `AdminInviteAccepted` audit entry with
  `existing_user: false`.
- `SPEC-8.17.7` `revoke_admin_invite` must mark the invite revoked and write an `AdminInviteRevoked` audit entry.

### 8.18 Email transport and send policy

- `SPEC-8.18.1` `build_transport` must return no transport when email is disabled; otherwise it must build an SMTP relay
  with the configured host, port and credentials, implicit TLS or STARTTLS per `smtp_tls`, announce the configured EHLO
  name, and log that name; a relay or TLS parameter build failure must return `AppError::internal` with
  `SMTP connection error: ...` or `TLS error: ...`.
- `SPEC-8.18.2` `reload` must build the new transport before swapping, replace transport and config together, and, when the
  build fails, return the error and leave the previous transport and config in place.
- `SPEC-8.18.3` A failed transport send must return `AppError::internal` whose message names the relay host and port, TLS
  mode, username, EHLO name and the underlying error, and must never contain the SMTP password.
- `SPEC-8.18.4` `send_email` must, in order: return an internal error `Suppression store unavailable: ...` when the
  suppression list cannot be read; skip a suppressed recipient with a warning and `Ok(())`; skip an RFC 2606 / RFC 6761
  reserved recipient with an info log naming only the domain and `Ok(())`; log an info line and return `Ok(())` without
  sending when there is no transport; otherwise build, log and send the message and return any send error.
- `SPEC-8.18.5` `is_reserved_recipient` must be true when the part after the last `@`, lowercased with one trailing dot
  trimmed, equals or ends with `.test`, `.invalid`, `.example` or `.localhost`, or equals `example.com`, `example.net` or
  `example.org`; it must be false for an address with no `@` or an empty domain.
- `SPEC-8.18.6` `build_message` must set `From` to `from_name <from_email>`, exactly one `Message-ID` of the form
  `<uuid@domain>` with `domain` taken from `from_email` (a built-in fallback when empty), `Reply-To` from
  `support_inbox_email` when set, `In-Reply-To` and `References` when supplied, and a multipart alternative body with the
  plain-text part before the HTML part; an unparsable address must return `AppError::internal`.
- `SPEC-8.18.7` `send_relay` must always use the configured sending identity as `From`, and when email is disabled or the
  transport is unbuilt it must log an error and return an upstream error `The mailer relay has no SMTP transport
  configured, so no message was sent.`.
- `SPEC-8.18.8` `send_relay` must, after that check, return a bare Message-ID without sending when the recipient is
  reserved; refuse an unparsable recipient with a validation error on field `to`; and otherwise send a text-only or
  text-plus-HTML message and return the bare Message-ID.
- `SPEC-8.18.9` `send_support_reply` must return `AppError::internal("email is disabled; support replies cannot be sent")`
  when email is disabled or unbuilt, return a validation error on field `to` for a suppressed recipient and for a
  reserved recipient, thread the reply with the supplied `In-Reply-To` and `References`, and return the bare Message-ID.
- `SPEC-8.18.10` `send_test_message` must return `AppError::internal("Email sending is disabled, so no test message was
  sent.")` when email is disabled or the transport is unbuilt, and otherwise send the `smtp_test` template (carrying the
  SMTP host and the UTC send time) through `send_email`.
- `SPEC-8.18.11` The product name in subjects and templates must come from the branding cache when one is attached and from
  `EmailConfig.app_name` otherwise; with no suppression list attached nothing is suppressed.
- `SPEC-8.18.12` `EmailService::new` must register the base layout and every transactional template (HTML and text), and a
  template parse failure must fail construction with `AppError::internal("Template error: ...")`; `new_capturing` must not
  be called by either binary.

### 8.19 Transactional senders and SMTP test

- `SPEC-8.19.1` Every template sender must, when email is disabled, send nothing, log at info level and return `Ok(())`;
  `send_admin_feedback_notification` must also skip, with an info log, when the recipient list is empty.
- `SPEC-8.19.2` Every sender that carries a single-use token, link or code (magic link, password reset, email change
  verify, email verify, admin invite, login approval) must not log that credential at info level when email is disabled,
  and may log the link or code only at debug level when `log_tokens` is set.
- `SPEC-8.19.3` Link-bearing emails must use these paths under `base_url`: `/magic-link?token=`,
  `/password-reset/confirm?token=`, `/settings/confirm-email?token=`, `/settings/verify-email?token=` and
  `/invite/accept?token=`.
- `SPEC-8.19.4` Subjects must be: `Sign in to {app}`, `Reset your {app} password`, `Welcome to {app}!` (account created and
  welcome), `Your {app} password was changed`, `New sign-in to your {app} account`, `Approve your sign-in to {app}`,
  `Action required: Payment failed`, `Only {n} days left to update payment`, `Your {app} membership has been canceled`,
  `Verify your new {app} email address`, `Your {app} email address was changed`, `Verify your {app} email address`,
  `Payment received - {app}`, `New feedback received - {app}`, `Response to your feedback - {app}`,
  `You've been invited to join {app} as an admin`, `{app} SMTP test message`.
- `SPEC-8.19.5` The password-reset email must show the request country only when one is provided; the login-approval email
  must state a 15 minute lifetime, equal to the approval code expiry.
- `SPEC-8.19.6` Amounts and prices in welcome and payment-succeeded emails must be rendered as cents divided by 100 with two
  decimals, and the membership-canceled end date as `%B %d, %Y`.
- `SPEC-8.19.7` The email-change notification must go to the old address and the verification to the new address;
  `send_admin_feedback_notification` must send to each recipient in order and stop at the first send error.
- `SPEC-8.19.8` `test_connection` must apply a 10 second timeout to the TCP connect and the SMTP connection, ignore
  `config.enabled`, send no message, and always attempt QUIT after authentication.
- `SPEC-8.19.9` `test_connection` must report a failure with one of the stages `connect`, `tls` or `auth`: an empty host
  as `connect` (`SMTP host is not configured.`); a connect timeout or refusal as `connect`; a TLS parameter or implicit
  TLS failure as `tls`; a STARTTLS greeting failure as `connect` and a STARTTLS upgrade failure as `tls`.
- `SPEC-8.19.10` `test_connection` must authenticate with PLAIN or LOGIN only when a username is configured, and report a
  rejection as stage `auth` with message `Authentication failed: ...`; success must return `Ok(())`.

### 8.20 Integration registry

- `SPEC-8.20.1` The integration registry must list exactly four integrations in this order, each with a stable id,
  a display name and a declared capability set: `quickbooks` ("QuickBooks": payment and invoicing), `stripe`
  ("Stripe": payment and invoicing), `paypal` ("PayPal": payment only) and `xero` ("Xero": invoicing only).
- `SPEC-8.20.2` A registry entry must carry metadata only (id, display name, capabilities); it must not carry
  provider credentials, and every entry must declare at least one capability.
- `SPEC-8.20.3` `integrations_with(capability)` must return, in registry order, exactly the entries whose declared
  capability set contains `capability`, matching on the capability and never on a provider id, so that adding an
  entry to the registry changes every capability-filtered result with no call-site change.
- `SPEC-8.20.4` `integration(id)` must return the entry whose id equals `id` exactly (case-sensitive), and must
  return `None` for an id that is not registered.
- `SPEC-8.20.5` The capability tokens must be `payment` and `invoicing`, and `IntegrationCapability::as_str` must
  return the same token the type serializes to (snake_case).

### 8.21 Integration status classification

- `SPEC-8.21.1` `integration_statuses` must be a pure function of its `IntegrationSignals` argument (no database,
  environment or network access) and must return exactly one status for each of these keys, in this order: `email`,
  `stripe`, `support_inbox`, `infisical`, `distribution`, `oci`, `ip2location`, `ip2proxy`,
  `mailer_feedback_webhook`, `update_checker`, `mokosh_webhook`, `mokosh_backup`, `mirzam`.
- `SPEC-8.21.2` Every status must be in exactly one of three states, serialized in snake_case: `configured` (every
  required input present), `unconfigured` (switched off by the operator) or `failing` (switched on but missing a
  required input). A `configured` status must carry an empty `remedy`.
- `SPEC-8.21.3` The `email` status must be `unconfigured` when no SMTP host is set, `configured` when a host is set
  and the SMTP password is present, and `failing` when a host is set and the password is absent. The failing text
  must name `SMTP_PASSWORD` and the declared secrets provider.
- `SPEC-8.21.4` The `stripe` status must be `unconfigured` when the Stripe secret key is absent (whatever the
  webhook secret signal says), `configured` when both the secret key and the webhook signing secret are present,
  and `failing` when the secret key is present and the webhook secret is absent. The failing text must name
  `STRIPE_WEBHOOK_SECRET` and the declared secrets provider.
- `SPEC-8.21.5` The `support_inbox` status must be `unconfigured` when the IMAP mailbox is neither enabled nor given
  a host, `configured` when it is configured and the IMAP password is present, and `failing` when it is configured
  and the password is absent. The failing text must name `SUPPORT_IMAP_PASSWORD` and the declared secrets provider.
- `SPEC-8.21.6` The `infisical` status must be decided in this precedence: when Infisical is the declared secrets
  provider it must be `configured` if its client is complete and `failing` otherwise, regardless of
  `INFISICAL_ENABLED`; otherwise it must be `unconfigured` when `INFISICAL_ENABLED` is off, `configured` when
  enabled and complete, and `failing` when enabled and incomplete. A failing status must carry the remedy of
  `INFISICAL_ADDRESS`.
- `SPEC-8.21.7` The `distribution` status must be `unconfigured` when no Forgejo base URL is set, `configured` when
  the base URL and API token are both present, and `failing` when the base URL is set and the token is absent (its
  text taken from `FORGEJO_API_TOKEN`).
- `SPEC-8.21.8` The `oci` status must be `unconfigured` when the OCI registry endpoint is not enabled, `configured`
  when it is enabled with a public hostname, and `failing` when it is enabled without a hostname (its text taken
  from `OCI_REGISTRY_SERVICE`).
- `SPEC-8.21.9` The `ip2location` (`IP2LOCATION_DB_PATH`), `ip2proxy` (`IP2PROXY_DB_PATH`),
  `mailer_feedback_webhook` (`MAILER_WEBHOOK_SECRET`), `mokosh_webhook` (`MOKOSH_WEBHOOK_URL`) and `mokosh_backup`
  (`MOKOSH_BACKUP_API_URL`) statuses must be `configured` with the detail "<VAR> is configured." when their one
  signal is set and `unconfigured` otherwise, and must never be `failing`.
- `SPEC-8.21.10` The `update_checker` status must be `unconfigured` when no update-check URL is configured,
  `failing` when one is configured and the last check failed, and `configured` otherwise. The failing remedy must
  name `BUNYIP_UPDATE_CHECK_URL` and `BUNYIP_UPDATE_CHECK_TOKEN`.
- `SPEC-8.21.11` The `mirzam` status must be decided in this precedence: `unconfigured` when the integration switch
  is off; else `failing` when the address or either list slug is missing; else `failing` (naming `MIRZAM_API_TOKEN`
  and the declared secrets provider) when the API token is absent; else `failing` with the detail "The last call to
  Mirzam failed: <error>" when a last sync error is recorded; else `configured`.
- `SPEC-8.21.12` The detail and remedy of an `unconfigured` or env-driven `failing` status must be read from the
  `ENV_INVENTORY` entry's `feature` and `remedy` of the named variable, and secret-absence text from
  `GovernedSecret::feature`, so the status page and the boot report share one description.

### 8.22 Dunite seams and the services module surface

- `SPEC-8.22.1` `services::ip_enrich` must re-export `IpEnrichError`, `IpEnrichService`, `IpEnrichment`,
  `NetworkCategory` and `VpnLikelihood` from the shared IP-enrichment crate and must not reimplement lookup logic,
  so every `crate::services::IpEnrichService` path stays stable.
- `SPEC-8.22.2` IP enrichment output (`VpnLikelihood`, `NetworkCategory`) must be advisory: this module must expose
  no function that turns an enrichment into an abuse or spam verdict.
- `SPEC-8.22.3` `services::password_breach` must re-export `check_password_breach` and `BreachCheckOutcome` from the
  shared breach-check crate, and in non-test builds must re-export that crate's `is_breached`.
- `SPEC-8.22.4` In test builds `password_breach::is_breached` must return the thread-local override set through
  `set_breach_override(Some(v))` without calling the breach service, and must call the real check when the
  override is `None`.
- `SPEC-8.22.5` `services` must declare the submodules `argon2_offload`, `auth`, `backup`, `email`, `event_bus`,
  `geoip`, `infisical`, `integration_registry`, `integration_status`, `ip_enrich`, `jwt`, `mailer_relay`,
  `mailer_webhook`, `mirzam`, `mirzam_backfill`, `mirzam_sync`, `password_breach`, `provider_status`, `stripe`,
  `totp` and `webhook`.
- `SPEC-8.22.6` `services` must re-export the kernel types `EncryptionKeySet`, `JwtConfig` and `PasswordService`
  and the `encryption` and `password` modules from the core kernel crate, the download-engine types from the
  download crate, and the mailer vocabulary (`NoSuppression`, `RelayMessage`, `RelayOutcome`, `SuppressionList`,
  `SuppressionReason`, `MAX_ADDRESS_LEN`, `MAX_BODY_LEN`, `MAX_SUBJECT_LEN`) from the mailer leaf crate, so old
  paths keep resolving.
- `SPEC-8.22.7` `services::AppDownloadCache` must be defined once, as the generic download cache backed by
  `DownloadCacheRepository`, so the engine-over-store binding has a single definition.

### 8.23 JWT access and refresh tokens

- `SPEC-8.23.1` `JwtService` must sign every token it creates with HS256 using the configured encoding key and set
  `iss` to the configured issuer, and must verify with the configured decoding key and require `iss` to equal the
  configured issuer.
- `SPEC-8.23.2` `create_access_token` must emit claims `sub`, `email`, `role`, `membership_status`, `price_locked`,
  `price_id`, `lifetime_member`, `trial_ends_at`, `grace_period_end`, `iat` (now), `exp` (now plus the configured
  access expiry) and `jti`, where `jti` is `at_` followed by a random UUID in 32 hex digits, and where `price_id`,
  `trial_ends_at` and `grace_period_end` are Unix seconds and are omitted when the user has none.
- `SPEC-8.23.3` `create_refresh_token` must return the token and its storage hash, with claims `sub`, `jti`
  (`rt_` followed by a random UUID in 32 hex digits), `iat` (now), `exp` (now plus the configured refresh expiry)
  and `iss`.
- `SPEC-8.23.4` `hash_token` must return the lowercase hex SHA-256 of the token's UTF-8 bytes, and only that hash,
  never the token, is what a caller stores.
- `SPEC-8.23.5` A failure to sign any token must return `AppError::internal` whose message names the token kind
  and the cause.
- `SPEC-8.23.6` `verify_access_token` and `verify_refresh_token` must return `AppError::TokenExpired` when the
  signature is valid and the token is expired, and `AppError::InvalidCredentials` for every other failure
  (malformed, bad signature, wrong issuer, missing claim).
- `SPEC-8.23.7` `verify_refresh_token` must require the `sub` and `exp` claims.
- `SPEC-8.23.8` An access token that carries no `grace_period_end` claim must decode with it unset, so that grace
  access is decided as expired.
- `SPEC-8.23.9` `AccessTokenClaims::has_member_access` (and its static form over raw fields) must return true when
  at least one of these holds, and false otherwise: the role is `admin`; the user is a lifetime member;
  `trial_ends_at` is later than now; the membership status is `active`; the membership status is `grace_period`
  and `grace_period_end` is later than now. A `grace_period` status with no end timestamp must not grant access.

### 8.24 JWT challenge tokens

- `SPEC-8.24.1` `create_2fa_challenge_token` must emit a token with `purpose` `2fa_challenge`, expiry five minutes
  after issue, `jti` prefixed `2fa_`, and the caller's `remember` flag.
- `SPEC-8.24.2` `create_login_approval_challenge_token` must emit a token with `purpose` `login_approval`, expiry 15
  minutes after issue, `jti` prefixed `appr_`, and the caller's `remember` flag, and must return the `jti` it put in
  the token alongside the token.
- `SPEC-8.24.3` `verify_2fa_challenge_token` and `verify_login_approval_challenge_token` must require `sub` and
  `exp`, the configured issuer and an unexpired token, and must return `AppError::InvalidCredentials` when
  `purpose` is not `2fa_challenge` / `login_approval` respectively, so a token of one flow is never accepted by the
  other.
- `SPEC-8.24.4` A challenge token whose claims carry no `remember` field must decode with `remember` false.
- `SPEC-8.24.5` `create_signup_challenge_token(max_age)` must emit a token with `purpose` `signup_challenge`,
  `iat` now, `exp` now plus `max_age`, the issuer, and no subject.
- `SPEC-8.24.6` `verify_signup_challenge_token` must require `exp`, the configured issuer, an unexpired token and
  `purpose` `signup_challenge` (else `AppError::InvalidCredentials`), and must return the claims so the caller can
  apply the minimum fill time to `iat`; the service itself must not enforce a minimum fill time.
- `SPEC-8.24.7` Each challenge verifier must map expiry to `AppError::TokenExpired` and every other decode failure
  to `AppError::InvalidCredentials`.

### 8.25 Mailer relay

- `SPEC-8.25.1` `MailerRelay::relay` must check the recipient against the suppression list before handing anything
  to the SMTP transport.
- `SPEC-8.25.2` When the suppression check itself fails, `relay` must return `AppError::internal` with the message
  "Suppression store unavailable: <cause>" and must not send; a store failure must never be treated as "not
  suppressed".
- `SPEC-8.25.3` When the recipient is suppressed, `relay` must return `Ok(RelayOutcome::Suppressed)` without calling
  the transport, and must log a `warn` that names the calling client and not the recipient address.
- `SPEC-8.25.4` When the recipient is not suppressed, `relay` must pass only the recipient, subject, text body and
  optional HTML body to `EmailService::send_relay` (the sending identity is always this deployment's), must return
  any transport error unchanged, and on success must log an `info` naming the client and message id and return
  `Ok(RelayOutcome::Sent { message_id })`.
- `SPEC-8.25.5` `DbSuppressionList::is_suppressed` must read the `mailer_suppressions` table through
  `MailerSuppressionRepository::is_suppressed`, and `suppress` must write through `MailerSuppressionRepository::upsert`
  with the reason's string form and the optional detail, so reads and writes fold address case identically.
- `SPEC-8.25.6` `DbSuppressionList` must convert any repository error into `SuppressionError::Unavailable` carrying
  the error text.

### 8.26 Mailer feedback webhook

- `SPEC-8.26.1` The feedback webhook signature header name must be `X-Webhook-Signature`, taken from the shared
  webhook crate's `SIGNATURE_HEADER`.
- `SPEC-8.26.2` `verify_signature` must accept only a hex HMAC-SHA256 of the exact body bytes keyed by the shared
  secret (compared in constant time by the shared crate), and must map every refusal (missing, malformed,
  mismatch) to the same `AppError::Unauthorized`.
- `SPEC-8.26.3` `ingest_feedback` must verify the signature before parsing the body, so an unsigned or badly signed
  call returns `AppError::Unauthorized` without reaching the parser or the suppression store.
- `SPEC-8.26.4` A verified body that is not valid feedback-event JSON must return a validation error on field
  `body` with message "Invalid feedback event JSON".
- `SPEC-8.26.5` An `event` value other than `bounce` or `complaint` must return a validation error on field `event`
  with message "Unknown feedback event; expected bounce or complaint".
- `SPEC-8.26.6` The `recipient` must be normalized with the mailer leaf's `normalize_address`; an empty result must
  return a validation error on field `recipient` with message "A recipient address is required", and a result
  longer than `MAX_ADDRESS_LEN` must return one with message "Recipient address exceeds <MAX_ADDRESS_LEN>
  characters".
- `SPEC-8.26.7` On an accepted event `ingest_feedback` must record the normalized address on the suppression list
  with the parsed reason and the optional `detail`, and return a `FeedbackOutcome` holding that address and
  reason.
- `SPEC-8.26.8` A suppression-store failure during ingestion must return `AppError::internal` with the message
  "Suppression store unavailable: <cause>".

### 8.27 Mirzam connection check

- `SPEC-8.27.1` `check_connection` must read each of the two lists concurrently with `GET
  {base_url}/api/v1/lists/{slug}` using the API token as a bearer token, with trailing `/` characters removed from
  `base_url` and the slug trimmed and URL-encoded in the path.
- `SPEC-8.27.2` Each request must time out after `MIRZAM_HTTP_TIMEOUT` (10 seconds) and must not follow redirects.
- `SPEC-8.27.3` `check_connection` must always return a `MirzamCheckReport` and never an error: `lists` holds the
  product-updates check (`updates_list`) then the notices check (`notices_list`), and `ok` is true only when both
  are ok.
- `SPEC-8.27.4` When the HTTP client cannot be built, both lists must report not ok with the message "Could not
  build the HTTP client: <cause>".
- `SPEC-8.27.5` A request timeout must report "<base_url> did not answer within 10 seconds." and any other
  transport failure must report "Could not reach <base_url>: <root cause>", without the request URL.
- `SPEC-8.27.6` A status of 301, 302, 303, 307 or 308 must report not ok with the message "<base_url> redirects to
  <location>. Save the address Mirzam is served from." (location "another address" when the header is absent).
- `SPEC-8.27.7` A status of 401, 403, 404 or 429 must report not ok with the distinct messages "Mirzam refused the
  API token (401). ...", "Mirzam refused the API token (403). The token cannot read this list.", "Mirzam has no
  list with the slug <slug>. ..." and "Mirzam is rate limiting this token (429). ...", and any other non-200 status
  must report "Mirzam answered with status <n>.".
- `SPEC-8.27.8` A 200 answer whose body is not a JSON object with string `name` and `kind` must report not ok with a
  message saying the address answered but not with a Mirzam list.
- `SPEC-8.27.9` A parsed list is ok only when its `kind` is `newsletter` for the product-updates list and `notices`
  for the notices list; ok reports "Found <name> (<kind>)." and a mismatch reports not ok with the list's name and
  kind and a message naming the required kind. Reports for a parsed list must carry its `name` and `kind`; reports
  for any failure before parsing must carry neither.

### 8.28 Mirzam API client

- `SPEC-8.28.1` `MirzamClient::new` must trim the base URL and token, remove trailing `/` from the base URL, apply
  a 10-second timeout, and not follow redirects; a client build failure must return a `MirzamCallError` with no
  status and the message "Could not build the HTTP client: <cause>".
- `SPEC-8.28.2` Every Mirzam call must make exactly one attempt per invocation, send the token as a bearer token,
  and be retried only by `with_retries`.
- `SPEC-8.28.3` A timed-out call must fail with the message "Mirzam did not answer within 10 seconds." and a
  transport failure with "Could not reach Mirzam: <root cause>"; neither may contain the request URL, the token or
  an address, and both carry no status.
- `SPEC-8.28.4` Failure text must have the token replaced by `[token]` and every address of the call replaced by
  `[address]` (exact, lower-cased and URL-encoded forms) over the whole text before any truncation.
- `SPEC-8.28.5` A non-success answer's summary must be Mirzam's `error.message`, else its `error.code`, else the
  raw body, with whitespace collapsed to single spaces and cut to 200 characters followed by an ellipsis
  character when longer.
- `SPEC-8.28.6` `MirzamCallError` must display as "Mirzam answered <status>." for a status with no detail, as
  "Mirzam answered <status>: <detail>" for a status with detail, and as the detail alone when it has no status.
- `SPEC-8.28.7` `MirzamCallError::is_transient` must be true when there is no status or the status is 408, 429 or
  at least 500, and false otherwise.
- `SPEC-8.28.8` `add` must `POST {base}/api/v1/subscribers` with `email`, `name` (omitted when absent), `list`,
  `consent` `recorded`, `consent_note` `Account holder`, and `keep_unsubscribed` true only when requested (omitted
  otherwise); any 2xx must yield `Added`, a 409 whose `error.code` is `unsubscribed` must yield `LeftAlone`, any
  other 409 must yield `AlreadyOn`, and any other status must be an error.
- `SPEC-8.28.9` `move_address` must `PATCH {base}/api/v1/subscribers/{old}` (address URL-encoded) with body
  `{"email": <new>}`; any 2xx must yield `Moved`, 409 `NewAddressTaken`, 404 `OldAddressUnknown`, and any other
  status must be an error.
- `SPEC-8.28.10` `remove` must `POST {base}/api/v1/subscribers/{email}/unsubscribe` with body `{"list": <slug>}`;
  any 2xx must yield `Removed`, 409 `NotSubscribed`, 404 `UnknownAddress`, and any other status must be an error;
  it must never erase a subscriber.

### 8.29 Mirzam retries and account operations

- `SPEC-8.29.1` `with_retries(delays, op)` must run `op` once and, while it fails with a transient error, run it
  again after each delay in turn; it must return the first success, return a non-transient error at once without
  waiting, and return the last error when the delays are exhausted.
- `SPEC-8.29.2` The default delays `MIRZAM_RETRY_DELAYS` must be 1 second then 4 seconds (three attempts in all).
- `SPEC-8.29.3` `add_account` must add the address to the product-updates list with `keep_unsubscribed` true and to
  the notices list without it, each under `with_retries`, and must attempt the second list even when the first
  failed.
- `SPEC-8.29.4` A failed add must be reported as "Adding user <user_id> to list <slug> failed: <error>", naming the
  user id and never the address, and `AccountAdd::errors` must list the product-updates failure first.
- `SPEC-8.29.5` `remove_account` must unsubscribe the address from the product-updates list then the notices list,
  each under `with_retries`, must continue to the second list after a failure, and must report a failure as
  "Removing user <user_id> from list <slug> failed: <error>".
- `SPEC-8.29.6` `move_account` must change the address in place; on `NewAddressTaken` it must add the new address to
  both lists and then unsubscribe the old address from both; on `OldAddressUnknown` it must add the new address to
  both lists; on a call error it must report "Moving user <user_id> to a new address failed: <error>"; on `Moved`
  it must report no errors.
- `SPEC-8.29.7` `account_display_name` must join the trimmed non-empty first and last names with one space and
  return `None` when both are absent or blank.

### 8.30 Mirzam account sync

- `SPEC-8.30.1` `active_lists` must return the two list slugs, trimmed, only when the integration row is enabled
  and its settings (address and both slugs) are complete, and `None` otherwise.
- `SPEC-8.30.2` `MirzamSync::notify` must return at once and run the Mirzam calls in a spawned task, so a Mirzam
  outage can never fail or delay the triggering request.
- `SPEC-8.30.3` `notify` must spawn nothing for a change that cannot lead to a call: `EmailChanged` when neither
  the old nor the new address is verified, and `Deleted` when the address was not verified; `Verified` must always
  spawn.
- `SPEC-8.30.4` `MirzamSync::idle` must resolve only when every task spawned by `notify` has finished, including a
  task that ended by panic.
- `SPEC-8.30.5` `apply` must make no Mirzam call and record nothing when the integration row is off or incomplete,
  or when the token source returns no token or a blank one.
- `SPEC-8.30.6` When `mirzam_config` cannot be read, or the account cannot be read, `apply` must send nothing and
  log a `warn` naming the user id and the cause.
- `SPEC-8.30.7` When the token source returns an error, `apply` must make no call and record "Reading the Mirzam API
  token for user <user_id> failed: <error>"; when the client cannot be built it must record "Calling Mirzam for
  user <user_id> failed: <error>".
- `SPEC-8.30.8` A `Verified` change must add the account only if, when the task runs, the account still exists and
  has a verified email, using the address and display name read at that time.
- `SPEC-8.30.9` An `EmailChanged` change must be planned as: no call when both states are verified and the
  addresses are equal ignoring ASCII case; an in-place move when both are verified and differ; an add of the new
  address when only the new state is verified; a removal of the old address when only the old state is verified;
  no call when neither is verified.
- `SPEC-8.30.10` A `Deleted` change must remove the address captured before the delete from both lists, and only
  when it was verified.
- `SPEC-8.30.11` After a run with no errors `apply` must clear the stored sync error; after a run with errors it
  must log a `warn` per error naming the user id and the error, and record all the errors joined by a space in
  `mirzam_config.last_error`; a failure to write that outcome must be logged at `warn` with the user id.
- `SPEC-8.30.12` Recorded and logged failure text must contain neither the API token nor any email address.

### 8.31 Mirzam backfill

- `SPEC-8.31.1` `backfill` must process every account returned by `UserRepository::list_verified` sequentially, one
  account at a time, making the same two calls as `add_account` with the account's email and display name.
- `SPEC-8.31.2` `backfill` must wait `pace` before every account except the first, and must not wait when `pace`
  is zero; the production pace `MIRZAM_BACKFILL_PACE` must be 250 milliseconds.
- `SPEC-8.31.3` A failed account must be counted and the run must continue with the next account; `backfill` must
  return an error only when listing the verified accounts fails.
- `SPEC-8.31.4` Each account must be classified `Failed` if either call failed, else `LeftAlone` if either answered
  left-alone, else `Added` if either added, else `AlreadyOn`, and the report must count each account in exactly
  one of `failed`, `left_alone`, `added`, `already_on`.
- `SPEC-8.31.5` A failed account's error sentences must be appended to the report's failure list; they must name
  the user id and never the address.
- `SPEC-8.31.6` The report must print as the line "mirzam-backfill: added <n>, already on <n>, left alone
  (unsubscribed) <n>, failed <n>" followed by one line per failure indented two spaces.

### 8.32 Provider-status contract and discrepancies

- `SPEC-8.32.1` The contract version `PROVIDER_STATUS_SCHEMA_VERSION` must be `1`.
- `SPEC-8.32.2` The provider-status types must require only `schema_version` and `report` (envelope),
  `hosting_profile` (report), `kind` (kind report and deviation), `name` (enabled provider) and `key` (key
  report); every other field must default when absent so a differing contract version does not fail the parse.
- `SPEC-8.32.3` No contract type may hold a secret value: fields must be limited to names, booleans, small
  integers, timestamps, statuses and an unreachable-provider message.
- `SPEC-8.32.4` `AppProviderStatus` must serialize with a snake_case `state` tag (`ok`, `unreachable`,
  `unauthenticated`, `version_mismatch`, `unknown`), an unrecognised `state` must decode as `Unknown`, and
  `is_healthy` must be true only for `Ok`.
- `SPEC-8.32.5` `ProviderDiscrepancy` must serialize with a snake_case `condition` tag
  (`declared_provider_holds_nothing`, `present_in_multiple_providers`, `absent_from_highest_priority_provider`),
  and an unrecognised `condition` must decode as `Unknown`.
- `SPEC-8.32.6` `KindEnumerationStatus::Supported` holding no names and `Unsupported` must remain distinct values.
- `SPEC-8.32.7` For each key, `discrepancies_for` must emit `DeclaredProviderHoldsNothing` when
  `recorded_served_by` is absent and `providers` is empty.
- `SPEC-8.32.8` For each key with `recorded_served_by` present, `discrepancies_for` must emit
  `AbsentFromHighestPriorityProvider` (with `serving` the kind's serving provider and `holder` the recorded
  provider) when the kind has a serving provider and the two differ.
- `SPEC-8.32.9` For each key whose `providers` holds more than one name, `discrepancies_for` must emit
  `PresentInMultipleProviders` with that key and those providers.
- `SPEC-8.32.10` For each kind in which no key has a non-empty `providers` list and more than one provider is
  enabled, `discrepancies_for` must emit `PresentInMultipleProviders` with an empty key and the enabled provider
  names.
- `SPEC-8.32.11` `aggregate` must keep every application row, in input order, and compute discrepancies only from
  rows whose status is `Ok`, in row order.

### 8.33 Provider-status remote fetch

- `SPEC-8.33.1` `fetch_remote` must return an `AppProviderStatus` variant for every outcome and never panic or
  return a bare error.
- `SPEC-8.33.2` With no status URL configured, `fetch_remote` must return `Unreachable` with the reason "no status
  endpoint is configured for this application" and make no request.
- `SPEC-8.33.3` `fetch_remote` must `GET` the status URL with a 5-second timeout, presenting HTTP Basic credentials
  when the application has a machine credential.
- `SPEC-8.33.4` A transport failure must return `Unreachable` with "request failed: <cause>", a non-2xx status
  other than 401 or 403 must return `Unreachable` with "unexpected status <status>", and a body that cannot be
  read must return `Unreachable` with "could not read the response body: <cause>".
- `SPEC-8.33.5` A 401 or 403 answer must return `Unauthenticated`.
- `SPEC-8.33.6` A body that does not parse as an envelope (and is not covered by `SPEC-8.33.8`) must return `Unreachable` with "response did not parse
  as a status envelope: <cause>".
- `SPEC-8.33.7` An envelope whose `schema_version` is not `1` must return `VersionMismatch` carrying the reported
  version, and a matching one must return `Ok` with its report.
- `SPEC-8.33.8` A reply whose `schema_version` differs from `1` must return `VersionMismatch` even when the rest of
  the body does not parse under this version's shape.

### 8.34 Stripe error mapping and key probes

- `SPEC-8.34.1` `StripePermission` must cover Products, Prices, Subscriptions, Customers, Checkout Sessions,
  Invoices and Webhook Endpoints, with labels "Products", "Prices", "Subscriptions", "Customers", "Checkout
  Sessions", "Invoices", "Webhook Endpoints" and wire keys `products`, `prices`, `subscriptions`, `customers`,
  `checkout_sessions`, `invoices`, `webhook_endpoints`.
- `SPEC-8.34.2` `stripe_err` and `stripe_err_for(permission)` must map the shared crate's errors as: `Internal` to
  `AppError::internal`, `Validation` to `AppError::validation`, `NotFound` to `AppError::not_found`, `Unauthorized`
  to `AppError::Unauthorized`, and a Stripe error whose details say the resource is missing to
  `AppError::not_found("Stripe resource")`.
- `SPEC-8.34.3` A Stripe error with code `more_permissions_required` or HTTP status 403 must log a `warn` with the
  details and the permission label (or "unattributed") and return a validation error on field `secret_key` whose
  message names the missing permission when the call site supplied one, or says the key lacks permission for this
  action otherwise; the message must end with the instruction to paste the key into Secret key and save.
- `SPEC-8.34.4` A Stripe error with HTTP status 401 or code `api_key_expired` or `invalid_api_key`, and not a
  permission failure, must log a `warn` with the details and return a validation error on field `secret_key` with
  the fixed text starting "Stripe rejected your secret key: it is invalid, expired or revoked."
- `SPEC-8.34.5` Any other Stripe error must return `AppError::internal` whose message is "<message> (<details>)", and
  Stripe's own error message must not be shown to a user.
- `SPEC-8.34.6` `classify_probe` must return `Granted` for success, `KeyRejected` for `Unauthorized` or for Stripe
  details that show a rejected key, `Missing` for details that show a permission failure, and `Unknown` for every
  other Stripe error and every other error variant.
- `SPEC-8.34.7` `ProbeStatus` must serialize in snake_case (`granted`, `missing`, `key_rejected`, `unknown`,
  `untested`), and `classify_probe` must never return `Untested`.

### 8.35 Stripe configuration construction

- `SPEC-8.35.1` The default app tag, used when the `stripe_config` row's tag is NULL, must be `bunyip`.
- `SPEC-8.35.2` The default checkout base must be the first non-empty trimmed entry of `CORS_ORIGIN` with trailing
  `/` removed, or `http://localhost:5173` when `CORS_ORIGIN` is unset or has no non-empty entry; the default
  success URL must be `<base>/checkout/success` and the default cancel URL `<base>/pricing?checkout=canceled`.
- `SPEC-8.35.3` The default trial length must be the value of `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` parsed as a
  trimmed unsigned 32-bit integer, or 30 days when it is unset, blank or unparseable.
- `SPEC-8.35.4` `unconfigured_stripe_config` must use the placeholder secret key and webhook secret so the service
  reports itself unconfigured, the default URLs, app tag and trial length, and no free price id.
- `SPEC-8.35.5` `stripe_settings_from_db_model` must take only the non-secret columns (app tag, success URL, cancel
  URL, trial days), keep the two secrets on their placeholders, and use the default for any NULL column or a trial
  value that is negative.
- `SPEC-8.35.6` `stripe_config_from_db_model` must decrypt the secret key and webhook secret with the given key set
  and the row's `key_version` only when both ciphertext and nonce are present, use the placeholder for a secret
  that is absent, apply the same defaults as `SPEC-8.35.5`, and return the decryption `AppError` on a decryption failure.
- `SPEC-8.35.7` Stripe configuration must come from the `stripe_config` row only: no Stripe-prefixed environment
  variable may be read by these constructors, and the free price id must stay `None` (it is read from the live
  tier configuration at the call site).

### 8.36 TOTP setup and enrolment

- `SPEC-8.36.1` TOTP codes must be six digits, SHA-1, with a 30-second step and a skew of zero, and the issuer
  stamped into a new enrolment's `otpauth://` URI must be the branding cache's brand name when a cache is attached
  and the constructor issuer otherwise; an issuer change must not alter existing enrolments.
- `SPEC-8.36.2` `begin_setup` must generate a fresh secret, store it encrypted with the key set together with the
  SHA-256 hex hash of a new random setup token that expires 15 minutes later, and return the `otpauth://` URI, the
  base32 (unpadded) secret and the raw setup token; only the hash of the token may be stored.
- `SPEC-8.36.3` `begin_setup` for an account that already has verified two-factor must return a conflict error
  with the message "Two-factor is already on. Use Reset authenticator app to change it."
- `SPEC-8.36.4` A setup token is live only when a stored hash and an expiry both exist, the hash of the presented
  token equals the stored hash (constant-time comparison) and the expiry is later than now.
- `SPEC-8.36.5` `resume_setup` must return the stored unfinished secret's URI and base32 secret without minting a
  new secret; it must return a validation error on field `setup_token` with the message "This setup expired. Start
  again." when no record exists or the token is not live, and the already-enrolled conflict when the record is
  verified.
- `SPEC-8.36.6` `confirm_setup` must apply its checks in this order: record exists, else the setup-expired error;
  record not yet verified, else a conflict "2FA is already enabled"; setup token live, else the setup-expired
  error; code valid and unclaimed, else a validation error on field `code` "Invalid verification code".
- `SPEC-8.36.7` After a valid code `confirm_setup` must complete setup through a guarded update keyed by the token
  hash that burns the token, return the setup-expired error when that update affects no row, and only then
  generate and return the recovery codes, so a racing confirm cannot enrol twice.
- `SPEC-8.36.8` `enroll_preset` must strip whitespace and `=` from the supplied base32 secret, upper-case it and
  decode it, returning a validation error on field `totp_secret` "preset TOTP secret is not valid base32" on a
  decode failure, and must reject a secret that cannot build a usable TOTP before storing anything.
- `SPEC-8.36.9` `enroll_preset` must replace any existing row with the encrypted preset secret and mark it
  verified; it must be called only from trusted non-interactive provisioning and never from a request handler.
- `SPEC-8.36.10` `disable` must delete the user's TOTP record; `is_enabled` must return the record's verified flag
  and false when no record exists; `recovery_codes_remaining` must return the count of unused recovery codes.

### 8.37 TOTP code verification and authenticator re-key

- `SPEC-8.37.1` Code matching must remove spaces from the presented code and accept it only against the current
  30-second step and the single step immediately before it (never a future step), returning the matched step
  number (Unix seconds divided by 30).
- `SPEC-8.37.2` An accepted code must be consumed by claiming its step for the user, and it must be rejected when
  the claim affects no row, so each step is usable once; a replayed code and a wrong code must both yield
  `false` with no distinguishing signal.
- `SPEC-8.37.3` `verify_code` must return a not-found error for "TOTP configuration" when the user has no record,
  `Ok(false)` without claiming a step when the record is not verified, and otherwise decrypt the secret (returning
  any decryption error) and check and claim the code.
- `SPEC-8.37.4` `begin_rekey` must return a not-found error for "TOTP configuration" when there is no record and a
  validation error on field `2fa` "2FA is not enabled" when the record is not verified; otherwise it must stage a
  fresh secret in the pending columns without disabling the active secret and return its URI and base32 secret.
- `SPEC-8.37.5` `confirm_rekey` must return a not-found error when there is no record, and a validation error on
  field `2fa` "No authenticator reset is in progress" unless the pending ciphertext, nonce and key version are all
  present; it must verify and claim the code against the pending secret (invalid gives a validation error on field
  `code` "Invalid verification code") before promoting.
- `SPEC-8.37.6` `confirm_rekey` must promote the pending secret through a guarded update, return the "No
  authenticator reset is in progress" error when that update affects no row, and only then generate and return
  fresh recovery codes.

### 8.38 TOTP recovery codes

- `SPEC-8.38.1` A recovery code must be 10 bytes from the thread-local CSPRNG (`rand::thread_rng`), base32-encoded to 16
  upper-case characters and shown as four hyphen-separated groups of four.
- `SPEC-8.38.2` Generating recovery codes must produce eight codes, hash each hyphen-stripped code with Argon2id
  (19456 KiB memory, 2 iterations, parallelism 1, random salt) inside one blocking task, store the hashes for the
  user, and return the plain codes only to the caller; a hashing or parameter failure must return
  `AppError::internal`.
- `SPEC-8.38.3` `regenerate_recovery_codes` must return a not-found error for "TOTP configuration" when the user
  has no record and a validation error on field `2fa` "2FA is not enabled" when the record is not verified.
- `SPEC-8.38.4` `verify_recovery_code` must upper-case the presented code and remove hyphens, then check it
  against the user's unused code hashes in a single blocking task, treating a stored hash of exactly 64 hex
  digits as a legacy unsalted SHA-256 and any other stored hash as Argon2id.
- `SPEC-8.38.5` A stored hash that is not a legacy hash and does not parse as an Argon2 hash must make
  `verify_recovery_code` return `AppError::internal` "Invalid hash format: <cause>".
- `SPEC-8.38.6` When no unused code matches, `verify_recovery_code` must return `Ok(false)`; when one matches it
  must mark that code used through a guarded update and return that update's result, so a code redeemed
  concurrently by another request fails rather than succeeding twice.

### 8.39 Outbound app webhooks

- `SPEC-8.39.1` `WebhookService` must deliver through the shared webhook sender, signed with the configured signing
  secret, to the application's `webhook_url`.
- `SPEC-8.39.2` Every notifier and `dispatch_account_deleted` must do nothing, and `dispatch_account_deleted` must
  return `Ok(())`, when the application's `webhook_url` is unset or empty.
- `SPEC-8.39.3` `notify_maintenance_change` must send once, without retry, a payload `event`
  `maintenance_mode_changed` with `slug`, `maintenance_mode`, `maintenance_message` and an RFC 3339 `timestamp`.
- `SPEC-8.39.4` `notify_active_change` must send once, without retry, a payload `event` `active_changed` with
  `slug`, `is_active` and an RFC 3339 `timestamp`.
- `SPEC-8.39.5` The `account_deleted` payload must be `event` `account_deleted`, `user_id` and an RFC 3339
  `timestamp`, built by one function shared by `notify_account_deleted` (single attempt) and
  `dispatch_account_deleted` so their wire shape and signature cannot differ.
- `SPEC-8.39.6` `dispatch_account_deleted` must serialize the payload once and send that same body and signature on
  every attempt, make at most three attempts, return `Ok(())` after the first 2xx answer, and return
  `Err(<last error>)` after three failed attempts so the caller can persist a replayable failure.

## 9. API application core (root, binaries, routes)

### 9.1 Crate manifest, library root and build metadata

`bunyip-api/Cargo.toml`, `bunyip-api/build.rs` and `bunyip-api/src/lib.rs`. Refines `SPEC-2.1.1` to `SPEC-2.1.3`.

- `SPEC-9.1.1` `bunyip-api/Cargo.toml` must declare `default-run = "bunyip-api"` so that `cargo run -p bunyip-api`
  resolves to the server binary; without it the crate's four binaries make the bare command ambiguous and it fails.
- `SPEC-9.1.2` The four `[[bin]]` targets must have exactly these names and paths: `bunyip-api` at `src/main.rs`,
  `bunyip-e2e-bootstrap` at `src/bin/bunyip_e2e_bootstrap.rs`, `seed` at `src/bin/seed.rs`, and `gen-demo-seed` at
  `src/bin/gen_demo_seed.rs` (`SPEC-2.1.3`).
- `SPEC-9.1.3` The package must inherit `version`, `edition`, `authors`, `license` and `repository` from
  `[workspace.package]` and must set `[lints] workspace = true`, so the crate carries no lint relaxation of its own
  (`SPEC-2.1.1`, `SPEC-2.1.2`).
- `SPEC-9.1.4` Each `dunite-*` dependency of this crate (`dunite-image-upload`, `dunite-core`, `dunite-update-check`,
  `dunite-events`) must be a git dependency pinned by a full commit `rev`, never by `branch` or `tag`
  (`SPEC-2.1.2`).
- `SPEC-9.1.5` The `reqwest` dependency must be declared with `default-features = false` and the `rustls-tls` feature
  (no `native-tls`), so the static musl image needs no system TLS library at runtime.
- `SPEC-9.1.6` The `hickory-resolver` dependency must be declared with `default-features = false` and only the `tokio`
  and `system-config` features, so no DoT/DoH TLS feature family is compiled in.
- `SPEC-9.1.7` The `image` dependency must be declared with `default-features = false` and only the `png`, `jpeg`,
  `gif`, `webp` and `ico` features: the four decoders the avatar policy admits plus the PNG and ICO encoders the
  branding derivations need (`SPEC-9.18.13`).
- `SPEC-9.1.8` `build.rs` must export the compile-time environment values `GIT_COMMIT`, `GIT_TAG` and `BUILD_DATE`.
  For each, a non-empty process environment variable of the same name must win; otherwise the value is the trimmed
  stdout of `git rev-parse --short HEAD`, `git describe --tags --always --dirty` and `date -u +%Y-%m-%dT%H:%M:%SZ`
  respectively; when the command is missing, exits non-zero, prints non-UTF-8 or prints nothing, the value must be the
  literal `unknown`.
- `SPEC-9.1.9` `build.rs` must request a rerun only when `build.rs`, one of the three environment variables, or one of
  the git paths reported by `git rev-parse --git-path` for `HEAD`, `refs/heads`, `refs/tags` and `packed-refs` changes,
  and must emit a `rerun-if-changed` directive for a git path only when that path exists; with no git binary or no
  repository it must emit no git directive. It must not watch all of `refs/`, so a fetch that moves only a
  remote-tracking ref does not recompile the crate.
- `SPEC-9.1.10` `lib.rs` must re-export these `bunyip-domain` modules under their original names: `config`,
  `config_providers`, `errors`, `feature_toggles`, `middleware`, `models`, `repositories`, `responses`, `services`,
  `validation`; and must re-export `Config`, `AppError`, `ApiResponse` and `ResponseMeta` at the crate root.
- `SPEC-9.1.11` `lib.rs` must declare as public modules exactly: `access_log`, `branding_assets`, `compress`,
  `config_status`, `db`, `db_metrics`, `error_log`, `extractors`, `handlers`, `host_config`, `host_secrets`,
  `machine_client`, `migrate_reconcile`, `mirzam_sync`, `mokosh_backup`, `provider_status`, `rate_limit_floor`,
  `reconcile_prices`, `reencrypt`, `root_span`, `routes`, `secrets`, `seed`, `settings_archive`, `support_ingest`,
  `version`.
- `SPEC-9.1.12` `lib.rs` must define `E2E_ACCOUNT_EMAILS` as exactly two addresses (an end-user account and an admin
  account of the e2e suite). It is the single source for both the `bunyip-e2e-bootstrap` binary (`SPEC-9.19.4`) and the
  `GET /e2e-bootstrapped` readiness probe, which compares the count of active accounts with these addresses against the
  length of the list (section 10).

None: this subsection holds no runtime error paths beyond `SPEC-9.1.8` (a failed git or `date` command yields
`unknown` and emits no `cargo:warning`; see the report).

### 9.2 Development image

`bunyip-api/Dockerfile` builds the hot-reload development image only; the production image is specified in section 14.

- `SPEC-9.2.1` The image must be based on the pinned rust-builder glibc image whose tag names the same Rust version as
  `rust-toolchain.toml` (`1.98.1`), so the compiler that builds in the container is the one the workspace pins
  (`SPEC-2.1.5`).
- `SPEC-9.2.2` The image must set `CARGO_NET_GIT_FETCH_WITH_CLI=true` (so the git CLI, which honours an injected
  token, fetches the `dunite-*` git dependencies) and `SQLX_OFFLINE=true` (so `sqlx::query!` macros resolve against the
  committed `.sqlx` cache instead of a live database).
- `SPEC-9.2.3` The image must run as a non-root user `app` created with build arguments `HOST_UID` and `HOST_GID`
  (both default `1000`), with `CARGO_HOME=/home/app/.cargo`, and must create `/app/target`,
  `/var/cache/bunyip-oci` and `/var/cache/bunyip-downloads` owned by that uid and gid, so named volumes mounted there
  inherit the ownership and writes do not fail with `Permission denied`.
- `SPEC-9.2.4` The image must set `WORKDIR /app`, run as `${HOST_UID}:${HOST_GID}`, expose port `4401`, and accept the
  build argument `CARGO_BUILD_JOBS` (default `default`, cargo's own CPU count) exported as the environment variable of
  the same name.
- `SPEC-9.2.5` The image's `CMD` must, when `DUNITE_GIT_TOKEN` is non-empty, configure a global git `insteadOf`
  rewrite that injects the token as basic-auth credentials for the dunite git host, and then must `exec`
  `cargo watch -w bunyip-api -w crates -x 'run -p bunyip-api'`, so source changes in the api crate or the library
  crates rebuild and restart the server.

### 9.3 Startup: logging, configuration, database connection and subcommand dispatch

`bunyip-api/src/main.rs` `main()`. Refines `SPEC-2.2.1` and `SPEC-2.2.2`.

- `SPEC-9.3.1` `main` must first load a local `.env` file with `dotenvy` (a missing file is not an error), before any
  configuration is read.
- `SPEC-9.3.2` `main` must install the tracing subscriber before `Config::from_env`, so every warning or error raised
  while parsing the environment is logged. The filter must be taken from `RUST_LOG` (default `info`), and the
  subscriber must combine a compact human-readable formatter, the error-log capture layer feeding a buffer of
  `DEFAULT_CAPACITY` entries, and the pool acquire-timeout counting layer (`SPEC-9.16.6`).
- `SPEC-9.3.3` When `Config::from_env` fails, `main` must call `log_startup_report` (one error line per failing
  variable, all of them in the one run), log `Refusing to start: fix the configuration errors above and restart`, and
  exit with status `1` without panicking and without opening a database connection (`SPEC-2.2.1`).
- `SPEC-9.3.4` After a successful load, `main` must log an `info` line `Starting bunyip-api` carrying the crate version
  and `config.environment`, must call `bunyip_domain::config::log_feature_gaps` once (one warning per optional
  variable whose absence disables a feature), and, when `Config::trusts_forwarded_client_ip()` is true, must log an
  `info` line carrying the number of trusted proxy CIDRs.
- `SPEC-9.3.5` `main` must open the primary database pool with at most `DB_POOL_MAX_CONNECTIONS` (`10`) connections and
  an acquire timeout of 5 seconds against `config.database_url`. A connection failure must be logged at `error` with
  the cause (message `Failed to connect to database`) and must terminate `main` with that
  error, giving a non-zero exit before any listener binds.
- `SPEC-9.3.6` The pool size must not be derived from the actix worker count. One replica opens two pools of
  `DB_POOL_MAX_CONNECTIONS` (the primary pool and the RLS pool, `SPEC-9.4.12`), so `2 * DB_POOL_MAX_CONNECTIONS` per
  replica times the replica count must fit under PostgreSQL `max_connections`; the constant may be raised only when
  the acquire-timeout count (`SPEC-9.16.4`) is non-zero and PostgreSQL's limit is raised in the same change.
- `SPEC-9.3.7` Immediately after the primary pool opens, when the process has any positional argument, `main` must hand
  the first argument and the remaining arguments to `run_subcommand` and return its result without running
  migrations, reconcilers, bootstrap steps or binding a listener (`SPEC-2.2.2`, `SPEC-9.11.1`). A subcommand
  therefore needs a reachable database, and runs against the schema the deployment already has.

### 9.4 Startup: migration reconciliation, role provisioning and database pools

`bunyip-api/src/main.rs` (startup order), `bunyip-api/src/migrate_reconcile.rs` and the role functions of
`bunyip-api/src/db.rs`. Refines `SPEC-2.2.3`.

- `SPEC-9.4.1` When no subcommand is given, startup must run, in this order and each before the next:
  `reconcile_legacy_migration_checksums`, `backfill_entitlement_source_check`, `ensure_app_role_shell`,
  `sqlx::migrate!("./migrations")` against the primary pool, then (only when `BUNYIP_APP_PASSWORD` is configured)
  `provision_app_role`. A failure in any step must be logged at `error` with a step-specific message and the cause,
  and must terminate `main` with that error before any listener binds (`SPEC-2.2.3`).
- `SPEC-9.4.2` `reconcile_legacy_migration_checksums` must return `Ok` without touching anything when
  `to_regclass('_sqlx_migrations')` is null (a database that has never been migrated), because the ledger does not yet
  exist.
- `SPEC-9.4.3` `reconcile_legacy_migration_checksums` must iterate exactly the eleven `(version, pre-edit SHA-384 hex)`
  pairs in `LEGACY_CHECKSUMS`. For each, it must look the version up in the embedded migrator and, when absent, log a
  `warn` and skip it; otherwise it must run `UPDATE _sqlx_migrations SET checksum = <embedded checksum> WHERE version =
  <v> AND checksum = decode(<original hex>, 'hex')` and log an `info` line per rewritten row.
- `SPEC-9.4.4` `reconcile_legacy_migration_checksums` must not change a ledger row whose recorded checksum equals
  neither the listed pre-edit value nor (already) the embedded value, so any other in-place migration edit is still
  caught by the migrator's immutability check; it must be idempotent, rewriting nothing on a second run. When at least
  one row was rewritten it must log one `warn` carrying the count and stating that the migrations' DDL guards are not
  retro-applied.
- `SPEC-9.4.5` `backfill_entitlement_source_check` must return `Ok` without writing when any of these holds, checked in
  this order: the `_sqlx_migrations` ledger is absent; migration version `20260802000010` is already recorded as
  applied; the `application_entitlements` table is absent; the constraint `application_entitlements_source_check`
  already exists on it.
- `SPEC-9.4.6` Otherwise `backfill_entitlement_source_check` must run `ALTER TABLE application_entitlements ADD
  CONSTRAINT application_entitlements_source_check CHECK (source IN ('admin', 'stripe', 'backfill'))` and log a `warn`
  naming the constraint, so migration `20260802000010` finds the constraint it drops.
- `SPEC-9.4.7` Each pre-migration reconciler must prove a relation exists with `to_regclass('<relation>')` before the
  first read of that relation, so a virgin database boots; a reconciler that reads a relation without that guard
  violates this requirement.
- `SPEC-9.4.8` `ensure_app_role_shell` must create the role `bunyip_app` as `NOLOGIN NOSUPERUSER NOBYPASSRLS` with no
  password only when `pg_roles` has no such role, and must never `ALTER` an existing role. A failure must return an
  internal error whose text begins `bunyip_app shell-role bootstrap failed:` and contains the database cause.
- `SPEC-9.4.9` When `config.app_password` is `None`, startup must skip `provision_app_role` and log an `info` line
  `BUNYIP_APP_PASSWORD unset; skipping bunyip_app role provisioning`.
- `SPEC-9.4.10` `provision_app_role` must run these statements in order, each identified by a stable label: `create_role`
  (create `bunyip_app` `LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD` only if absent), `alter_role` (reconcile attributes and
  password), `grant_connect` (on the current database), `grant_usage_schema` (on `public`), `grant_tables` (`SELECT,
  INSERT, UPDATE, DELETE` on all tables in `public`), `grant_sequences` (`USAGE, SELECT` on all sequences),
  `default_privileges_tables`, `default_privileges_sequences`; it must be idempotent and safe to run on every boot,
  and must log an `info` line naming the database on success.
- `SPEC-9.4.11` The password in `provision_app_role` must be embedded as a single-quoted SQL literal with embedded
  single quotes doubled, and the database name as a double-quoted identifier with embedded double quotes doubled. A
  failing step must return an internal error of the form `bunyip_app provisioning step '<label>' failed: <cause>`; the
  error and every log line must never contain the statement text, because two statements carry the password.
- `SPEC-9.4.12` Startup must build the self-service RLS pool after provisioning, with the same limits as the primary
  pool (`SPEC-9.3.5`): when `APP_DATABASE_URL` is set it must connect to that URL (failure logged at `error`
  `Failed to connect to the bunyip_app (RLS) database pool` with the cause, and terminate startup) and log an `info`
  line; when unset it must reuse a clone of the primary pool, in which case row-level security is a runtime no-op. It
  must be registered as the `AppPool` newtype.
- `SPEC-9.4.13` Startup must start the pool sampler (`SPEC-9.16.8`) with the primary pool labelled `primary` and,
  only when `APP_DATABASE_URL` is set, the RLS pool labelled `rls`, so a shared pool is never sampled twice.
- `SPEC-9.4.14` After the reconciliation steps in `SPEC-9.5`, startup must run `SELECT 1` on the primary pool; a failure
  must be logged at `error` `Database health check failed` with the cause and terminate startup.

### 9.5 Startup: bootstrap administrator and OIDC client reconciliation

`bunyip-api/src/main.rs`: the `SETUP_DEFAULT_ADMIN` block, `upsert_spa_oidc_client`, `upsert_lets_chat_oidc_client`,
`upsert_mokosh_webhook_url`, `fatal_config_error`.

- `SPEC-9.5.1` When `SETUP_DEFAULT_ADMIN` (plain variable or `SETUP_DEFAULT_ADMIN_FILE`; empty counts as unset) is
  set and the user repository reports at least one admin email, startup must create nothing and log an `info` line
  `Admin user(s) already exist, skipping SETUP_DEFAULT_ADMIN`.
- `SPEC-9.5.2` When it is set and no admin exists, startup must split the value at the first `:` into email and
  password, trim both, hash the password with `PasswordService`, create a user with role `Admin`, set its super-admin
  flag to true, and log an `info` line carrying the email (never the password). The hash runs on the startup thread
  because no worker arbiter exists yet.
- `SPEC-9.5.3` When the value contains no `:`, startup must call `fatal_config_error("SETUP_DEFAULT_ADMIN", ...)`
  (`SPEC-9.5.4`) naming the required `email:password` format; it must not seed a partial account.
- `SPEC-9.5.4` `fatal_config_error(env_var, reason, remedy)` must log one `error` line naming the variable, the reason
  and the remedy, then `Refusing to start: fix the configuration error above and restart`, and exit with status `1`;
  it must never `panic!`, because a panic prints a location and exits `101`, reading as a bug.
- `SPEC-9.5.5` `upsert_spa_oidc_client` must register a client only when both its `*_REDIRECT_URIS` and `*_AUDIENCE`
  variables resolve non-empty through `secret_env`; otherwise it must return `Ok(())` without a database write and
  without a log line (the environment inventory has already warned once).
- `SPEC-9.5.6` `upsert_spa_oidc_client` must split `*_REDIRECT_URIS` and `*_POST_LOGOUT_REDIRECT_URIS` on `,`, trim
  each entry and drop empty entries; an unset `*_POST_LOGOUT_REDIRECT_URIS` must write an empty array, not skip the
  client; an unset or empty `*_BACKCHANNEL_LOGOUT_URI` must write `NULL`.
- `SPEC-9.5.7` `upsert_spa_oidc_client` must run `INSERT INTO oauth_clients ... ON CONFLICT (client_id) DO UPDATE`
  that, on conflict, rewrites only `redirect_uris`, `post_logout_redirect_uris`, `audience` and
  `backchannel_logout_uri`; a freshly inserted row must be `client_type = 'public'`, scopes `openid, email,
  offline_access`, grant types `authorization_code, refresh_token`, `token_endpoint_auth_method = 'none'`,
  `require_pkce = TRUE` and `access_token_ttl_seconds = 600`. It must log an `info` line with the client name,
  redirect URIs, audience and back-channel URI.
- `SPEC-9.5.8` Startup must call `upsert_spa_oidc_client` for exactly two fixed client ids, in this order: the hosted
  apps SPA client with variable prefix `MOKOSH_APPS_` (`..._REDIRECT_URIS`, `..._POST_LOGOUT_REDIRECT_URIS`,
  `..._AUDIENCE`, `..._BACKCHANNEL_LOGOUT_URI`) and the drill-tool SPA client with prefix `DRILLMARK_`. A database
  error must propagate and terminate startup.
- `SPEC-9.5.9` `upsert_lets_chat_oidc_client` must act only when both `LETS_CHAT_REDIRECT_URIS` and
  `LETS_CHAT_AUDIENCE` resolve (otherwise silent `Ok(())`), and must `UPDATE` (never insert) the existing row for its
  fixed client id, setting `redirect_uris`, `post_logout_redirect_uris` (from `LETS_CHAT_POST_LOGOUT_REDIRECT_URIS`,
  comma-split as in `SPEC-9.5.6`), `audience`, and `client_secret_hash = COALESCE(<LETS_CHAT_CLIENT_SECRET_HASH>,
  client_secret_hash)`, so an unset hash keeps the migration's value and `client_type` and
  `token_endpoint_auth_method` are never touched.
- `SPEC-9.5.10` When that `UPDATE` affects zero rows, startup must log a `warn` naming the client id and must continue;
  otherwise it must log an `info` line carrying the redirect URIs, audience and whether a secret hash was pinned.
- `SPEC-9.5.11` `upsert_mokosh_webhook_url` must do nothing when `MOKOSH_WEBHOOK_URL` is unset, and otherwise must run
  `UPDATE applications SET webhook_url = <url> WHERE slug = 'mokosh'`. Zero affected rows must log a `warn` stating
  that account-deleted dispatch will not fire, and must not fail startup; a non-zero count must log an `info` line
  with the URL.

### 9.6 Startup: secrets, configuration and cache resolution

`bunyip-api/src/main.rs` (after the database steps). Refines `SPEC-2.2.3`.

- `SPEC-9.6.1` Startup must read `JWT_SECRET` through `secret_env` (`JWT_SECRET_FILE` or the plain variable; empty is
  unset). When unset and `config.is_production()` it must call `fatal_config_error("JWT_SECRET", ...)`; when unset
  otherwise it must use a fixed development placeholder. It must build `JwtConfig::from_secret(secret, app_name)` with
  `access_token_expiry` of 30 minutes and `refresh_token_expiry` of 30 days (the cookie and database deadline, not the
  JWT expiry, enforce the real 1-day or 30-day refresh lifetime).
- `SPEC-9.6.2` Startup must read `BUNYIP_WEBHOOK_SIGNING_SECRET` through `secret_env`, separate from `JWT_SECRET`, and
  use it as the only signing key of the outbound `WebhookService`. When unset and production it must call
  `fatal_config_error`; when unset otherwise it must use a fixed development placeholder.
- `SPEC-9.6.3` Startup must resolve the tier, email and auto-ban configurations each the same way: read the singleton
  row; a read failure must be logged at `error` naming the table and stating that the file and environment providers
  alone are used, and resolution must continue with no row; a row whose `database_provider` conversion fails must call
  `fatal_config_error` with the failure's variable, reason and remedy; otherwise build
  `ConfigStack::with_database(provider)`, call `log_shadowed_providers`, and resolve (`TierConfig::resolve`,
  `EmailConfig::resolve`, `AutoBanConfig::resolve`). The resolved tier configuration must be held as
  `Arc<RwLock<TierConfig>>`.
- `SPEC-9.6.4` Startup must read `rate_limit_configs`; on success it must call `log_shadowed_providers` on a stack
  built from `rate_limit_config::database_provider(&rows)`; on failure it must log an `error` stating that an
  environment cap overridden by an admin row is not reported, and must continue.
- `SPEC-9.6.5` Startup must call `FeatureToggleRepository::load`. On success it must log the loaded map at `info` and
  store it in the shared snapshot; on failure it must log an `error` stating that every feature stays off until the
  next refresh and continue with an empty (all off) snapshot.
- `SPEC-9.6.6` Startup must spawn a task that, every `FEATURE_TOGGLE_REFRESH_SECS` (`60`) seconds and with its first
  immediate tick skipped, calls `admin_feature_toggles::refresh_snapshot`.
- `SPEC-9.6.7` Startup must call `secrets::survey` with `InfisicalProbe::Inspect` only when
  `config.secrets_provider == Infisical`, else `Skip`, so Infisical is never a boot dependency of a `database` or
  `environment` deployment. When `secrets::enforce` returns any report, startup must log each as an `error` with field
  `env_var = "SECRETS_STORAGE"`, then `Refusing to start: fix the secrets-provider errors above and restart`, and exit
  with status `1`. Otherwise it must log an `info` line naming the provider.
- `SPEC-9.6.8` Startup must copy the survey's `SmtpPassword` value (empty string when absent) into
  `config.email.smtp_password` before the email service is built, and must pass the same value to
  `EmailConfig::resolve`.
- `SPEC-9.6.9` When `config.is_production()` and the resolved email configuration is not enabled, startup must call
  `fatal_config_error("SMTP_HOST", ...)`, because magic links and password resets would never be delivered.
- `SPEC-9.6.10` Startup must build the branding cache seeded with `config.app_name` (the bootstrap default for a
  database that was never branded). A failed first read of the branding row must be logged at `error` with the cause,
  stating that the bootstrap default is served until the next refresh, and must not abort startup; a successful read
  must be stored and logged with the brand name.
- `SPEC-9.6.11` Startup must spawn a task that, every `BRANDING_REFRESH_SECS` (`60`) seconds with the first tick
  skipped, re-reads the branding row and stores it; a failed refresh must be logged at `warn` and must keep the last
  loaded values rather than reverting to the bootstrap default.

### 9.7 Startup: service construction

`bunyip-api/src/main.rs`. Each service is built once and shared by `Arc` with the primary server (`SPEC-9.9.8`).

- `SPEC-9.7.1` Startup must build `EmailService` from the resolved email configuration; if construction fails it must
  log a `warn` with the cause and use `EmailService::new_dev()`. It must then attach the branding cache, so
  subjects and template `app_name` follow the branding record without a restart, and attach the shared
  `DbSuppressionList`, so every send path (not only the mailer relay) is guarded by the suppression table.
- `SPEC-9.7.2` Startup must build `MailerRelay` from the email service and the same suppression list, read
  `MAILER_WEBHOOK_SECRET` through `secret_env` (`None` when unset, in which case the feedback webhook must fail closed
  for want of a verification secret), and build one `HickoryMxResolver` shared by the feedback spam gate.
- `SPEC-9.7.3` Startup must build the GeoIP service from `IP2LOCATION_DB_PATH`: unset must log `info` and yield
  `None`; a load failure must log a `warn` carrying the path and the cause and yield `None`; neither case may block
  login. IP enrichment must be built the same way from `IP2PROXY_DB_PATH` independently of GeoIP.
- `SPEC-9.7.4` Startup must build the Mirzam sync handle with `mirzam_sync::mirzam_sync(pool, config, key_set)`
  (`SPEC-9.17.1`), share it with the auth service, and register it as app data.
- `SPEC-9.7.5` Startup must build `AuthService` from the primary pool, the JWT service, the shared tier-configuration
  lock, `config.bootstrap_admin_email`, the email service, the GeoIP service, `config.login_approval_enabled`,
  `config.country_allow` and `config.country_deny`, with the Mirzam sync attached.
- `SPEC-9.7.6` Startup must build the Stripe configuration from the `stripe_config` row (non-secret columns) and the
  declared secrets provider (secret key and webhook secret). A failed row read must be logged at `error`
  (`Failed to read stripe_config; starting with Stripe disabled`) and yield the unconfigured configuration. A missing
  secret key must yield the unconfigured configuration with an `info` line. A missing webhook secret must keep the
  unconfigured placeholder webhook secret.
- `SPEC-9.7.7` When Stripe is configured but the webhook signing secret is unset or the placeholder, startup must
  log a `warn` stating that the webhook endpoint rejects all events (fail closed).
- `SPEC-9.7.8` The Forgejo asset client must exist only when both `config.download.forgejo_base_url` and
  `forgejo_api_token` are set; the release cache and the disk download cache (with its Postgres store) must exist only
  when the client does. A failure to create the cache directory must be logged at `warn` and must not abort startup.
  The download limiter must be built from `concurrency_per_user` and `daily_limit_per_user`, and the daily counter from
  the primary pool. An `info` line must report whether downloads are enabled and the cache directory.
- `SPEC-9.7.9` The Forgejo registry client must exist only when both Forgejo settings in `SPEC-9.7.8` are set. The OCI
  manifest cache (TTL `config.oci.manifest_cache_ttl_secs`) and blob cache (directory and maximum bytes from
  `config.oci`, backed by `OciBlobCacheRepository`) must exist only when the client does; failure to create the blob
  cache directory must be logged at `warn` and must not abort startup.
- `SPEC-9.7.10` Startup must build `OciLimiter` from `concurrent_manifests_per_user` and `pulls_per_user_per_day`
  and `OciTokenService` from the JWT configuration and `config.oci.token_ttl_secs`. When `config.oci.enabled` and
  `config.oci.validate()` fails, startup must stop with `invalid OCI registry configuration: <cause>` before any
  listener binds.
- `SPEC-9.7.11` Startup must build `TotpService` with the app key set, `config.app_name` and the primary pool, attach
  the branding cache (new enrolments take the branded issuer; existing rows keep their label), build `WebhookService`
  from the key in `SPEC-9.6.2`, and build one in-process `EventBus`.
- `SPEC-9.7.12` Startup must build the OIDC provider only when `config.oidc.enabled()`: it must load the key set from
  `jwt_private_key_path`, `jwt_active_kid` and `jwt_public_keys_dir`; a load failure must be logged at `error` with
  the cause and terminate startup. When OIDC is disabled it must log `info` `OIDC provider disabled (OIDC_ISSUER not
  set)` and register `None`.
- `SPEC-9.7.13` Startup must register the OIDC provider as the access-token (`at+jwt`) verifier when present, and
  `DisabledAtJwtVerifier` otherwise, so the authentication extractors accept legacy HS256 access tokens alone when OIDC
  is off.
- `SPEC-9.7.14` Startup must choose the account-backup adapter for the hosted app: the real
  `MokoshHttpBackupAdapter` only when `MOKOSH_BACKUP_API_URL` is non-blank, the OIDC provider exists and the fixed
  hosted-app OAuth client row loads; when the URL is set but the client row is missing it must log an `error` and fall
  back to the pending stub `MokoshBackupAdapter`; when the URL is unset or OIDC is off it must use the stub. A database
  error while loading the client must propagate and terminate startup.
- `SPEC-9.7.15` Startup must build the auto-ban service from the resolved configuration and the primary pool, load the
  unexpired bans with `auto_ban::load_active_bans`, and, if that load fails, log an `error`
  (`Failed to load IP bans from database`) and continue with no bans loaded. It must log the enabled flag and
  threshold.
- `SPEC-9.7.16` Startup must build the update checker from `BUNYIP_UPDATE_CHECK_URL` (empty counts as unset, which
  disables the checker) and `BUNYIP_UPDATE_CHECK_TOKEN` (through `secret_env`), with the running crate version and the
  user agent `bunyip-api/<CARGO_PKG_VERSION>`.
- `SPEC-9.7.17` Startup must build one `reqwest::Client` with a 5-second timeout for OIDC back-channel logout
  delivery; a builder error must terminate startup with `failed to build backchannel logout HTTP client`. It must be
  built once and cloned per worker.
- `SPEC-9.7.18` Startup must spawn `support_ingest::spawn(pool, config, key_set)` unconditionally; the task itself must
  re-read its configuration each tick and do nothing while IMAP is disabled or unconfigured.

### 9.8 Background tasks

`bunyip-api/src/main.rs`. Every task runs in its own `tokio::spawn` loop for the life of the process.

- `SPEC-9.8.1` A failure inside one iteration of any background task in this subsection must be logged at `error` with
  the cause and must not end the loop; the next tick must run normally.
- `SPEC-9.8.2` The rate-limit cleanup task must call `RateLimitRepository::cleanup_expired` every 3600 seconds, log
  an `info` line with the deleted count only when it is non-zero, and on error log `Failed to cleanup expired rate
  limit entries`.
- `SPEC-9.8.3` The history retention task must call `RateLimitHistoryRepository::sweep(pool, 86400)` every 3600
  seconds, and the traffic retention task `RateLimitTrafficRepository::sweep(pool, 86400)` every 3600 seconds, each
  logging the deleted count at `info` only when non-zero (retention is 24 hours).
- `SPEC-9.8.4` The auto-ban cleanup task must, every 300 seconds, first call the in-memory
  `AutoBanService::cleanup_expired` and then `auto_ban::cleanup_expired_bans` on the database, logging the deleted
  count at `info` only when non-zero.
- `SPEC-9.8.5` The feedback task must call `FeedbackRepository::archive_and_purge_closed` every 86400 seconds and
  log the purged count at `info` only when non-zero.
- `SPEC-9.8.6` The grace-period task must call `UserRepository::end_expired_grace_periods` every 3600 seconds. For each
  returned `(user_id, email, role)` it must write an audit log entry of action `GracePeriodEnded` with that user as
  actor and resource `user`; an audit write failure must be logged at `error` with the user id and must not stop the
  remaining entries. The sweep must not be what denies access (the access predicates deny after `grace_period_end`
  on their own); it exists to keep `membership_status` accurate.
- `SPEC-9.8.7` The e2e disposable-account reaper must be spawned only when `config.e2e_purge_enabled()` (a
  non-production environment and `BUNYIP_E2E_BOOTSTRAP_ALLOW=true`) and must log `info` on start. Every 3600 seconds it
  must hard-delete accounts through `UserRepository::hard_delete_stale_disposable` whose email matches `%+e2e-%` and
  that are older than `E2E_REAPER_MAX_AGE_SECS` (6 hours), so it can never race a live test or run in production.
- `SPEC-9.8.8` For each account the reaper returns that was not already soft-deleted, it must notify the Mirzam sync
  with `AccountChange::Deleted { user_id, email, was_verified }`; an already soft-deleted account must not be notified
  again.
- `SPEC-9.8.9` The cleanup, retention, auto-ban, feedback, grace-period and reaper tasks use `tokio::time::interval`
  without skipping the first tick, so each runs once immediately at startup; the branding and feature-toggle refresh
  tasks must skip the first tick because their data was just loaded.

### 9.9 Primary HTTP server

`bunyip-api/src/main.rs`. Refines `SPEC-2.2.4` and `SPEC-2.2.5`.

- `SPEC-9.9.1` The primary `HttpServer` must bind `config.server_addr()` (`<host>:<port>`) and run with a graceful
  `shutdown_timeout` of 30 seconds. A bind failure must terminate `main` with the error (non-zero exit).
- `SPEC-9.9.2` The allowed browser origins must be the `CORS_ORIGIN` value split on `,`, trimmed, with empty entries
  dropped. CORS must echo only those origins, with credentials, and must not register `allowed_origin_fn` or any
  wildcard or prefix/suffix origin match, because that reflects credentialed CORS to attacker-controlled hosts.
- `SPEC-9.9.3` CORS must allow exactly the methods `GET, POST, PUT, PATCH, DELETE, OPTIONS`, the request headers
  `Authorization, Accept, Content-Type, Cookie`, expose `Set-Cookie`, support credentials, and cache preflights for
  `3600` seconds.
- `SPEC-9.9.4` The CSRF guard must be `dunite_core::middleware::OriginGuard` built from the same origin list as
  `SPEC-9.9.2`, with exempt path prefixes exactly `/oauth2/`, `/.well-known/` and `/v1/webhooks/stripe` and ambient
  cookie names exactly `access_token` and `refresh_token`. It must run inside CORS so CORS answers preflights; the guard's rejection
  rule (a state-changing request carrying an ambient cookie with an `Origin` or `Referer` outside the list) is
  implemented in `dunite-core`.
- `SPEC-9.9.5` The Content-Security-Policy configuration must set `connect_src` and `form_action` to the same origin
  list as `SPEC-9.9.2` and nothing else beyond the locked-down default.
- `SPEC-9.9.6` The primary application must wrap, from outermost to innermost: `AutoBanMiddleware`, `RateLimitFloor`,
  CORS, the CSRF guard, `RequestIdMiddleware`, `SecurityHeaders::with_csp`, `access_log::access_logger()`,
  `TracingLogger<ClientIpRootSpanBuilder>`, `actix_web::middleware::Compress` (`SPEC-2.2.5`). Auto-ban must be
  outermost so a banned address is rejected before it costs a rate-limit row or a CORS evaluation.
- `SPEC-9.9.7` The primary application must register the extractor configurations from `extractors` (`SPEC-9.14.6`)
  before any route is added, and must mount the routes through `routes::configure`.
- `SPEC-9.9.8` The primary application must register as shared state, per worker, clones of: the primary `PgPool`,
  `AppPool`, the same auto-ban service `Arc` the middleware holds, the process start `Instant`, the error-log buffer,
  the JWT service, the at+jwt verifier, the auth, Mirzam, email, mailer relay, suppression, `MailerWebhookSecret`,
  Stripe, TOTP, webhook, backup, event bus and app key set services, the `Config`, the download limiter, download
  counter, release cache and download cache, the manifest cache, blob cache, OCI limiter, OCI token service, `OciConfig`
  and Forgejo registry client, the OIDC provider `Option` (handlers answer `404` when it is `None`), the back-channel
  HTTP client, tier configuration, pricing cache (TTL `PRICING_CACHE_TTL_SECS`), branding cache, feature-toggle
  snapshot, update checker, IP enrichment, and the MX resolver.
- `SPEC-9.9.9` Before awaiting, startup must print to stdout a banner containing the primary address, the OIDC issuer
  when configured, and the OCI registry address when the OCI server will start (`SPEC-9.10.1`).

### 9.10 OCI registry server

`bunyip-api/src/main.rs`. Refines `SPEC-2.2.4` and `SPEC-2.2.5`.

- `SPEC-9.10.1` The OCI server must start only when `config.oci.enabled` is true and a Forgejo registry client exists
  (`SPEC-9.7.9`); it must bind `<config.host>:<config.oci.port>` and use `shutdown_timeout` 30 seconds, and a bind
  failure must terminate `main` with the error.
- `SPEC-9.10.2` When `config.oci.enabled` is true but the Forgejo settings are missing, startup must log a `warn`
  `OCI_REGISTRY_ENABLED=true but FORGEJO_BASE_URL / FORGEJO_API_TOKEN are unset - OCI registry server will NOT be
  started`, and must continue on the primary server alone.
- `SPEC-9.10.3` When the OCI server does not start, startup must log an `info` line stating the three conditions
  required and must await only the primary server.
- `SPEC-9.10.4` The OCI application must wrap, from outermost to innermost: `WwwAuthenticate` (built from
  `OciConfig::realm_url()` and `OciConfig::service`), `RequestIdMiddleware`, `SecurityHeaders::new()` (the default
  policy, no extra origins), `access_log::access_logger()`, `TracingLogger<ClientIpRootSpanBuilder>`. It must not
  register CORS, CSRF, auto-ban, the rate-limit floor or `Compress`.
- `SPEC-9.10.5` The OCI application must register as shared state clones of the primary `PgPool`, the OCI token service
  both as a raw `Arc` (for the bearer extractor) and as `web::Data` (for the token handler), the manifest cache, blob
  cache, OCI limiter, daily pull counter, `OciConfig` and Forgejo registry client, and must mount
  `bunyip_oci::routes::configure`. It must not register `Config`, so no proxy is trusted and the access log shows the
  socket peer.
- `SPEC-9.10.6` When both servers run, startup must await them with `tokio::try_join!`, so the first server to exit
  with an error ends the process with that error.

### 9.11 Maintenance subcommands and the config-status survey

`bunyip-api/src/main.rs` `run_subcommand` and `bunyip-api/src/config_status.rs`. Refines `SPEC-2.2.2`.

- `SPEC-9.11.1` `run_subcommand` must recognise exactly these names and no others: `secrets-status`,
  `secrets-migrate`, `secrets-purge`, `config-status`, `machine-client`, `reconcile-duplicate-prices`,
  `settings-export`, `settings-import`, `mirzam-backfill`, `reencrypt-secrets`. Any other name must return the error
  `unknown subcommand "<name>" (known: ...)` listing all ten (`SPEC-2.2.2`). Any error returned must make the process
  exit non-zero, and success must exit `0`.
- `SPEC-9.11.2` Secrets subcommands must call `secrets::survey` with `InfisicalProbe::Inspect` when
  `config.infisical.enabled` or the declared provider is Infisical, else `Skip`.
- `SPEC-9.11.3` `secrets-status` must print the status report as pretty JSON when `--json` is among the arguments and
  as the rendered text otherwise.
- `SPEC-9.11.4` `secrets-migrate` must require `--to <provider>` where the value parses as a `SecretsProvider`; a
  missing flag, missing value or unparseable value must fail with `secrets-migrate needs --to <LEGAL_VALUES>`. It must
  accept `--dry-run` and `--allow-missing`, and must print the migration summary.
- `SPEC-9.11.5` `secrets-purge` must treat `--confirm` as the sole switch that performs the purge, and must print the
  summary.
- `SPEC-9.11.6` `config-status` must print the report as pretty JSON with `--json` and as rendered text otherwise, and
  must contain no configuration value.
- `SPEC-9.11.7` `config_status::survey` must merge into one database provider the provider of each of: the
  `email_config` row, the `tier_config` row, the `auto_ban_config` row and the `rate_limit_configs` rows, and return
  the `ConfigStack` over it. A row that cannot be read must be logged at `error` naming the table and contribute
  nothing. A row holding a Group-1 key must fail the survey with `AppError::BadRequest("<var> is not usable - <reason>.
  <remedy>")`.
- `SPEC-9.11.8` `machine-client` must pass the remaining arguments and `config.email.base_url` to
  `machine_client::run` and print the returned report to stdout; the plaintext secret is printed there and nowhere else
  (`SPEC-9.12.9`).
- `SPEC-9.11.9` `reconcile-duplicate-prices` must be read-only unless `--apply` is present. It must build the Stripe
  service from the `stripe_config` row and the secrets survey exactly as `SPEC-9.7.6` does (a failed row read logged at
  `error` and treated as Stripe disabled) and print the report from `reconcile_prices::reconcile`.
- `SPEC-9.11.10` `settings-export` must require `--passphrase-file <path|->` and `--output <path>`; each missing flag
  must fail with a message naming the flag. The passphrase must come only from a file or standard input, never from a
  flag value. It must accept `--include-catalog` and `--include-oauth-clients`, export, seal with the passphrase,
  write the archive, and print a line naming the output path, that its mode is `0600`, and that it holds every
  integration secret once opened. An existing output path must be refused.
- `SPEC-9.11.11` `settings-import` must require `--passphrase-file <path|->` and `--input <path>`. With `--dry-run`
  it must print the import plan and write nothing. Otherwise it must apply the snapshot and print the report; when
  any step did not apply it must print the full report first and then fail with `settings-import did not complete: N
  step(s) did not apply (<steps>)...`, giving a non-zero exit. A re-run of the same import is the recovery, because
  every step is a replace.
- `SPEC-9.11.12` `mirzam-backfill` must call `mirzam_sync::backfill` with `MIRZAM_RETRY_DELAYS` and
  `MIRZAM_BACKFILL_PACE`, log an `info` line with the added, already-on, left-alone and failed counts, print the
  report, and, when the failed count is above zero, fail with `mirzam-backfill: N account(s) failed...` giving a
  non-zero exit after the counts are printed.
- `SPEC-9.11.13` `reencrypt-secrets` must call `reencrypt::reencrypt_all` with the current key set, log the summary at
  `info`, print `reencrypt-secrets: <summary>` and one `undecryptable, left untouched: <item>` line per undecryptable
  value, and, when any value is undecryptable, fail with the count and a prompt to add the missing key and re-run
  (non-zero exit).
- `SPEC-9.11.14` The `flag_value` helper used by the subcommand parser must return the argument following the flag
  verbatim, including a following token that starts with `--`, and `None` when the flag is absent or last.

### 9.12 The machine-client command

`bunyip-api/src/machine_client.rs`. `bunyip-api machine-client <verb>` provisions the credential a calling app presents
to the mailer relay.

- `SPEC-9.12.1` The verbs must be exactly `register`, `rotate`, `disable` and `list`. A missing verb must fail with
  `machine-client needs a verb`, and an unknown verb with `unknown machine-client verb "<verb>"`; every parse failure
  must append the `USAGE` text and no invocation may be a silent no-op.
- `SPEC-9.12.2` `register` must require `--name <name>`; it must accept repeatable `--grant`, `--secret-key` and
  `--config-key` flags. A flag value that is missing or itself starts with `--` must count as missing.
- `SPEC-9.12.3` Every `--secret-key` value must be a member of `HOST_SECRET_KEYS` and every `--config-key` value a
  member of `HOST_CONFIG_KEYS`, checked at parse time against its own set; a value outside its set (including a key of
  the other registry) must fail with `machine-client register: "<key>" is not a <what> this deployment serves. Known
  keys: <list>` followed by the usage text, so a typo is a usage error and not a later `404`.
- `SPEC-9.12.4` A registration must be `client_type = 'confidential'` with `token_endpoint_auth_method =
  'client_secret_basic'`, a fresh random `client_id`, empty `redirect_uris`, `post_logout_redirect_uris` and
  `allowed_scopes`, `require_pkce = TRUE`, and `audience` equal to `<base_url without trailing slashes>/v1`.
- `SPEC-9.12.5` `allowed_grant_types` must always begin with `MACHINE_GRANT`, followed by each extra `--grant` in order
  without duplicates; the secret-key and config-key lists must each keep the first spelling of each key and drop
  repeats; both default to empty, which grants no host-secret or host-config read.
- `SPEC-9.12.6` The client secret must be generated with `generate_opaque_token(32)` and hashed with
  `bunyip_oidc::machine_client::hash_client_secret`; only the hash may be stored. The `Debug`
  rendering of `Secret` must be `Secret(redacted)`.
- `SPEC-9.12.7` `rotate --client-id <uuid>` must fail with `no registration with client_id <id>` for an unknown id, fail
  when `token_endpoint_auth_method` is not `client_secret_basic` (the row holds no machine credential), fail when the
  row is disabled (`register a new machine client instead of rotating a revoked one`), and otherwise replace only
  `client_secret_hash` and print the new secret once.
- `SPEC-9.12.8` `disable --client-id <uuid>` must set `disabled_at = NOW()` when the row is not already disabled and
  print that the relay now answers `401`; for an already disabled row it must change nothing and print that it was
  already disabled. A `--client-id` that is missing or not a UUID must fail with a message naming the verb.
- `SPEC-9.12.9` The plaintext secret must appear only in the report returned by `register` and `rotate`, which
  states that it is shown once and not stored; this module must not call any logging or printing macro, and nothing
  except the hash may be written to the database.
- `SPEC-9.12.10` `list` must print one row per `oauth_clients` row with `client_type = 'confidential'`, ordered by
  `name`, with columns `client_id`, `name`, `state` (`active` or `disabled`) and the comma-joined grants, or the line
  `no confidential registrations; nothing holds a machine credential` when there are none.

### 9.13 Host-secret and host-config registries

`bunyip-api/src/host_secrets.rs` and `bunyip-api/src/host_config.rs` define what a registered machine client may read
through `/v1/host/secrets/{KEY}` and `/v1/host/config/{KEY}`.

- `SPEC-9.13.1` A host secret key must be servable only if it is a variant of `HostSecret`; the only variant must have
  the key `mokosh/google_oauth_client`. `HostSecret::parse` must return `None` for every other string, including a
  governed secret's own name, a key with trailing whitespace, a prefix, and the empty string.
- `SPEC-9.13.2` `HOST_SECRET_KEYS` must be built from the variants' `key()`, so the list and the variants cannot drift,
  and is the set `machine-client register --secret-key` validates against (`SPEC-9.12.3`).
- `SPEC-9.13.3` `HostSecret::resolve` for the Google client must return `Ok(None)` when the governed secret
  `MokoshGoogleClientSecret` is absent or when the trimmed `google_client_id` of the `mokosh_config` row is empty (both
  halves or neither), and otherwise `Ok(Some(json))` where `json` serialises exactly `{"client_id": ..., "client_secret":
  ...}` with those two fields only. A serialisation failure must return an internal error
  `could not serialise the host secret: <cause>`; a repository or secret read error must propagate as an error, not
  as `None`.
- `SPEC-9.13.4` A host config key must be servable only if it is a variant of `HostConfig`; the only variant must have
  the key `mokosh/abuse_contact_email`. `HostConfig::parse` must return `None` for every other string, including the
  name of any `GovernedSecret` and any key in `HOST_SECRET_KEYS`, and `HostSecret::parse` must return `None` for every
  key in `HOST_CONFIG_KEYS`, so the two registries cannot be crossed by naming a key.
- `SPEC-9.13.5` `HostConfig::resolve` for the abuse-contact key must be synchronous, must read only the already
  resolved `Config`, and must return the trimmed `config.email.support_inbox_email`, or `None` when it is unset or
  blank; it must not query the database.

### 9.14 Request observability, extractor errors and response compression

`bunyip-api/src/access_log.rs`, `root_span.rs`, `error_log.rs`, `extractors.rs`, `compress.rs`.

- `SPEC-9.14.1` `access_logger()` must return an actix `Logger` with the format `%{client_ip}xi "%r" %s %b
  "%{Referer}i" "%{User-Agent}i" %T`, where `client_ip` is `extract_client_ip(request)` rendered as text, or `-` when
  no address can be determined.
- `SPEC-9.14.2` The client address in the access log must honour `X-Forwarded-For` or `X-Real-IP` only when the socket
  peer is within `TRUSTED_PROXY_CIDR`; without a `Config` in app data (as on the OCI server) it must be the socket
  peer, and a forged forwarding header must be ignored.
- `SPEC-9.14.3` `ClientIpRootSpanBuilder::on_request_start` must create an `info` span named `HTTP request` with the
  fields `http.method`, `http.route` (the matched pattern, else `default`), `http.flavor`, `http.scheme`, `http.host`,
  `http.client_ip`, `http.user_agent`, `http.target` (path and query), `http.status_code` (empty), `otel.name`
  (`<method> <route>`), `otel.kind = "server"`, `otel.status_code` (empty), `trace_id` (empty), `request_id`,
  `exception.message` and `exception.details` (empty). `http.client_ip` must come from `extract_client_ip` (empty when
  undeterminable), never from the spoofable realip, and must be set at span creation, never overwritten afterwards,
  because the formatter appends on `record` and would emit the field twice.
- `SPEC-9.14.4` The span's `request_id` must be the id the request-id middleware stored in the request extensions (the
  value echoed in `X-Request-Id`), falling back to the `tracing_actix_web` id, then to the empty string.
  `on_request_end` must delegate to `DefaultRootSpanBuilder`.
- `SPEC-9.14.5` `error_log` must re-export `ErrorLogBuffer`, `ErrorLogEntry`, `ErrorLogLayer` and `DEFAULT_CAPACITY`
  from `dunite_core::error_log`; the buffer registered as app data must be the same instance the capture layer writes
  to, and its entries are lost on restart.
- `SPEC-9.14.6` `extractors` must provide `json_config()`, `path_config()`, `query_config()` and `form_config()`. Each
  rejection must be logged at `warn` (`rejected malformed request`) with the extractor kind (`json`, `path`, `query`,
  `form`) and the underlying parse error, and must return `400` in the `AppError` envelope with code `BAD_REQUEST`.
- `SPEC-9.14.7` The client message of those rejections must be exactly `The request body was malformed or invalid.` for
  JSON and form bodies and `Invalid request.` for path and query parameters, and must carry none of the framework's
  parse text (field names, positions).
- `SPEC-9.14.8` The JSON body limit must be `32768` bytes.
- `SPEC-9.14.9` `compress::mark_uncompressed` must insert the header `Content-Encoding: identity` on the response, which
  makes `Compress` leave the body alone. It must be applied to every streamed response (`GET /v1/events`, the
  release-asset downloads) and to every response whose `content_type` is a runtime value (the public branding asset,
  the avatar, and the admin feedback attachment), so no stored image or archive pays a compression pass and no handler
  loses its `Content-Length`.
- `SPEC-9.14.10` The primary router must not mount the OCI vertical: the OCI blob stream is the one streamed response
  not marked, because the OCI server carries no `Compress` layer.

### 9.15 Default rate-limit floor

`bunyip-api/src/rate_limit_floor.rs`. Refines `SPEC-2.2.5` (second layer).

- `SPEC-9.15.1` `RateLimitFloor` must apply a default cap under every route of the primary server, so an endpoint that
  adds no `check_rate_limit` of its own is still throttled; per-endpoint caps are tighter and still run inside it.
- `SPEC-9.15.2` The floor must not apply to an `OPTIONS` request or to a request whose path equals, exactly and
  case-sensitively, one of: `/`, `/health`, `/version`, `/e2e-bootstrapped`, `/v1/health`, `/v1/version`,
  `/v1/auth/register-challenge`, `/v1/webhooks/stripe`, `/v1/pricing`, `/v1/auth/setup/status`, `/v1/mailer/send`,
  `/v1/mailer/webhooks/feedback`. A longer path or a near miss (for example `/v1/healthz`, `/v1/mailer`) must be
  floored.
- `SPEC-9.15.3` For a floored request the key must be the verified subject id with the `API_AUTH` preset (100 requests
  per 60 seconds per user) when `resolve_rate_limit_subject` yields one, and otherwise the trusted client IP (the
  literal `unknown` if none) with the `API_UNAUTH` preset (60 requests per 60 seconds per IP), so presenting an
  unverifiable token never buys the larger budget.
- `SPEC-9.15.4` The floor must count the request with `RateLimitRepository::check_and_increment`; when the cap is
  exceeded it must not call the inner service and must answer `429` with headers `Retry-After` (seconds) and
  `X-RateLimit-Bucket` (the preset's action), and the body `{"success": false, "error": {"code": "RATE_LIMITED",
  "message": "rate limit exceeded", "details": {"retry_after": <seconds>, "bucket": <action>}}}`.
- `SPEC-9.15.5` On a throttled request the floor must log a `warn` `request cap floor exceeded` with the action and
  the request path. `retry_after` must come from `RateLimitRepository::get_retry_after`.
- `SPEC-9.15.6` When the rate-limit check itself fails, the floor must pass the request through to the inner service
  (fail open, so a rate-limit table outage does not take the API down) and must log the failure at `error`
  (`request cap floor check failed; passing through`) with the cause.
- `SPEC-9.15.7` The floor must borrow the inner `HttpRequest` and must never hold a clone of it across the inner
  `service.call`, because the router asserts sole ownership of the request in `match_info_mut` and a clone panics the
  worker.

### 9.16 Database plumbing and pool metrics

`bunyip-api/src/db.rs` (`AppPool`, `begin_with_user`) and `bunyip-api/src/db_metrics.rs`.

- `SPEC-9.16.1` `AppPool` must be a distinct newtype over `PgPool`, so app state can distinguish the self-service pool
  from the system `web::Data<PgPool>`; only genuinely self-service paths (a logged-in user reading or writing their
  own rows) may use it, and pre-auth, cross-user, Stripe-webhook, OIDC and admin paths must use the system pool.
- `SPEC-9.16.2` `begin_with_user(pool, user_id)` must begin a transaction and, as its first statement, run
  `SELECT set_config('app.current_user_id', $1, true)` with the user id bound as a parameter (never interpolated), so
  the setting is transaction-local and cannot leak to the next request on a pooled connection. A begin or statement
  failure must return the converted `AppError`.
- `SPEC-9.16.3` Self-service queries must run on the transaction `begin_with_user` returns and must commit it; a query on
  a fresh pool checkout does not see the setting and, as a `NOBYPASSRLS` role, returns zero rows (fail closed).
- `SPEC-9.16.4` `acquire_timeouts()` must return the process-wide count of database acquisitions that timed out waiting
  for a free connection; the counter must always be live, whether or not sampling is enabled.
- `SPEC-9.16.5` An acquire timeout is recognised by the substring `pool timed out` (`ACQUIRE_TIMEOUT_SIGNATURE`) in the
  rendered form of any field of an `ERROR` event, because the conversion from `sqlx::Error` is inside a git
  dependency; a test must fail the build if sqlx rewords it.
- `SPEC-9.16.6` `AcquireTimeoutLayer` must, for each `ERROR`-level event whose any field renders the signature,
  increment the counter by exactly one, and must ignore events of every other level.
- `SPEC-9.16.7` `sampling_interval()` must read `DB_POOL_METRICS_INTERVAL_SECS` and return `None` (sampling off) when it
  is unset, empty after trim, or `0`; when it is present but non-UTF-8 or not a whole number of seconds it must log a
  `warn` carrying the cause or value and return `None`.
- `SPEC-9.16.8` When sampling is on, `spawn_sampler` must log an `info` line with the interval and pool count and then,
  every interval, call `log_sample` for each `(label, pool)`, which must log `database pool sample` with the fields
  `pool`, `size`, `idle`, `in_use` (`size - idle`, saturating) and `acquire_timeouts`. When off it must start nothing.

### 9.17 Account integrations: Mirzam sync, backup adapter and provider status

`bunyip-api/src/mirzam_sync.rs`, `mokosh_backup.rs`, `provider_status.rs`.

- `SPEC-9.17.1` `mirzam_sync::mirzam_sync(pool, config, key_set)` must return a `MirzamSync` whose token source reads
  `MirzamApiToken` through `secrets::read_secret` on every sync (so a token saved on the admin page applies at once);
  a read error must be returned to the sync as its text.
- `SPEC-9.17.2` `mirzam_sync::notify(sync, change)` must forward the change when a handle is present and do nothing when
  the handler's `Option<web::Data<MirzamSync>>` is `None`, so an app built without the handle sends nothing and does
  not fail the request.
- `SPEC-9.17.3` `mirzam_sync::backfill` must fail, before calling the remote service, with: `the Mirzam integration is
  switched off; switch it on on the admin Mirzam page first` when the saved row is not enabled; `the Mirzam integration
  is incomplete; set the address and both list slugs on the admin Mirzam page` when `active_lists` yields `None`;
  `MIRZAM_API_TOKEN is not set in the <provider> provider` when the token is absent or blank. Otherwise it must build a
  `MirzamClient` from the saved base URL and token and return the backfill report.
- `SPEC-9.17.4` `MokoshHttpBackupAdapter::slug()` must be `mokosh`. `backup` must mint an access token for `ctx.user_id`
  and `GET <base_url without trailing slash>/api/v1/data/export` with it as bearer.
- `SPEC-9.17.5` The minted token must be for the acting user with scopes `openid` and `email`, the OAuth client's
  audience and TTL, `acr` `urn:bunyip:loa:pwd`, no `sid` claim and no extra claims; a user that does not exist must
  fail with `AppError::not_found("User")`.
- `SPEC-9.17.6` A `2xx` export response must yield `AppBackupOutcome::Produced(<json body>)`; any other status must yield
  `AppBackupOutcome::Unavailable("Mokosh export returned HTTP <status>")` (not fatal to the overall backup); a
  transport failure or a body that is not JSON must fail with `AppError::upstream`.
- `SPEC-9.17.7` `restore` must first require the string field `tenant_name` in the bundle, failing with
  `AppError::bad_request("Mokosh backup bundle is missing tenant_name; cannot restore")` before any token is minted,
  then `POST <base>/api/v1/data/import` with body `{"confirm": <tenant_name>, "export": <bundle>}`, returning
  `Ok(true)` for a `2xx` status and `Ok(false)` otherwise; a transport failure must fail with `AppError::upstream`.
- `SPEC-9.17.8` `provider_status::own_report` must return `hosting_profile = "bunyip"`, an empty `deviations`, no
  `configuration_generation`, a `collected_at` of the current time, and exactly two kinds in this order:
  `configuration`, then `secrets_application`.
- `SPEC-9.17.9` The `configuration` kind must list each provider of the stack in priority order with its index as
  `priority` and `reachable` false (carrying the error as `unreachable_reason`) exactly when the status report lists it
  as unreadable; `serving` must be the first provider in priority; each key must carry `recorded_served_by` equal to
  the serving provider and `live_holds` true exactly when a provider serves it.
- `SPEC-9.17.10` The `secrets_application` kind must list every `SecretsProvider` in `ALL` order with its index as
  `priority`; the Infisical entry must report `reachable` false with the survey's error text when Infisical was probed
  and failed, and every other entry `reachable` true; `serving` must be the declared provider; each governed secret
  must appear as a key with `state = "unchanged"`, `recorded_served_by` equal to its live source and `live_holds`
  true exactly when a live source exists.
- `SPEC-9.17.11` `provider_status::remote_apps()` must always return both remote applications (`mokosh`, then
  `drillmark`), never dropping one, with `status_url` from `MOKOSH_PROVIDER_STATUS_URL` or
  `DRILLMARK_PROVIDER_STATUS_URL` (`None` when unset or blank) and the same `MachineCredential` built from
  `PROVIDER_STATUS_CLIENT_ID` and `PROVIDER_STATUS_CLIENT_SECRET` (the latter through `secret_env`) only when both are
  non-blank, else `None`; the consumer reports a missing URL or credential as unreachable.

### 9.18 Maintenance passes: re-encryption, price reconciliation and branding assets

`bunyip-api/src/reencrypt.rs`, `reconcile_prices.rs`, `branding_assets.rs`.

- `SPEC-9.18.1` `reencrypt_all` must run, in order and merging the summaries: TOTP secrets (active and pending),
  Stripe `secret_key` and `webhook_secret`, email `smtp_password` and `imap_password`, Mirzam `api_token`, and the
  hosted-product `google_client_secret`; this is the complete list of columns encrypted under the app key set, and a
  new encrypted column must be added to it.
- `SPEC-9.18.2` For each value, a rewrite that `EncryptionKeySet::rewrite` reports as needed must be stored under the
  current key and counted in `rewritten`; a value already on the current key and version must be counted in
  `already_current` and not written (so a second pass rewrites nothing); a value no key in the set can decrypt must be
  appended to `undecryptable` as `<table> <identifier>` and left untouched, never cleared or overwritten.
- `SPEC-9.18.3` A NULL ciphertext or NULL nonce must be skipped without counting; for TOTP, the pending
  `(secret, nonce, version)` triple is processed only when all three are non-NULL.
- `SPEC-9.18.4` The Stripe pass must write the shared `key_version` (the current version) only when at least one value
  was rewritten. A database read or write error in any pass must propagate and stop the pass.
- `SPEC-9.18.5` `ReencryptSummary` must render as `<n> rewritten, <n> already current, <n> undecryptable`.
- `SPEC-9.18.6` `reconcile` must return `Stripe is not configured; nothing to reconcile.` with no error when the Stripe
  service is not configured. Otherwise it must list all prices, read the tier configuration, and consider only active
  prices.
- `SPEC-9.18.7` A price is referenced when it maps to a tier column in `tier_config`, has a `stripe_price_entitlements`
  row, or has at least one member on its tier or locked to it through `users.locked_price_id`. The `subscriptions`
  table must not be consulted.
- `SPEC-9.18.8` Active prices must be grouped by `ActivePriceKey` (product, currency, interval, interval count); only
  groups of two or more are planned, sorted by product id, currency, interval, interval count. A group with at least
  one referenced and one unreferenced price must archive every unreferenced price and keep the referenced ones. A group
  with none referenced must be skipped (`choose one by hand`), and a group with all referenced must be skipped
  (`migrate references, then archive by hand`); neither may be touched.
- `SPEC-9.18.9` Without `apply`, each report line must be prefixed `[dry-run] ` and no price may be archived or audit row
  written. With `apply`, each archive must call `StripeService::archive_price` and then write an
  `AdminStripePlanArchived` audit log whose metadata holds `source = "reconcile-duplicate-prices"`, `product_id`,
  `archived_price_id`, `kept_price_ids`, `currency`, `recurring_interval` and `recurring_interval_count`; an error in
  either step must stop the run and propagate.
- `SPEC-9.18.10` The report must end with `Summary: <archived|would archive> N orphan price(s), skipped N group(s),
  scanned N product(s).` and, when no group is planned, include `No duplicate active prices found.` first.
- `SPEC-9.18.11` The derivations in `branding_assets` are CPU-bound and must be called on the blocking pool, never on a
  request future; each returns the complete new content of its slot, so the caller writes the set as one unit.
- `SPEC-9.18.12` Each derivation must reject an input whose format `image::guess_format` cannot identify with
  `Could not read that file as an image.` and an undecodable input with `Could not read that image: <cause>`, and must
  return no assets in either case; an encode failure must return `Could not encode the <w>px icon: <cause>` or
  `Could not encode favicon.ico: <cause>`.
- `SPEC-9.18.13` `derive_favicons` must produce, for every entry of `DERIVED_FAVICONS`, a square image at its size by
  `resize_to_fill` with Lanczos3 (centre-cropping a non-square source), encoded as a single-frame ICO when the entry's
  MIME is `image/x-icon` and as PNG (best compression, adaptive filter) otherwise, and must append the original bytes
  last under `FAVICON_SOURCE_KIND` with the detected MIME type.
- `SPEC-9.18.14` `derive_mark` must produce one PNG of kind `mark` whose long edge is `MARK_DERIVED_SIZE` (`64`) by
  aspect-preserving `resize` (never cropping), followed by the original under `MARK_SOURCE_KIND`; `derive_mascot` must
  produce for each entry of `DERIVED_MASCOTS` (`mascot` at `448`, `mascot-2x` at `896`) a PNG by aspect-preserving
  `resize`, followed by the original under `MASCOT_SOURCE_KIND`.

### 9.19 Operator seed binaries

`bunyip-api/src/bin/bunyip_e2e_bootstrap.rs`, `seed.rs`, `gen_demo_seed.rs`. Refines `SPEC-2.1.3`.

- `SPEC-9.19.1` `bunyip-e2e-bootstrap` must accept only `--cleanup`, `--dry-run`, `--enable-2fa`, `--help` and `-h`; any
  other argument must fail with `unknown argument: <arg> (try --help)`, and help must print and exit `0`.
- `SPEC-9.19.2` After loading configuration (failure: `failed to load configuration`), `bunyip-e2e-bootstrap` must
  refuse to run, before any database connection, unless the variable `BUNYIP_E2E_BOOTSTRAP_ALLOW` equals `true` after trim
  and `config.environment` is non-empty and not `production` (case-insensitive); each refusal must fail with a
  `refusing to run` message.
- `SPEC-9.19.3` It must parse the compiled-in `seed/e2e.json` template before any write, failing with `e2e.json template
  is invalid: <cause>`. With `--dry-run` it must print what it would seed (or delete with `--cleanup`) and write nothing,
  and must not open a database connection.
- `SPEC-9.19.4` Otherwise it must connect with at most 2 connections and a 5-second acquire timeout and must not run
  migrations; `--cleanup` must call `seed::reset` with the template's owned scope (exactly `E2E_ACCOUNT_EMAILS`, no
  domain) and print the removed account and feedback counts; without `--cleanup` it must call `seed::load` and print
  the seeded account count.
- `SPEC-9.19.5` `--enable-2fa` must, after seeding, refuse with an error when `config.app_encryption_key` is the all-zero
  development key, require `BUNYIP_E2E_TOTP_SECRET` (trimmed, non-empty) and, for every address in
  `E2E_ACCOUNT_EMAILS`, find the account (failing `seeded account <email> not found for 2FA enrollment`) and enroll that
  preset secret through `TotpService::enroll_preset`, printing the enrolled count; an enrollment error must fail with
  `2FA enrollment for <email> failed: <cause>`.
- `SPEC-9.19.6` `seed` must accept `--dry-run`, `--help`/`-h` and the positional commands `import <file>` and `reset
  [file]`. After loading configuration it must, before touching the database, call `seed::seed_guard(environment,
  allow)` with `allow` true only when `BUNYIP_SEED_ALLOW` equals `true` after trim, and fail if the guard fails.
- `SPEC-9.19.7` `seed import <file>` must read and `seed::parse` the file (errors: `failed to read <path>`, the parse
  error), print a validation summary and exit without connecting under `--dry-run`, and otherwise connect (at most 4
  connections, 5-second acquire timeout) and call `seed::load`, printing counts of groups, apps, users, entitlements and
  feedback. A missing file argument must fail with `usage: seed import <file> [--dry-run]`.
- `SPEC-9.19.8` `seed reset [file]` must use the named file's effective `owns` scope, or `SeedOwns::reserved()` (the
  reserved seed domain) when no file is given; under `--dry-run` it must print the targeted domains and emails and write
  nothing; otherwise it must call `seed::reset` and print the removed user and feedback counts.
- `SPEC-9.19.9` `seed` with no command or an unknown command must print help and fail with `unknown or missing command`.
- `SPEC-9.19.10` `gen-demo-seed [path]` must never open a database. It must emit the demo template as pretty-printed
  JSON followed by a newline, deterministically and byte-stably (no randomness and no clock), to `path` (printing
  `wrote <path>` to stderr) or to stdout when no path is given; a write failure must return the I/O error.
- `SPEC-9.19.11` The generated template must contain version `1`, owned scope of the reserved demo email domain only, 3
  application groups, 8 applications, 42 users (2 admins, 3 lifetime members, 12 price-locked early adopters among the
  active non-lifetime members, 2 unverified), 6 entitlements to the two restricted apps, and 7 feedback entries
  including one marked spam, and must be identical to the committed `seed/demo-msp.json`.

### 9.20 Route tree assembly

`bunyip-api/src/routes/mod.rs` builds the route table that the primary server of `SPEC-2.2.4` serves.

- `SPEC-9.20.1` `routes::configure` must mount, inside one `/v1` scope and in this order, the route sets of: health,
  host, auth, user, account, download, events, application, billing, feedback, mailer, membership, pricing, branding,
  webhook, admin. A route set not listed here must not be reachable under `/v1`.
- `SPEC-9.20.2` `routes::configure` must register three routes outside the `/v1` scope: `GET /` (`root_status`),
  `GET /health` (`health_check`), and `GET /e2e-bootstrapped` (`e2e_bootstrapped`).
- `SPEC-9.20.3` `routes::configure` must register `GET /version` outside the `/v1` scope through
  `routes::version::configure`.
- `SPEC-9.20.4` `routes::configure` must register the OIDC discovery routes and the OAuth 2.1 routes outside the
  `/v1` scope by calling `bunyip_oidc::routes::oidc::configure_well_known` and
  `bunyip_oidc::routes::oidc::configure_oauth2`; `bunyip-api` itself must define no handler for those paths in this
  module (`SPEC-2.4.1`).
- `SPEC-9.20.5` No route set in `bunyip-api/src/routes/` may register a token-introspection path or a dynamic
  client-registration path; an unmatched path must fall to the framework default (`SPEC-1.3`).

### 9.21 Health, status and end-to-end readiness probes

`bunyip-api/src/routes/health.rs`. All handlers here take no authentication input.

- `SPEC-9.21.1` `GET /` and `GET /v1/version` must answer `200` with the JSON object
  `{"service":"bunyip-api","version":<CARGO_PKG_VERSION>,"git_tag":<GIT_TAG>,"commit":<GIT_COMMIT>,"build_date":<BUILD_DATE>}`.
  Each of `git_tag`, `commit`, and `build_date` must be the compile-time environment value of the variable of the
  same upper-case name, or the string `unknown` when that variable was not set at compile time.
- `SPEC-9.21.2` `GET /health` and `GET /v1/health` must answer `200` with
  `{"status":"ok","version":<CARGO_PKG_VERSION>}` without touching the database or any other dependency.
- `SPEC-9.21.3` `GET /e2e-bootstrapped` must, when `Config::is_production()` is true, answer `200` with
  `{"bootstrapped":false}` without querying the database.
- `SPEC-9.21.4` `GET /e2e-bootstrapped` must, outside production, answer `200` with `{"bootstrapped":true}` only when
  the count of non-deleted users whose email is in `E2E_ACCOUNT_EMAILS` (two fixed addresses) equals the length of
  that list, and `{"bootstrapped":false}` when the count is lower.
- `SPEC-9.21.5` When the user-count query behind `GET /e2e-bootstrapped` fails, the handler must log the failure with
  its cause and must not answer `{"bootstrapped":false}` with status `200`, because "could not evaluate" is not "not
  bootstrapped" (see the defect recorded for this requirement).

### 9.22 Root version endpoint and build identity

`bunyip-api/src/routes/version.rs` and `bunyip-api/src/version.rs`.

- `SPEC-9.22.1` `GET /version` must answer `200` with a JSON object that has exactly the keys `version`, `revision`,
  and `update`.
- `SPEC-9.22.2` In the `GET /version` body, `version` must be the workspace package version compiled into the binary,
  `revision` must be the compile-time `GIT_COMMIT` value or the string `unknown` when it was not set, and `update`
  must be the result of `UpdateChecker::status()` of the `Arc<UpdateChecker>` held in application data.
- `SPEC-9.22.3` The `revision` reported by `GET /version` must equal the `commit` reported by `GET /v1/version` in the
  same build, because both read the compile-time `GIT_COMMIT` and never a runtime environment variable.
- `SPEC-9.22.4` `crate::version` must keep re-exporting `UpdateChecker` and `UpdateStatus` from the shared
  `dunite-update-check` crate, and the version endpoints must only report update availability; applying an update
  must remain an operator action outside the process.

### 9.23 Authentication, user and account route tables

`bunyip-api/src/routes/auth.rs`, `user.rs`, and `account.rs`. Authentication and authorization of each endpoint are
specified with its handler in section 10.

- `SPEC-9.23.1` The `/v1/auth` scope must register these session routes: `POST /register`, `GET /register-challenge`,
  `POST /login`, `POST /logout`, `GET /logout` (redirecting variant), `POST /logout-all`, `POST /refresh`.
- `SPEC-9.23.2` The `/v1/auth` scope must register these credential-recovery and login-gate routes: `POST /magic-link`,
  `POST /magic-link/verify`, `POST /login-approval/verify`, `POST /password-reset`, `GET /password-reset/verify`,
  `POST /password-reset/confirm`.
- `SPEC-9.23.3` The `/v1/auth` scope must register these two-factor routes: `POST /2fa/setup`,
  `POST /2fa/setup/resume`, `POST /2fa/confirm`, `POST /2fa/verify`, `POST /2fa/disable`, `POST /2fa/recovery-codes`,
  `POST /2fa/rekey`, `POST /2fa/rekey/confirm`, `GET /2fa/status`.
- `SPEC-9.23.4` The `/v1/auth` scope must register `POST /invite/accept`, `GET /redirect`, and `GET /setup/status`,
  and must not register a `POST /setup` route; the first administrator comes from the `BOOTSTRAP_ADMIN_EMAIL`
  variable, not from an interactive wizard.
- `SPEC-9.23.5` The `/v1/users` scope must register these profile routes: `GET /me`, `PUT /me/profile`,
  `GET /me/avatar`, `POST /me/avatar`, `DELETE /me/avatar`, `PUT /me/password`, `DELETE /me`.
- `SPEC-9.23.6` The `/v1/users` scope must register these consent and identity routes: `POST /me/consents` and
  `GET /me/oauth-clients/{client_id}/identity`.
- `SPEC-9.23.7` The `/v1/users` scope must register these email routes: `POST /me/email`, `POST /me/email/confirm`,
  `POST /me/email/verify`, `POST /me/email/verify/confirm`.
- `SPEC-9.23.8` The `/v1/users` scope must register these session and device routes: `GET /me/sessions`,
  `POST /me/sessions/revoke-others`, `DELETE /me/sessions/{session_id}`, `GET /me/trusted-devices`,
  `POST /me/trusted-devices/{id}/revoke`.
- `SPEC-9.23.9` The `/v1/account` scope must register `GET /backup` and `POST /restore`, and must install a JSON
  extractor body limit of 8 MiB (8 * 1024 * 1024 bytes) on that scope so a restore upload larger than the global JSON
  default but within 8 MiB reaches the handler.

### 9.24 Public catalog, pricing and branding route tables

`bunyip-api/src/routes/application.rs`, `download.rs`, `pricing.rs`, and `branding.rs`.

- `SPEC-9.24.1` The `/v1/applications` scope must register: `GET ""`, `GET /{slug}`, `GET /{slug}/downloads`,
  `GET /{slug}/downloads/{asset_name}`, `GET /{slug}/downloads/{version}/{asset_name}` (a recorded historical
  release), `GET /{slug}/docs`, and `GET /{slug}/docs/{doc_slug}`.
- `SPEC-9.24.2` The list of applications that carry documentation must be served by `GET /v1/application-docs` in its
  own scope, never under `/v1/applications/...`, so no segment of it can be read as an application slug.
- `SPEC-9.24.3` `GET /v1/application-groups` must be registered and served by `list_application_groups`.
- `SPEC-9.24.4` `GET /v1/downloads` must be registered and served by `list_all_downloads`.
- `SPEC-9.24.5` `GET /v1/pricing` must be registered and served by `public_pricing`.
- `SPEC-9.24.6` `GET /v1/branding` and `GET /v1/branding/assets/{kind}` must be registered and served by
  `public_branding` and `public_branding_asset`; neither path may be in the rate-limit floor's `EXEMPT_PATHS`, so the
  default per-IP cap applies to them.

### 9.25 Membership, billing, events, feedback and webhook route tables

`bunyip-api/src/routes/membership.rs`, `billing.rs`, `events.rs`, `feedback.rs`, and `webhook.rs`.

- `SPEC-9.25.1` The `/v1/memberships` scope must register: `GET /me`, `POST /checkout`, `POST /cancel`,
  `POST /cancel-now`, `POST /reactivate`, `POST /billing-portal`, `GET /payments`.
- `SPEC-9.25.2` The `/v1/billing` scope must register: `POST /setup-intent`, `GET /invoices`, and
  `GET /invoices/{invoice_id}/download`.
- `SPEC-9.25.3` `GET /v1/events` must be registered as the single server-sent-events stream endpoint
  (`events_stream`).
- `SPEC-9.25.4` `POST /v1/feedback` must be registered and served by `submit_feedback`.
- `SPEC-9.25.5` `POST /v1/webhooks/stripe` must be registered and served by `stripe_webhook`, and its path must be in
  the rate-limit floor's `EXEMPT_PATHS`.

### 9.26 Machine-client route tables (host secrets, host config, mailer relay)

`bunyip-api/src/routes/host.rs` and `mailer.rs`.

- `SPEC-9.26.1` `GET /v1/host/secrets/{key:.*}` and `GET /v1/host/config/{key:.*}` must be registered with a tail
  pattern, so a key that contains `/` (a key namespaced by its reading product) matches as one key.
- `SPEC-9.26.2` The host-secret and host-config paths must not be in the rate-limit floor's `EXEMPT_PATHS`; the
  default per-IP cap applies to them in addition to the route's own per-app cap.
- `SPEC-9.26.3` `POST /v1/mailer/send` and `POST /v1/mailer/webhooks/feedback` must be registered, and both exact
  paths must be in the rate-limit floor's `EXEMPT_PATHS`, because their throttling is per calling app (send) or by
  signed body (feedback webhook) rather than per IP.

### 9.27 Admin route table: ordering and body limits

`bunyip-api/src/routes/admin.rs`. Route order matters because the first matching registration wins.

- `SPEC-9.27.1` `PUT /v1/admin/applications/reorder` must be registered before `PUT /v1/admin/applications/{app_id}`,
  so the literal `reorder` is never captured as an `app_id` and fails UUID parsing.
- `SPEC-9.27.2` `GET /v1/admin/feedback/new-count`, `GET /v1/admin/feedback/export`, and
  `GET /v1/admin/feedback/archive` must be registered before `GET /v1/admin/feedback/{feedback_id}`, so none of the
  three literals is captured as a feedback id.
- `SPEC-9.27.3` `POST /v1/admin/seed/import` must be registered as its own resource with a payload limit of 4 MiB
  (4 * 1024 * 1024 bytes), above the framework default for a `String` body and above the web tier's 2 MiB form limit.
- `SPEC-9.27.4` No route at `/v1/admin/test-email` may exist; the real-send test route is
  `POST /v1/admin/email/test-send` (`send_test_email_message`).

### 9.28 Admin route table: inventory

All paths below are under the `/v1/admin` scope in `bunyip-api/src/routes/admin.rs`; the method and path pair
must be registered to the named handler.

- `SPEC-9.28.1` Dashboard and status: `GET /stats`, `GET /health`, `GET /integrations`, `GET /providers/status`,
  `GET /key-health`, `GET /key-health/{key_id}`, `GET /pricing/status`.
- `SPEC-9.28.2` User management: `GET /users`, `GET /users/{user_id}`, `DELETE /users/{user_id}`, and `PUT` on
  `/users/{user_id}/status`, `/users/{user_id}/role`, `/users/{user_id}/email`; `POST` on
  `/users/{user_id}/email/verify`, `/users/{user_id}/two-factor/reset`, `/users/{user_id}/reset-password`,
  `/users/{user_id}/impersonate`, `/users/{user_id}/lifetime`, `/users/{user_id}/lifetime/revoke`,
  `/users/{user_id}/tier`.
- `SPEC-9.28.3` Entitlements and memberships: `GET` and `POST /users/{user_id}/entitlements`,
  `POST /users/{user_id}/entitlements/revoke`, `GET /memberships`, `POST /memberships/grant`,
  `POST /memberships/revoke`.
- `SPEC-9.28.4` Applications: `GET /applications`, `POST /applications`, `PUT /applications/reorder`,
  `PUT` and `DELETE /applications/{app_id}`, `PUT /applications/{app_id}/group`,
  `PUT /applications/{slug}/restricted`, `POST` and `DELETE /applications/{slug}/stripe-prices`,
  `POST /applications/{slug}/downloads/refresh`, `POST /applications/{slug}/oci/refresh` (served by the OCI crate's
  `admin_oci::refresh_oci`).
- `SPEC-9.28.5` Application documentation and groups: `GET` and `POST /applications/{app_id}/docs`, `PUT` and
  `DELETE /application-docs/{doc_id}`, `GET` and `POST /application-groups`, `PUT` and `DELETE`
  `/application-groups/{group_id}`.
- `SPEC-9.28.6` Abuse controls: `GET /ip-enrichment`, `GET /ip-bans`, `POST /ip-bans`, `DELETE /ip-bans/{ip}`,
  `GET /mailer-suppressions`, `DELETE /mailer-suppressions/{address}`, `POST /account-deletes/{user_id}/replay`.
- `SPEC-9.28.7` Rate limits: `GET /rate-limits`, `GET /rate-limits/history`, `GET /rate-limits/overview`,
  `POST /rate-limits/reset`, `GET` and `POST /rate-limits/whitelist`, `DELETE /rate-limits/whitelist/{id}`,
  `GET /rate-limit-configs`, `PUT` and `DELETE /rate-limit-configs/{action}`.
- `SPEC-9.28.8` Logs: `GET /audit-logs` and `GET /logs` (the error-log ring buffer).
- `SPEC-9.28.9` Feedback and support: `GET /feedback`, `GET /feedback/new-count`, `GET /feedback/export`,
  `GET /feedback/archive`, `POST /feedback/archive/{archive_id}/restore`,
  `GET /feedback/{feedback_id}/attachments/{attachment_id}`, `GET` and `DELETE /feedback/{feedback_id}`,
  `POST /feedback/{feedback_id}/respond`, `PUT /feedback/{feedback_id}/status`,
  `POST /feedback/{feedback_id}/mark-spam`, `POST /feedback/{feedback_id}/unmark-spam`,
  `POST /feedback/{feedback_id}/archive`, `GET /support/tickets`, `GET /support/tickets/{id}`,
  `POST /support/tickets/{id}/reply`.
- `SPEC-9.28.10` Seed data: `GET /seed/templates`, `GET /seed/export`, `POST /seed/import`.
- `SPEC-9.28.11` System, tier and feature configuration: `GET` and `PUT` on each of `/system-config`, `/tier-config`,
  `/auto-ban-config`, `/branding`, `/email`, `/mirzam`, `/mokosh`, `/stripe`; `PUT /tier-settings`;
  `GET /feature-toggles`; `PUT /feature-toggles/{key}`; `POST /email/test`; `POST /email/test-send`;
  `POST /mirzam/check`; `POST` and `DELETE /branding/assets/{slot}`.
- `SPEC-9.28.12` Stripe administration: `GET /stripe/permissions`; `GET` and `POST /stripe/products`;
  `PUT` and `DELETE /stripe/products/{id}`; `POST /stripe/products/{id}/unarchive`; `GET` and `POST /stripe/prices`;
  `DELETE /stripe/prices/{id}`; `POST /stripe/prices/{id}/unarchive`; `POST /stripe/prices/{id}/replace`;
  `GET` and `POST /stripe/webhooks`; `DELETE /stripe/webhooks/{id}`.
- `SPEC-9.28.13` Invites, tenants, notifications and key rotation: `POST` and `GET /invites`,
  `DELETE /invites/{invite_id}`; `GET` and `POST /oauth-clients/{client_id}/user-tenants`;
  `DELETE /oauth-clients/{client_id}/user-tenants/{assignment_id}`; `GET /notifications`;
  `POST /notifications/{notification_id}/read`; `POST /notifications/read-all`;
  `GET /key-rotation/{key_id}/status`; `POST /key-rotation/{key_id}/reencrypt`.

### 9.29 Governed secrets: provider reads and surveys

`bunyip-api/src/secrets.rs`. A governed secret is a `GovernedSecret` variant (SMTP password, Stripe secret key,
Stripe webhook secret, support IMAP password, Mirzam API token, Mokosh Google client secret). `SECRETS_STORAGE`
declares exactly one provider (`environment`, `database`, or `infisical`) as `config.secrets_provider`.

- `SPEC-9.29.1` `read_secret` must consult only the declared provider: `environment` reads only the file named
  by the secret's `<NAME>_FILE` variable (never the plain variable), `database` decrypts the secret's column pair
  from its owning table row, and `infisical`
  fetches the secret by name; it must never fall back to another provider.
- `SPEC-9.29.2` `read_secret` in `infisical` mode must fail with an internal error that names the missing
  `INFISICAL_*` variables when no Infisical client can be built from settings, and must, on a fetch failure, log an
  `error` line carrying the secret name and cause and return an upstream error reading
  `Could not read <NAME> from Infisical: <cause>`.
- `SPEC-9.29.3` `survey` must treat an empty string as absent in every provider, so a blank value is never counted as
  a holder and never copied as a source.
- `SPEC-9.29.4` `survey` must always read the database provider, always read the environment provider, and read
  Infisical only when called with `InfisicalProbe::Inspect`; with `InfisicalProbe::Skip` it must make no network
  call.
- `SPEC-9.29.5` `survey` must list the holders of each secret in the order environment, database, infisical, and
  must set a secret's `value` only from the declared provider.
- `SPEC-9.29.6` `survey` with `InfisicalProbe::Inspect` must record, not swallow, an Infisical failure: when no client
  can be built it must set `infisical_error` naming the four `INFISICAL_*` settings, and after the first fetch
  failure it must set `infisical_error` to that cause and make no further Infisical reads. `infisical_inspected` must
  be true only when the probe ran and `infisical_error` is empty.
- `SPEC-9.29.7` A stored database ciphertext that no key in the key set decrypts must be logged at `error` with the
  secret name and key version, and must then be treated as holding no value, so boot enforcement reports it rather
  than falling through to another provider.
- `SPEC-9.29.8` No secret value may be logged or printed by `survey`, `status_report`, `render_status`, or
  `render_plan`.
- `SPEC-9.29.9` `stripe_runtime_config` must build the runtime Stripe settings from the non-secret columns of the
  `stripe_config` row and both secrets from `read_secret`, substituting the unconfigured placeholder only for a
  secret the declared provider does not hold, and must propagate any `read_secret` error.

### 9.30 Governed secrets: boot enforcement

- `SPEC-9.30.1` `classify(declared, holders)` must return `Use` when the declared provider holds the secret and no
  other does, `FeatureOff` when nobody holds it, `Misplaced(others)` when only other providers hold it, and
  `Duplicated(others)` when the declared provider and at least one other hold it.
- `SPEC-9.30.2` `enforce` must, when the declared provider is `infisical` and the survey recorded an Infisical
  error, return exactly one fatal report containing that cause and skip the per-secret checks.
- `SPEC-9.30.3` `enforce` must emit one `warn` per `FeatureOff` secret naming the secret, the declared provider, and
  the disabled feature, and must treat the secret as not configured.
- `SPEC-9.30.4` `enforce` must return one fatal report per `Misplaced` secret that names the secret, the providers
  that hold it, the command `bunyip-api secrets-migrate --to <declared>`, and the `SECRETS_STORAGE` variable.
- `SPEC-9.30.5` `enforce` must emit one `warn` per `Duplicated` secret per duplicate provider, naming the secret, the
  declared provider, the duplicate provider, and the command `bunyip-api secrets-purge --confirm`, and must not
  return a fatal report for it.
- `SPEC-9.30.6` `enforce` must only return the fatal reports and must not exit the process itself; the caller owns
  the exit (`SPEC-2.2.1`).

### 9.31 Governed secrets: writes and purges

- `SPEC-9.31.1` `write_secret` to the `environment` provider must fail with a `409 Conflict` error whose message
  names `SECRETS_STORAGE=environment`, the `<NAME>_FILE` variable, and the `./secrets/<file>` path to edit, and must
  never report success.
- `SPEC-9.31.2` `write_secret` to the `database` provider must encrypt the value with the key set and store
  ciphertext, nonce, and key version in the secret's own row: the `email_config` SMTP or IMAP password columns, the
  `stripe_config` secret-key or webhook-secret columns, the `mirzam_config` API-token columns, or the `mokosh_config`
  client-secret columns; it must not write one secret into another secret's columns.
- `SPEC-9.31.3` `write_secret` with an `updated_by` administrator must stamp that administrator as the editor; with
  `updated_by` of `None` (the command-line path) it must write only the ciphertext columns and must leave the row's
  `updated_by` attribution alone.
- `SPEC-9.31.4` `write_secret` to `infisical` must fail with an internal error when no Infisical client can be built,
  and on an upsert failure must log an `error` with the secret name and cause and return a field-scoped validation
  error (a `4xx`) on the secret's form field reading
  `Could not write <NAME> to Infisical, so nothing was saved: <cause>. The machine identity needs write access to
  INFISICAL_SECRET_PATH.`, because the web tier collapses a `5xx` body to a generic line.
- `SPEC-9.31.5` `purge_secret` on the `environment` provider must change nothing and return an operator note
  naming the `<NAME>_FILE` variable and the `./secrets/<file>` file to remove.
- `SPEC-9.31.6` `purge_secret` on the `database` provider must set only that secret's ciphertext and nonce columns to
  `NULL` and refresh `updated_at` on row `id = 1`, and must leave every non-secret column unchanged.
- `SPEC-9.31.7` `purge_secret` on `infisical` must delete the named secret, and on failure must log an `error` with
  the secret name and cause and return an upstream error reading `Could not delete <NAME> from Infisical: <cause>`.

### 9.32 Governed secrets: operator subcommands

`secrets-status`, `secrets-migrate`, and `secrets-purge` are dispatched by `run_subcommand` (`SPEC-2.2.2`); they run
against a healthy deployment and read state through `survey`.

- `SPEC-9.32.1` `status_report` must list, per governed secret, its name, the providers that hold it (serialized
  under the JSON key `stores`), its `live_source` (the declared provider name when the declared provider holds it,
  else `null`), and a readiness entry for each of the three modes.
- `SPEC-9.32.2` A readiness entry must be `ready` only when that mode's provider holds the secret, and the
  `infisical` entry must be not ready with the note `not inspected: Infisical was not contacted in this run` when
  the survey did not inspect Infisical; an unready entry must carry the note
  "run `bunyip-api secrets-migrate --to <mode>` before switching".
- `SPEC-9.32.3` `render_status` must print the report as `SECRETS_STORAGE=<declared> (declared)`, a warning line
  when `infisical_error` is set, and per secret the lines `held by:`, `live source:`, and one line per mode reading
  `ready` or `NOT ready`, and must never print a secret value.
- `SPEC-9.32.4` `plan_migration` must plan, per secret: `AlreadyPresent` when the target provider holds it, else
  `Copy` when the declared provider's survey value exists, else `NoSource`.
- `SPEC-9.32.5` `run_migration` must fail with a bad-request error that contains the rendered plan and names every
  `NoSource` secret, unless `allow_missing` is set, before writing anything.
- `SPEC-9.32.6` `run_migration` must, for `dry_run` or for target `environment`, return the rendered plan without
  writing; for target `environment` the plan must be the exact `<NAME>_FILE: /run/secrets/<file>` entries and
  `./secrets/<file>` paths (mode 0600) to create, because a process cannot write that provider.
- `SPEC-9.32.7` `run_migration` must write each `Copy` step with `write_secret` and `updated_by` of `None`, must
  leave the source copies in place, then must re-survey (inspecting Infisical when it is the target) and fail with an
  upstream error that includes `do NOT set SECRETS_STORAGE=<target>` when any copied secret is not present in the
  target afterward.
- `SPEC-9.32.8` `run_migration` on success must end its output with
  `<N> secret(s) copied into <target> and verified present there.` followed by the instruction to set
  `SECRETS_STORAGE`, restart, soak, and run `secrets-purge --confirm`.
- `SPEC-9.32.9` `run_purge` without `--confirm` must fail with a bad-request error that requires `--confirm` and
  names `bunyip-api secrets-status`, and must delete nothing.
- `SPEC-9.32.10` `run_purge` must fail with a bad-request error and delete nothing when any secret is held by an
  inspected provider other than the declared one but not by the declared one (`would_orphan`); a secret held by no
  provider must not block the purge.
- `SPEC-9.32.11` `run_purge` must, for every provider other than the declared one that holds a secret, call
  `purge_secret`, print `<NAME>: removed from <provider>` for a removal and a `not writable from here` note for the
  `environment` provider, and print `nothing to remove: every copy already sits in the declared provider` when no
  line was produced; a purge error must abort the run with that error.

### 9.33 Support mailbox poller

`bunyip-api/src/support_ingest.rs`. The poller is spawned unconditionally at boot.

- `SPEC-9.33.1` `spawn` must start one background task that, every `max(config.email.imap_poll_secs, 10)` seconds
  and after skipping the immediate first tick, calls `poll_once`; a result of `0` must be silent, a positive count
  must log `info` `support mailbox poll ingested messages` with the count, and an error must log `warn`
  `support mailbox poll failed` with the cause, and the loop must continue.
- `SPEC-9.33.2` `poll_once` must re-read the `email_config` row on every call, resolve it through the same database
  provider and configuration stack the boot path uses, and fail with an error naming the offending variable and
  reason when that resolution fails.
- `SPEC-9.33.3` `poll_once` must return `0` without connecting when `imap_enabled` is false, `imap_host` is empty,
  `imap_username` is empty, or the support IMAP password governed secret has no value in the declared provider.
- `SPEC-9.33.4` `poll_once` must connect to `imap_host:imap_port` over TCP, upgrade to TLS using `imap_host` as the
  server name, log in, select `imap_mailbox`, and search `UNSEEN`; a failure in any of these steps must be returned
  as an error, and an empty search result must log out and return `0`.
- `SPEC-9.33.5` `poll_once` must fetch each unseen message with `BODY.PEEK[]`, so fetching alone never sets the
  `\Seen` flag.
- `SPEC-9.33.6` `poll_once` must, for a message that parses, call `SupportRepository::ingest_inbound`, and on success
  set `\Seen` and count it; on an ingest error it must log `warn` with the sequence number and cause, leave the
  message unseen for the next poll, and continue with the next message.
- `SPEC-9.33.7` `poll_once` must, for a message whose bytes do not parse, log `warn` with the sequence number and set
  `\Seen` so it is skipped on later polls.
- `SPEC-9.33.8` Setting `\Seen` must be best effort: a store failure must log `warn` with the sequence number and
  cause, and must not fail the poll; a re-fetched message must not create a second row, because ingestion looks up an existing
  `message_id` and `support_messages.message_id` has a unique index.
- `SPEC-9.33.9` `parse_inbound` must return `None` only when the bytes do not parse as a message, and otherwise
  extract: the first `From` address (empty string when absent) and its non-empty display name, the subject
  (`(no subject)` when absent), the `Message-ID`, the first `In-Reply-To` id, and every `References` id, each id with
  surrounding angle brackets and whitespace removed, a plain-text body (falling back to the HTML body, then to an
  empty string), the HTML body when present, and `to_email` of `None`.

### 9.34 Seed file schema and validation

`bunyip-api/src/seed.rs`. A seed file is JSON; the reserved seed email domain is `SEED_EMAIL_DOMAIN`.

- `SPEC-9.34.1` `parse` must reject a seed file whose `version` is not `SEED_SCHEMA_VERSION` (1) with
  `seed file version <found> is not supported (this build expects version <expected>)`.
- `SPEC-9.34.2` `parse` must reject any unknown field at any level of the file with a parse error reading
  `seed file is not valid JSON: <cause>`.
- `SPEC-9.34.3` `SeedFile::effective_owns` must return the file's `owns` scope, or a scope holding only the reserved
  domain when the file declares neither domains nor emails.
- `SPEC-9.34.4` `SeedOwns::covers(email)` must match case-insensitively an owned individual email, or an address
  whose text ends in `@` plus an owned domain, so a sibling domain with the owned domain as a suffix does not match.
- `SPEC-9.34.5` `validate` must collect every problem and return them together as one validation error whose text
  starts `seed file failed validation (<N> problems):` and lists each as a line beginning `  - `; it must not stop at
  the first problem.
- `SPEC-9.34.6` `validate` must report a duplicate application-group slug, a duplicate application slug, and an
  application `group_slug` that names no group in the file.
- `SPEC-9.34.7` `validate` must report any `owns.domains` entry other than the reserved domain, naming the offending
  domain and directing that a real domain be scoped through `owns.emails`.
- `SPEC-9.34.8` `validate` must report a user email not covered by the effective `owns` scope, a duplicate user email
  compared case-insensitively, and a `password_env` that is blank after trimming.
- `SPEC-9.34.9` `validate` must reject a user role outside `subscriber`, `admin`; a membership status outside `none`,
  `active`, `past_due`, `canceled`, `grace_period`; and a membership tier outside `free`, `standard`,
  `early_adopter`, `lifetime`; each compared case-insensitively and reported with the allowed set.
- `SPEC-9.34.10` `validate` must report an entitlement whose `user_email` (case-insensitive) is not a user in the
  file or whose `app_slug` is not an application in the file.
- `SPEC-9.34.11` `validate` must report a feedback entry whose message is blank after trimming, an entry with no
  author email, and an entry whose email is not covered by the effective `owns` scope.
- `SPEC-9.34.12` `seed_guard(environment, allow)` must fail with a guard error when `allow` is false, and, when
  `allow` is true, when `environment` is empty after trimming or equals `production` case-insensitively; any other
  value must pass.
- `SPEC-9.34.13` `SEED_TEMPLATES` must hold the compiled-in templates `demo-msp` and `minimal`, and `find_template`
  must return a template only on an exact name match; every embedded template must pass `parse`.

### 9.35 Seed loading, reset and export

- `SPEC-9.35.1` `load` must process, in this order: application groups, applications, users, entitlements, feedback;
  a group or application that already exists (matched by slug) must not be recreated or updated, except that an
  existing application is still re-linked to its `group_slug` group.
- `SPEC-9.35.2` `load` must create an absent application with `container_name` equal to its `container_name` field or
  else its slug, and must link an application to its group by slug, failing with an unresolved-reference error
  (`unresolved reference: group_slug '<slug>' not found for app '<slug>'`) when the group is absent from the
  database.
- `SPEC-9.35.3` `load` must resolve each user's password from, in precedence order, the environment variable named by
  `password_env` (read with `secret_env`), the user's own `password`, then the file's `default_password`; it must fail
  with `PasswordEnvUnset` when the named variable is unset, `MissingPassword` when none exists, and `EmptyPassword`
  when the resolved value is blank after trimming, before any user row is written.
- `SPEC-9.35.4` `load` must hash all resolved passwords, trimmed, in one blocking task (`argon2_offload`) rather than
  on the request future, and must fail with a hash error if hashing fails.
- `SPEC-9.35.5` `load` must upsert users by email: an existing user must get the new password hash and role; a new
  user must be created with the hash and role; `verified` true must mark the email verified; a profile update must
  be applied only when `first_name`, `last_name`, or `phone` is present; the membership must be applied with status
  default `none`, tier mapped from the string (`lifetime` flag forces lifetime, an unrecognized value maps to
  free), and `trial_ends_at` parsed as RFC 3339, failing with `BadTimestamp` when it is not.
- `SPEC-9.35.6` `load` must grant each entitlement with source `SEED` and fail with an unresolved-reference error when
  the user or application is absent from the database.
- `SPEC-9.35.7` `load` must delete all feedback the effective `owns` scope covers before inserting the file's
  feedback, so re-importing the same file does not duplicate feedback, and must insert seeded feedback with no
  submitter IP and no user agent.
- `SPEC-9.35.8` `load` must return per-section counts of the groups, applications, users, entitlements, and feedback
  rows it processed.
- `SPEC-9.35.9` `reset` must delete the feedback and then the users covered by the `owns` scope: by whole domain only
  for the reserved domain, and by exact email for each owned email; for any other domain it must fail with an
  `UnsafeReset` error (`refusing to reset the whole domain '<domain>'...`) and must never delete catalog groups or
  applications.
- `SPEC-9.35.10` `export(domain)` must return a version-1 `SeedFile` holding every application group and application,
  the users and their entitlements and the feedback under `domain`, with `owns.domains` equal to `[domain]`,
  `default_password` equal to `change-me-after-import`, and no password or password hash on any user.

### 9.36 Settings archive: envelope, passphrase and encryption

`bunyip-api/src/settings_archive.rs`, dispatched by the `settings-export` and `settings-import` subcommands
(`SPEC-2.2.2`).

- `SPEC-9.36.1` `seal` must produce a pretty-printed JSON envelope with `format` equal to `bunyip-settings-archive`,
  `format_version` equal to 1, a `kdf` block of `argon2id`, version 19, `memory_kib` 65536, `iterations` 3,
  `parallelism` 4, and a base64 `salt` of 16 random bytes, a `cipher` block of `aes-256-gcm` with a base64 `nonce`,
  and a base64 `ciphertext` of the JSON-serialized snapshot.
- `SPEC-9.36.2` `seal` must derive a 32-byte key from the passphrase with Argon2id using the envelope's parameters,
  and must run that derivation on the blocking pool (`argon2_offload`).
- `SPEC-9.36.3` `seal` must reject a passphrase shorter than `MIN_PASSPHRASE_CHARS` (16 characters, counted as
  characters) with a validation error on field `passphrase` stating the actual and required length, before scoring
  its strength.
- `SPEC-9.36.4` `seal` must reject a passphrase whose zxcvbn score is below 4 with a validation error on field
  `passphrase` stating `scores <n>/4 for guessability; 4 is required` followed by the zxcvbn warning and suggestions.
- `SPEC-9.36.5` No error message or log line may contain the passphrase.
- `SPEC-9.36.6` `passphrase_inputs` must return, for the strength check, the snapshot's brand name (or
  `config.app_name` when the brand name is blank) and the host of the configured base URL, with blank entries
  removed.
- `SPEC-9.36.7` `open` must check, in this order, and fail with a validation error on the named field: the bytes
  parse as an envelope (`archive`), `format` equals the archive format (`format`), `format_version` equals 1
  (`format_version`), the cipher is `aes-256-gcm` (`cipher.algorithm`), and `salt`, `nonce`, and `ciphertext` are
  valid base64 (`kdf.salt`, `cipher.nonce`, `ciphertext`).
- `SPEC-9.36.8` `open` must, before deriving a key, reject an envelope whose KDF algorithm is not `argon2id`
  (`kdf.algorithm`), whose Argon2 version is not 19 (`kdf.version`), or whose `memory_kib` exceeds 1048576
  (`kdf.memory_kib`, 1 GiB), because the parameters come from an untrusted file; Argon2 parameters the library
  refuses must fail on field `kdf`.
- `SPEC-9.36.9` `open` must fail with a validation error on field `passphrase` reading
  `the archive did not decrypt: wrong passphrase, or the archive is damaged` when authenticated decryption fails, and
  with a validation error on field `archive` when the decrypted bytes are not a snapshot.
- `SPEC-9.36.10` `SettingsSnapshot` and every section type must reject unknown fields, except that the sections
  `mirzam_config` and `mokosh_config`, the fields `branding.newsletter_url`, `allowed_secret_keys`, and
  `allowed_config_keys`, and the optional `catalog` and `oauth_clients` sections may be absent from older archives
  and must then take their empty or default-deny value.

### 9.37 Settings archive: schema guard and export

- `SPEC-9.37.1` `require_matching_schema` must fail with an internal error naming both versions when the highest
  applied migration in `_sqlx_migrations` differs from the highest migration compiled into the binary, and must
  fail with an internal error telling the operator to start `bunyip-api` once when the table is unreadable or empty.
- `SPEC-9.37.2` `export` must call `require_matching_schema` first and record the agreed version as
  `schema_version`, the creation time, and the binary's package version in the snapshot.
- `SPEC-9.37.3` `export` must carry these sections: `branding`, `branding_assets`, `tier_config`, `auto_ban_config`,
  `email_config`, `stripe_config`, `mirzam_config`, `mokosh_config`, `rate_limit_configs`, `feature_toggles`,
  `system_settings` (login approval, signup bot guard, country allow and deny lists), and `governed_secrets`.
- `SPEC-9.37.4` `export` must carry the `catalog` section (groups, applications, application documentation, Stripe
  price entitlements) only when `include_catalog` is set, and the `oauth_clients` section only when
  `include_oauth_clients` is set; otherwise the section must be absent from the snapshot.
- `SPEC-9.37.5` `export` must read each governed secret's plaintext through `read_secret` from the declared provider
  and store it under its variable name, with `null` when the provider holds none; a read error must fail the
  export.
- `SPEC-9.37.6` `export` must never carry a secret ciphertext or nonce column, or a surrogate key, timestamp, or
  attribution column listed under `excluded` in `ARCHIVED_TABLES`; it must carry an application's group and a
  documentation page's or price entitlement's application as the referenced row's slug, and OAuth client secrets
  only as their stored hash.
- `SPEC-9.37.7` `export` must read keyed tables in a stable order (branding assets by `kind`, rate-limit overrides by
  `action`, feature toggles by `key`, catalog rows by slug, OAuth clients by `client_id`), and must read each
  singleton from the row with `id = 1`, failing when that row is missing.
- `SPEC-9.37.8` Every column of an archived table must be listed in exactly one of the `archived` or `excluded` lists
  of its `ArchivedTable`, so a schema change cannot silently drop a setting from the archive.
- `SPEC-9.37.9` The archive must not contain users, per-user data, `ip_bans`, `mailer_suppressions`,
  `application_versions`, `download_cache`, or `audit_logs`.

### 9.38 Settings archive: validation and plan

- `SPEC-9.38.1` `plan` must fail with a validation error on field `schema_version` naming both versions when the
  snapshot's `schema_version` differs from the database's, after the schema guard of `SPEC-9.37.1`.
- `SPEC-9.38.2` `plan` must validate the whole snapshot before any write, so a rejected archive fails as loudly in a
  dry run as in a real run.
- `SPEC-9.38.3` Snapshot validation must apply the admin path's own validators to the branding section, to the tier
  visibility rule (a visible Free or lifetime, early-adopter, or standard tier needs a non-blank price id), to every
  rate-limit override (`validate_limits`, failing as a bad request naming the action), to the Mirzam settings
  (field prefixed `mirzam_config.`), and to the Mokosh Google client id (field prefixed `mokosh_config.`).
- `SPEC-9.38.4` Snapshot validation must refuse an archive whose email section is disabled (or unset) when
  `Config::is_production()` is true, using the admin path's `refuse_disabled_email_in_production`.
- `SPEC-9.38.5` Snapshot validation of a present catalog must fail with a validation error when an application names
  a group the catalog does not carry (`catalog.applications`), or a documentation page or a price entitlement names an
  application the catalog does not carry (`catalog.application_docs`, `catalog.stripe_price_entitlements`).
- `SPEC-9.38.6` `plan` must diff the target's export, taken with the same optional sections as the archive, against
  the archive; a section the archive lacks (`catalog`, `oauth_clients`) must not be diffed or modified.
- `SPEC-9.38.7` A singleton diff must list the names of the archive columns whose value differs, sorted, and never
  the values.
- `SPEC-9.38.8` A keyed-table diff must report keys only in the archive as inserted, keys in both with different row
  content as updated, and keys only in the target as deleted, so applying the archive replaces the table's content.
- `SPEC-9.38.9` The diff keys must be: branding asset `kind`; rate-limit `action`; feature-toggle `key`;
  application-group `slug`; application `slug`; documentation `<application_slug>/<slug>`; price entitlement
  `<stripe_price_id> -> <application_slug>`; OAuth client `client_id`.
- `SPEC-9.38.10` A deleted application must list the cascades `application_docs`, `application_versions`,
  `application_entitlements`, `stripe_price_entitlements`, and `download_cache`, and a deleted OAuth client must
  list `oauth_authorization_codes`, `refresh_token_families`, `refresh_tokens_v2`, `oauth_client_user_tenants`,
  `user_application_access`, and `lifecycle_event_delivery`.
- `SPEC-9.38.11` A governed-secret diff must be `Set` when the archive has a value that differs from the target's or
  the target has none, `Cleared` when the archive has none and the target has one, and `Unchanged` otherwise; when the
  declared provider is `environment` and the outcome is not `Unchanged` it must also carry the refusal text that
  `apply` would produce.

### 9.39 Settings archive: apply, reporting and file handling

- `SPEC-9.39.1` `apply` must run `plan` (including validation) first and must return its error without writing when
  planning fails.
- `SPEC-9.39.2` `apply` must write all database sections in one transaction that commits only at the end, so a
  failure in any statement leaves every database section as it was, and must return that error.
- `SPEC-9.39.3` The database write must make each section hold exactly the archive's content: singleton rows updated
  in place; branding assets, rate-limit overrides, feature toggles, catalog rows, and OAuth clients absent from the
  archive deleted and the rest upserted by their keys; and the attribution columns set to `updated_by` (`created_by`
  for OAuth clients), which is `None` for the command-line import.
- `SPEC-9.39.4` The catalog write must insert or update groups first, then delete applications absent from the archive
  and upsert the rest with their group resolved from the group slug, then delete groups absent from the archive, then
  replace documentation and price entitlements.
- `SPEC-9.39.5` The OAuth client write must delete the `refresh_tokens_v2`, `refresh_token_families`, and
  `oauth_authorization_codes` rows of every client absent from the archive before deleting that client.
- `SPEC-9.39.6` `apply` must write each governed secret whose plan outcome is not `Unchanged` through the declared
  provider (`write_secret` for `Set`, `purge_secret` for `Cleared`), and must fail that step with a `409 Conflict`
  naming the `<NAME>_FILE` to change when the declared provider is `environment`.
- `SPEC-9.39.7` `apply` must save the system settings while holding the system-config save lock, so a concurrent
  admin save cannot interleave.
- `SPEC-9.39.8` `apply` must finish with a verification step that re-exports the archive's sections and requires a
  diff against the archive to be empty, and must otherwise record the step as not applied with a message naming only
  the sections still differing.
- `SPEC-9.39.9` `apply` must return an `ImportReport` whose steps are, in order, `database sections`,
  `governed secrets`, `system settings (file layer)`, and `verification`, each with `applied` and an optional
  failure detail; a failure in the secrets, system-settings, or verification step must not stop the later steps, and
  `unapplied()` must list the steps with `applied` false so the caller can exit non-zero.
- `SPEC-9.39.10` `render_plan` and `render_report` must name sections, columns, keys, and counts only, never a setting
  value, a secret, a client-secret hash, or asset bytes; `render_plan` must end with
  `Nothing has been written. Re-run without --dry-run to apply.` and `render_report` must end with
  `Restart bunyip-api so every process picks the restored settings up.`
- `SPEC-9.39.11` `read_passphrase(path)` must read standard input when `path` is `-` and the file otherwise, strip at
  most one trailing line ending (`\n` or `\r\n`), and fail with an error when the source is unreadable or the
  result is empty.
- `SPEC-9.39.12` `write_archive` must refuse a path of `-` and refuse an existing path without overwriting it, and
  must create the file exclusively with mode `0600` set at creation; any create or write failure must be returned as
  an error naming the path.
- `SPEC-9.39.13` `read_archive` must refuse a path of `-` and return an error naming the path when the file cannot be
  read.

## 10. API handlers

### 10.1 Account backup and restore

- `SPEC-10.1.1` `GET /v1/account/backup` must require an account admin (`AdminUser`) and must build the bundle for the
  acting admin's own user id (token `sub`) in the default app tenant (the fixed UUID `00000000-0000-0000-0000-000000000001`)
  with the current UTC time as the creation time.
- `SPEC-10.1.2` On success the backup response must be HTTP 200 with content type `application/json; charset=utf-8`, the
  bundle as pretty-printed JSON (not wrapped in the standard success envelope), a `Content-Disposition` header of
  `attachment; filename="account-backup-<created_at as %Y%m%d-%H%M%S>.json"`, and an `x-request-id` header carrying the
  request id.
- `SPEC-10.1.3` If the backup service fails, or the bundle cannot be serialized, the backup endpoint must return the
  resulting error (a serialization failure is an internal error naming the serialize step) and must not send a bundle.
- `SPEC-10.1.4` After building the bundle the backup endpoint must write an `AccountBackupCreated` audit entry with the
  admin as actor, resource type `user` and id the admin's id, and metadata `user_id` and `app_sections` (the number of
  per-app sections) and no other profile data; if the audit write fails the endpoint must return that error and not the
  bundle.
- `SPEC-10.1.5` `POST /v1/account/restore` must require an account admin, accept a JSON `AccountBackup` body, and re-apply
  it only to the acting admin's own account (user id and acting-user id both the token `sub`) in the default app tenant.
- `SPEC-10.1.6` On a successful restore the endpoint must write an `AccountRestored` audit entry (actor the admin,
  resource `user` with the admin's id, metadata `user_id`, `entitlements_granted` count and `apps` as the list of
  restored app slugs) and then answer with the standard success envelope carrying the `RestoreReport`.
- `SPEC-10.1.7` If the restore service fails the endpoint must return its error and must not write an `AccountRestored`
  audit entry; a body that does not deserialize as `AccountBackup` must be rejected by the JSON extractor before the
  service is called.

### 10.2 Admin user management

- `SPEC-10.2.1` `GET /v1/admin/users` must require an admin and return users in the paginated envelope with `page`
  defaulting to 1 and at least 1 and `per_page` defaulting to 20 and capped at 100; it must support filters `search`,
  `status`, `active` (false lists suspended, soft-deleted accounts), `tier` (blank means no filter) and `verified`, and
  sorting by `email`, `tier`, `verified` or `joined` with `dir` of `asc` (any other value or none is descending), where an
  absent or unknown `sort` means newest first by join date.
- `SPEC-10.2.2` `GET /v1/admin/users/{user_id}` must require an admin and return the user, or 404 "User" not found.
- `SPEC-10.2.3` `PUT /v1/admin/users/{user_id}/status` with `{"active": true}` must require a verified admin and
  reactivate a soft-deleted user, returning 404 "Deleted user" not found when the user is not a soft-deleted account; it
  must then notify the mailing-list sync of a verified account, revoke all of the user's refresh tokens, write an
  `AdminUserActivated` audit entry (metadata `sessions_revoked`) and publish a claims-changed event.
- `SPEC-10.2.4` `PUT /v1/admin/users/{user_id}/status` with `{"active": false}` must return 404 "User" not found for an
  unknown user, otherwise soft-delete the user, notify the mailing-list sync of a deleted account, revoke all of the
  user's refresh tokens, write an `AdminUserDeactivated` audit entry (metadata `target_email`, `sessions_revoked`),
  publish a `SessionRevoked` event with reason `admin_deactivate`, and, when the OIDC provider is configured, dispatch the
  `user.deleted` lifecycle event in a background task.
- `SPEC-10.2.5` `DELETE /v1/admin/users/{user_id}` must require a verified admin and refuse with 400 on field `user_id`
  "Cannot delete your own account" for the acting admin, 404 "User" not found for an unknown user, and 400 on field
  `user_id` "Cannot delete admin users" for a user whose role is `admin`; otherwise it must soft-delete the user, notify
  the mailing-list sync, log at info the admin id, deleted user id and email, write an `AdminUserDeleted` audit entry
  (metadata `target_email`, `target_role`), dispatch the `user.deleted` lifecycle event in the background when the OIDC
  provider is configured, and return the no-data success envelope.
- `SPEC-10.2.6` `PUT /v1/admin/users/{user_id}/role` with `{"role"}` must require a verified admin and return 400 on field
  `role` "Invalid role. Must be 'subscriber' or 'admin'" for any other role, 400 on field `user_id` "Cannot change your own
  role" for the acting admin, and 404 "User" not found; on a change it must update the role, and when the role actually
  differs it must revoke all of the user's refresh tokens and publish a `SessionRevoked` event with reason `role_change`.
- `SPEC-10.2.7` A role change must log at info the admin, target and new role, write an `AdminUserRoleChanged` audit entry
  (old value `{role}`, new value `{role}`, metadata `target_email`, `sessions_revoked`), and return the updated user.
- `SPEC-10.2.8` `PUT /v1/admin/users/{user_id}/email` with `{"email", "verified"?}` must require a verified admin, trim and
  lowercase the address, validate its format, return 404 "User" not found, and return 409 "Email already registered" when
  the address differs from the current one (case-insensitively) and is held by any live or soft-deleted account.
- `SPEC-10.2.9` A valid email correction must store the address with the `verified` flag (default false), notify the
  mailing-list sync of the move with the verified state before and after, log at info, write an `AdminUserEmailChanged`
  audit entry (old value `{email}`, new value `{email, email_verified}`), and return the user as freshly re-read.
- `SPEC-10.2.10` `POST /v1/admin/users/{user_id}/email/verify` must require a verified admin, return 404 "User" not found,
  mark the address verified, notify the mailing-list sync only when the flag actually changed, log at info, and always
  write an `AdminUserEmailVerified` audit entry (metadata `target_email`).
- `SPEC-10.2.11` `POST /v1/admin/users/{user_id}/two-factor/reset` must require a verified admin, return 404 "User" not
  found, delete the user's TOTP secret and recovery codes first and only then clear `two_factor_enabled`, log at info, and
  write an `AdminUserTwoFactorReset` audit entry (metadata `target_email`).
- `SPEC-10.2.12` `POST /v1/admin/users/{user_id}/reset-password` must require a verified admin, return an internal error
  "JWT service not configured" when the token service is absent, return 404 "User" not found, store a password-reset token
  (random value kept only as a hash, expiring in one hour, no IP) and send the reset email with no requester IP; an
  email failure must be returned as an error, and success must write an `AdminPasswordReset` audit entry (metadata
  `target_user_id`, `target_email`).
- `SPEC-10.2.13` `POST /v1/admin/users/{user_id}/impersonate` must require an admin, return 400 on field `user_id`
  "Cannot impersonate yourself" for the acting admin, 404 "User" not found, mint an access token and a refresh token for
  the target (refresh token valid 30 days, device label "Admin impersonation", no IP), write an `AdminUserImpersonated`
  audit entry (metadata `target_user_id`, `target_email`, `admin_id`) and return `access_token`, `refresh_token` and `user`.
- `SPEC-10.2.14` Every user-mutating admin action in this subsection except impersonation (status, delete, role, email,
  email verify, two-factor reset, password reset) must require the verified-admin extractor, which refuses an unverified
  admin with a 403 naming verification, while the plain admin extractor must remain on the mail-repair endpoints of 10.11.
- `SPEC-10.2.15` Revoking a user's sessions must revoke every refresh-token family of that user so the next refresh fails
  and a new sign-in carries the changed claims, and a claims-changed event must be published only after the revoke and the
  audit write.
- `SPEC-10.2.16` The lifecycle event dispatcher must look up every registered lifecycle event URI, post a freshly minted
  lifecycle token as form field `lifecycle_event` to each with a 5 second timeout, and for a failed lookup, a failed mint
  or a failed post must log a warning (with the client id for per-target failures) and continue with the remaining
  targets.

### 10.3 Memberships, lifetime grants and tier moves

- `SPEC-10.3.1` `POST /v1/admin/memberships/grant` with `{"user_id", "price_locked"?, "locked_price_amount"?}` must
  require a verified admin and grant a free membership (lifetime member, status active, attributed to the acting admin).
- `SPEC-10.3.2` When the live tier configuration has a free price id, a free or lifetime grant must ensure the user has a
  Stripe customer (creating it and persisting its id when missing) and create a $0 subscription for it; a Stripe failure
  must be returned as an error.
- `SPEC-10.3.3` A free grant with `price_locked` true must lock the user's price with price id `price_admin_grant` and
  amount `locked_price_amount` (default 0).
- `SPEC-10.3.4` A free grant must revoke the user's sessions, publish a claims-changed event, write an
  `AdminMembershipGranted` audit entry (resource `user`, metadata `tier` = `free`, `price_locked`, `locked_price_amount`,
  `sessions_revoked`) and return the no-data success envelope.
- `SPEC-10.3.5` `POST /v1/admin/memberships/revoke` (same body) must require a verified admin, return 404 "User" not found
  before changing anything, set the status to canceled, reset the tier to standard, clear any grace period, revoke the
  user's sessions, publish a claims-changed event and write an `AdminMembershipRevoked` audit entry (metadata
  `sessions_revoked`).
- `SPEC-10.3.6` `GET /v1/admin/memberships` must require an admin and return the paginated envelope with `page` defaulting
  to 1 and at least 1, `per_page` defaulting to 20 and capped at 100, and a saturating offset; with `tier` it must list
  non-deleted users of that tier (a missing tier counts as `standard`) oldest first, else with `status` the non-deleted
  users of that status newest first, else all non-deleted users whose status is not `none` newest first, with `total`
  counted under the same predicate; `tier` must take precedence over `status`.
- `SPEC-10.3.7` `POST /v1/admin/users/{user_id}/lifetime` and `.../lifetime/revoke` with `{"totp_code"}`, and
  `POST /v1/admin/users/{user_id}/tier`, must require a verified admin and verify the acting admin's 2FA code (trimmed)
  before any mutation: a verification error must return 400 on field `totp_code` "2FA must be enabled to change a tier"
  and a wrong code 400 "Invalid 2FA code", in both cases changing nothing.
- `SPEC-10.3.8` A lifetime grant must grant lifetime membership, perform the $0 subscription step of SPEC-10.3.2, revoke
  the user's sessions, publish a claims-changed event, write an `AdminMembershipGranted` audit entry (metadata `tier` =
  `lifetime`, `target_email`, `sessions_revoked`) and return the updated user.
- `SPEC-10.3.9` A lifetime revoke must revoke lifetime membership, revoke the user's sessions, publish a claims-changed
  event, write an `AdminMembershipRevoked` audit entry (metadata `tier` = `lifetime`, `target_email`, `sessions_revoked`)
  and return the updated user.
- `SPEC-10.3.10` The tier move must parse `tier` strictly as one of `lifetime`, `free`, `early_adopter`, `standard`
  (trimmed) before touching anything, returning 400 on field `tier` "Unknown subscription tier" otherwise, and must
  return 404 "User" not found for an unknown user before the 2FA check.
- `SPEC-10.3.11` The tier move must resolve trial windows from the freshly read tier settings, move the user with the
  acting admin recorded and those windows, create the $0 subscription of SPEC-10.3.2 (using the freshly resolved free price
  id) only when the user moves to lifetime from another tier, and revoke the user's sessions only when the tier actually
  changes.
- `SPEC-10.3.12` The tier move must always publish a claims-changed event, write an `AdminTierChanged` audit entry
  (metadata `from_tier`, `to_tier`, `target_email`, `sessions_revoked`) and return the updated user.

### 10.4 Per-product entitlements

- `SPEC-10.4.1` `GET /v1/admin/users/{user_id}/entitlements` must require an admin and return the user's entitlement rows
  in the success envelope.
- `SPEC-10.4.2` `POST /v1/admin/users/{user_id}/entitlements` with body `{"slug"}` must require a verified admin
  (`VerifiedAdminUser`), resolve the slug to an application, and grant the entitlement with the acting admin as granter
  and source `admin`; an unknown slug must return 404 "Application" not found and grant nothing.
- `SPEC-10.4.3` A successful grant must write an `AdminEntitlementGranted` audit entry (resource `user` with the target
  id, metadata `slug` and `application_id`) and then answer with the no-data success envelope.
- `SPEC-10.4.4` `POST /v1/admin/users/{user_id}/entitlements/revoke` with body `{"slug"}` must require a verified admin,
  return 404 for an unknown slug, be idempotent (success when no entitlement existed), and write an
  `AdminEntitlementRevoked` audit entry (metadata `slug`, `application_id`) only when a row was actually revoked.
- `SPEC-10.4.5` `PUT /v1/admin/applications/{slug}/restricted` with body `{"requires_entitlement": bool}` must require an
  admin, return 404 for an unknown slug, and set the flag and (when needed) the member backfill in one transaction, so a
  backfill failure leaves the flag unchanged.
- `SPEC-10.4.6` When the flag goes from false to true the same transaction must grant the application to every member who
  can access it at that moment; when the flag is set to false, or was already true, no backfill must run.
- `SPEC-10.4.7` After the transaction commits, the restricted-flag endpoint must write an
  `AdminApplicationRestrictionChanged` audit entry (resource `application` with the application id, metadata `slug`,
  `requires_entitlement` and `backfilled_members`) and answer with the no-data success envelope.
- `SPEC-10.4.8` `POST /v1/admin/applications/{slug}/stripe-prices` and `DELETE` on the same path, each with body
  `{"stripe_price_id"}`, must require an admin, return 404 for an unknown slug, add or remove the price-to-application
  mapping, and write an `AdminStripePriceMappingChanged` audit entry (resource `application`, metadata `slug` and
  `stripe_price_mapping_added` or `stripe_price_mapping_removed` holding the price id).

### 10.5 Admin applications and application groups

- `SPEC-10.5.1` `GET /v1/admin/applications` must require an admin and return `{"applications": [...]}` including
  inactive applications.
- `SPEC-10.5.2` `PUT /v1/admin/applications/reorder` with `{"ordered_ids"}` must require an admin, set each listed
  application's sort order to its index in the list, and return the full application list.
- `SPEC-10.5.3` `PUT /v1/admin/applications/{app_id}` must require an admin, return 404 "Application" not found, and
  validate the distribution configuration formed by overlaying the body on the stored row, returning a 400 on the failing
  field instead of a database error.
- `SPEC-10.5.4` After updating, the handler must record the current pinned image tag and pinned release tag (those that
  are set) in the application's version history without duplicates; a failed history write must log a warning
  "application_versions record failed" with the application id and tag and must not fail the update.
- `SPEC-10.5.5` When the download source changed it must invalidate the release cache for the old source and the download
  cache for the old version (a failed download-cache invalidation must be logged at warn), and when the pinned image tag
  changed it must invalidate the OCI manifest cache for the application.
- `SPEC-10.5.6` When `maintenance_mode` changed it must notify the application's webhook of the maintenance change, and
  when `is_active` changed of the active change, in a background task that does not delay the response.
- `SPEC-10.5.7` An application update must write an `ApplicationUpdated` audit entry (old and new `name`, `is_active`,
  `maintenance_mode`), an additional `ApplicationMaintenanceToggled` entry (metadata `application_name`,
  `maintenance_mode`) when maintenance mode changed, and return the updated application.
- `SPEC-10.5.8` `POST /v1/admin/account-deletes/{user_id}/replay` with `{"app_slug"}` must require an admin, return 404
  "Application" not found for an unknown slug, re-send the `account_deleted` webhook to that application, record the
  outcome in the dispatch-failure tracking exactly as the original delete fan-out does, and log at info the admin id,
  user id, slug and whether it was delivered.
- `SPEC-10.5.9` A delivered replay must return `{"user_id", "app_slug", "status": "delivered"}`; a failed replay must
  return an internal error "account_deleted webhook to <slug> still failing: <error>".
- `SPEC-10.5.10` `POST /v1/admin/applications` must require an admin and, in this order, return 400 on field `name`
  "Name is required", `slug` "Slug is required", `display_name` "Display name is required", `container_name` "Container
  name is required" for blank values, `slug` "Slug must contain only lowercase letters, numbers, and hyphens" for a bad
  slug, 409 "An application with this slug already exists", and a 400 for an invalid distribution configuration.
- `SPEC-10.5.11` A valid application create must return 201 with the application and write an `ApplicationCreated` audit
  entry (metadata `application_name`, `application_slug`).
- `SPEC-10.5.12` `DELETE /v1/admin/applications/{app_id}` with `{"password", "totp_code"}` must require an admin and
  first verify the acting admin's password (argon2 off the request worker): no stored hash must return 400 on field
  `password` "Account has no password set" and a mismatch 400 "Invalid password".
- `SPEC-10.5.13` The application delete must then verify the TOTP code: a verification error must return 400 on field
  `totp_code` "2FA must be enabled to delete applications" and a wrong code 400 "Invalid 2FA code"; only after both checks
  must it return 404 "Application" not found for an unknown id, delete the application and write an `ApplicationDeleted`
  audit entry (metadata `application_name`, `application_slug`).
- `SPEC-10.5.14` `GET /v1/admin/application-groups` must require an admin and return `{"groups": [...]}`.
- `SPEC-10.5.15` `POST /v1/admin/application-groups` must require an admin and return 400 on field `name` "Name is
  required", `display_name` "Display name is required", `slug` "Slug must contain only lowercase letters, numbers, and
  hyphens", and 409 "An application group with this slug already exists"; on success it must return 201 with the group.
- `SPEC-10.5.16` `PUT /v1/admin/application-groups/{group_id}` must require an admin, return 404 "Application group" not
  found, validate a supplied slug with the same format message, return 409 "An application group with this slug already
  exists" when the slug belongs to a different group (its own slug is allowed), and return the updated group.
- `SPEC-10.5.17` `DELETE /v1/admin/application-groups/{group_id}` must require an admin, return 404 "Application group"
  not found, and delete the group, leaving its member applications ungrouped.
- `SPEC-10.5.18` `PUT /v1/admin/applications/{app_id}/group` with `{"group_id"}` must require an admin, return 404
  "Application" not found, return 404 "Application group" not found for a non-null unknown group, and set the group or
  clear it when `group_id` is null.

### 10.6 Public application catalog and documentation

- `SPEC-10.6.1` The catalog handlers must compute `has_member_access` per request from the caller's current user row,
  never from the token claim snapshot: an anonymous caller must get false; a caller whose row was already read while
  verifying an `at+jwt` access token in the same request must be answered from that row; any other authenticated caller
  must be answered from a fresh read of the user row.
- `SPEC-10.6.2` When the fresh user-row read returns no row, `has_member_access` must fall back to the token claim; when
  the read fails it must fall back to the token claim and log a warning naming the user id and the error, and the
  endpoint must not fail because of that read.
- `SPEC-10.6.3` `GET /v1/application-groups` must be public and return `{"groups": [...]}` with the display metadata of
  every application group.
- `SPEC-10.6.4` `GET /v1/applications` must accept an optional caller and list only active hosted applications
  (catalog-only distribution products excluded) as `{"applications": [...]}`, each carrying the caller's
  `has_member_access`.
- `SPEC-10.6.5` The list must drop a restricted application (requires entitlement) unless the caller is an admin
  (`role` = `admin`) or holds an active entitlement for it; open applications must always be listed. Entitlements must be
  fetched in one batched query, and not at all for an admin or an anonymous caller.
- `SPEC-10.6.6` `GET /v1/applications/{slug}` must accept an optional caller, return 404 "Application" not found when the
  slug is not an active application, and return the same 404 for a restricted application the caller may not access, so
  its existence is not disclosed.
- `SPEC-10.6.7` `GET /v1/applications/{slug}/docs` must be public, return 404 "Application" not found unless the slug is
  an active application (entitlement and membership must not gate it), and return the ordered metadata-only index of its
  pages, an empty list when it has none.
- `SPEC-10.6.8` `GET /v1/application-docs` must be public and return every active application that has at least one
  documentation page.
- `SPEC-10.6.9` `GET /v1/applications/{slug}/docs/{doc_slug}` must be public, return 404 "Application" not found for a
  non-active application, and 404 "Documentation page" not found when the page does not exist.
- `SPEC-10.6.10` `GET /v1/admin/applications/{app_id}/docs` must require an admin and return every page of the
  application as full rows.
- `SPEC-10.6.11` `POST /v1/admin/applications/{app_id}/docs` and `PUT /v1/admin/application-docs/{doc_id}` must require
  an admin, create or patch the page, write an `ApplicationDocCreated` or `ApplicationDocUpdated` audit entry (resource
  `application_doc`, metadata `application_id`, `slug`, `title`) and return the page.
- `SPEC-10.6.12` `DELETE /v1/admin/application-docs/{doc_id}` must require an admin, return 404 "Documentation page" not
  found when no page was removed, and otherwise write an `ApplicationDocDeleted` audit entry (resource
  `application_doc`) and return `{"deleted": true}`.

### 10.7 Audit logs, error log, statistics and notifications

- `SPEC-10.7.1` `GET /v1/admin/audit-logs` must require an admin and return the paginated envelope with `page` defaulting
  to 1 and at least 1 and `per_page` defaulting to 50 and capped at 100, filtered by `user_id`, `action` and
  `admin_only` (default false).
- `SPEC-10.7.2` Before querying, the audit-log handler must validate `severity` (trimmed, blank means absent) as one of
  `info`, `warning`, `error`, `critical`, else 400 on field `severity` "must be one of: info, warning, error, critical".
- `SPEC-10.7.3` `since` (trimmed, blank means absent) must be an RFC 3339 timestamp or one of `1h`, `24h`, `7d`, `30d`
  counted back from now and used as an inclusive lower bound on creation time, else 400 on field `since` "must be an
  RFC3339 timestamp or one of: 1h, 24h, 7d, 30d".
- `SPEC-10.7.4` `q` (trimmed, blank means absent) must be at most 128 bytes, else 400 on field `q` "must be at most 128
  characters", and must search actor email and resource id.
- `SPEC-10.7.5` `GET /v1/admin/logs` must require an admin and return the ERROR-level entries of the in-memory ring buffer
  newest first, filtered by exact `category`, truncated to `limit` capped at the buffer capacity, as `entries`, `matched`
  (count before truncation), `buffered` (all entries held) and `capacity`.
- `SPEC-10.7.6` `GET /v1/admin/stats` must require an admin and return `total_users` (non-deleted), `active_members`,
  `past_due_members` and `grace_period_members` (non-deleted users with that membership status), `total_applications`
  and `active_applications`; any query failure must be returned as an error and never reported as a zero count.
- `SPEC-10.7.7` `GET /v1/admin/notifications` must require an admin and return the paginated envelope with `page`
  defaulting to 1 and at least 1 and `per_page` defaulting to 20 and capped at 100; with `unread=true` it must return
  only unread notifications, honoring `page` and `per_page` with a saturating start offset and `total` equal to the number
  of unread notifications.
- `SPEC-10.7.8` `POST /v1/admin/notifications/{notification_id}/read` and `POST /v1/admin/notifications/read-all` must
  require an admin, mark one or all notifications read for the acting admin, and return the no-data success envelope.

### 10.8 Seed data and admin invites

- `SPEC-10.8.1` `GET /v1/admin/seed/export` must require an admin and return the seed-owned data in canonical seed format
  as pretty-printed JSON with content type `application/json` and `Content-Disposition: attachment;
  filename="seed-export.json"`; an export failure must be returned as an internal error.
- `SPEC-10.8.2` `GET /v1/admin/seed/templates` must require an admin and list each embedded template with `name`,
  `description` and the counts of `groups`, `applications`, `users`, `entitlements` and `feedback`.
- `SPEC-10.8.3` `POST /v1/admin/seed/import` must require an admin and refuse with 400 (the guard's message) before
  reading any data when the environment is production or unset.
- `SPEC-10.8.4` The import must load the embedded template named by `?template=` (400 "unknown seed template '<name>'"
  when unknown) or else the request body; unparseable data must return 400 with the parse error, a load failure must be
  an internal error, and success must return the loaded counts `groups`, `applications`, `users`, `entitlements`,
  `feedback`; importing must be idempotent.
- `SPEC-10.8.5` `POST /v1/admin/invites` with `{"email"}` must require a verified admin, validate the email format, create
  the invite recording the acting admin and client IP, send the invite email in a background task whose failure is logged
  at error with the address, and return 201 with `{"email"}`.
- `SPEC-10.8.6` `GET /v1/admin/invites` must require an admin and return the paginated envelope with `page` defaulting to
  1 and at least 1 and `per_page` defaulting to 20 and capped at 100, accepting `status` of `pending`, `accepted`,
  `revoked` or `expired` (400 on field `status` "must be one of pending, accepted, revoked, expired" otherwise) and an
  `email` substring filter of at most 128 bytes (400 on field `email` "must be at most 128 characters" otherwise).
- `SPEC-10.8.7` `DELETE /v1/admin/invites/{invite_id}` must require a verified admin, revoke the invite through the auth
  service with the acting admin recorded, return its error on failure, and otherwise the no-data success envelope.

### 10.9 System health, integration status and provider status

- `SPEC-10.9.1` `GET /v1/admin/providers/status` must require an admin and build Bunyip's own provider report from the
  secrets survey and the configuration-stack survey, inspecting the secrets manager only when it is enabled or is the
  declared secrets provider; a survey failure must be returned as an error.
- `SPEC-10.9.2` The response must contain one row for the hosting application itself and one row per remote suite
  application fetched over HTTP; an unreachable, unauthenticated or version-mismatched application must appear as a row
  carrying that status and must never be omitted.
- `SPEC-10.9.3` The rows must be returned aggregated in the success envelope, and the endpoint must make no change.
- `SPEC-10.9.4` `GET /v1/admin/health` must require an admin and probe the database with `SELECT 1`: success is
  `healthy` with the latency in milliseconds, failure is `unhealthy` with the error text as message and an overall
  status of `degraded`, otherwise the overall status is `healthy`.
- `SPEC-10.9.5` The health response must contain `health` (`status`, `database`, `uptime_seconds`, `version`,
  `git_commit`, `git_tag`, `build_date`, `db_pool_size`, `db_pool_idle`, `datasets`) and `stats` (`total_users`,
  `active_members`, `audit_logs_last_hour`); a failing statistics query must be returned as an error, not dropped.
- `SPEC-10.9.6` Each dataset entry (the offline login-country dataset and the offline ASN/VPN dataset) must report
  `configured` (path set and non-blank), `present` (file readable), `age_days` (whole days since the file's modification
  time, null when unset, unreadable or in the future) and `stale` (true only when the age exceeds 40 days).
- `SPEC-10.9.7` `GET /v1/admin/integrations` must require an admin and return `{"integrations": [...]}` classified from
  runtime signals: a governed secret counts as present only when non-blank, the secrets manager is inspected only when
  enabled or declared as provider, and a survey or database failure must be returned as an error.

### 10.10 Stripe account configuration

- `SPEC-10.10.1` `GET /v1/admin/stripe` must require an admin and return the Stripe configuration with secrets masked:
  non-secret columns from the stored row and the secret key and webhook secret read from the declared secrets provider.
- `SPEC-10.10.2` `PUT /v1/admin/stripe` must treat empty-string fields as "no change", trim `success_url` and
  `cancel_url`, and reject `trial_period_days` outside 0 to 365 with 400 on field `trial_period_days` "Must be between 0
  and 365".
- `SPEC-10.10.3` When the secrets provider is read-only (`environment`), a non-empty `secret_key` (checked first) or
  `webhook_secret` must be refused with the read-only-provider error before any write, while the non-secret fields remain
  editable.
- `SPEC-10.10.4` With the `database` provider the secrets must be encrypted with the current application key and stored
  as ciphertext; with the `infisical` provider each given secret must first be written to the provider (a failure aborts
  the save with its cause, changing nothing) and the ciphertext columns must be left untouched.
- `SPEC-10.10.5` After the row update the handler must reload the live Stripe service from the secrets as read back from
  the declared provider, log the reload at info, and invalidate the public pricing cache.
- `SPEC-10.10.6` If no app-tagged price exists, a save must try to create a default product and recurring price; a
  failure must be logged at warn and must not fail the save, and a success must be logged at info.
- `SPEC-10.10.7` A save must write an `AdminStripeConfigUpdated` audit entry (metadata `fields_updated` with booleans
  `secret_key`, `webhook_secret` and the `app_tag`, `secret_store` only when a secret was written, and `bootstrap` with
  the created product and price ids or null), never any secret value, and return the masked configuration.

### 10.11 Email configuration

- `SPEC-10.11.1` `GET /v1/admin/email` must require an admin and return the resolved email configuration with the
  source label, `secrets_storage`, `has_smtp_password` and `has_imap_password` booleans (the password values, masked or
  not, must never be returned), and `smtp_password_editable` and `imap_password_editable` true only when the secrets
  provider is writable.
- `SPEC-10.11.2` `PUT /v1/admin/email` must require the plain admin extractor (so an unverified admin can repair mail),
  accept `smtp_tls` only as `implicit` or `starttls` (400 on field `smtp_tls` "Must be 'implicit' or 'starttls'"), and
  `smtp_port` and `imap_port` only within 1 to 65535 (400 on the field "Must be between 1 and 65535").
- `SPEC-10.11.3` Blank or whitespace-only text fields must mean "no change", and a non-empty `smtp_password` or
  `imap_password` under a read-only secrets provider must be refused with the read-only-provider error before any write
  (SMTP first, then IMAP).
- `SPEC-10.11.4` With the `database` provider a given password must be encrypted and stored as ciphertext; with the
  `infisical` provider it must be written to the provider first, a failure aborting the save with its cause before the
  row changes and without a reload.
- `SPEC-10.11.5` After storing, the handler must re-read the row, resolve the configuration (using the password just
  written, else the provider's), hot-reload the live email service (returning its error on failure), and log
  "Email config updated and hot-reloaded" at info.
- `SPEC-10.11.6` The email configuration must be refused with 400 on field `enabled` "Email cannot be disabled in a
  production deployment" when it resolves to disabled in a production deployment, by a check also callable from settings
  archive import.
- `SPEC-10.11.7` A save must write an `AdminEmailConfigUpdated` audit entry (metadata `setting` = `email_config`,
  submitted `enabled`, `smtp_host`, `smtp_port`, `smtp_tls`, `smtp_username`, `from_email`, `from_name`,
  `password_changed`, and `secret` = `SMTP_PASSWORD` and `secret_store` only when a password was written), never a
  password, and return the resolved configuration with source `database`.
- `SPEC-10.11.8` `POST /v1/admin/email/test` must require the plain admin extractor, consume one call from that admin's
  `SMTP_TEST` rate limit (keyed by the admin's user id; an exceeded limit returns the rate-limit error), connect to the
  saved SMTP settings, negotiate TLS and authenticate without sending mail, and always answer 200 with `{ok, stage,
  message}` where a success is `ok` true, stage `ok` and message "SMTP connection and authentication succeeded." and a
  failure is `ok` false with the failing stage (connect, tls or auth) and its message.
- `SPEC-10.11.9` The connection test must write an `AdminEmailConnectionTested` audit entry (metadata `smtp_host`,
  `smtp_port`, `smtp_tls`, `ok`, `stage`).
- `SPEC-10.11.10` `POST /v1/admin/email/test-send` must require the plain admin extractor, take no body and no recipient,
  share the `SMTP_TEST` limit, reload the live email service from the saved settings and send a test message only to the
  signed-in admin's own address.
- `SPEC-10.11.11` The test send must always answer 200 with `{ok, message}`: success is `ok` true with "Test message sent
  to your address. Check your inbox."; a transport build failure or send failure is `ok` false with the relay's text
  with a leading "Internal error: " removed, logged at error with the SMTP host.
- `SPEC-10.11.12` The test send must write an `AdminTestEmailSent` audit entry (metadata `smtp_host`, `smtp_port`,
  `smtp_tls`, `ok`) and must not record the recipient address.

### 10.12 Tier configuration and tier settings

- `SPEC-10.12.1` Resolving an admin-managed section's configuration must fail with 400 naming the offending variable, its
  reason and remedy when the database provider refuses a startup-only value, and must label the source with the first
  provider serving any of the section's keys, or `environment` when none does.
- `SPEC-10.12.2` `GET /v1/admin/tier-config` must require an admin and return the resolved tier configuration with
  `pricing_enabled`, the three tier visibility flags, `orgs_enabled`, the slot and trial values, the mapped price and
  product ids, `source`, `lifetime_slots_used`, `early_adopter_slots_used`, `updated_at` and `updated_by`.
- `SPEC-10.12.3` `PUT /v1/admin/tier-config` must require an admin and reject a negative `lifetime_slots`,
  `early_adopter_slots`, `early_adopter_trial_days` or `standard_trial_days` with 400 on that field "Must be non-negative".
- `SPEC-10.12.4` Each of `free_price_id`, `early_adopter_price_id` and `standard_price_id` must be three-state: omitted
  keeps the stored mapping, a blank value clears the mapping and its derived product, a non-empty id sets it; the free
  price must derive the lifetime product.
- `SPEC-10.12.5` Before consulting Stripe, a tier touched by the request (a price op or a visibility flag) with the
  effective visibility true and no effective price must be refused with 400 on field `tier_visible` naming every
  offending tier in one message, judged on the request merged onto the stored row.
- `SPEC-10.12.6` A price being set must be looked up in the app-tagged Stripe price list and its product stored as the
  mapped product: an archived price must be refused with 400 on field `price_id` "<tier>: <id> is archived in Stripe. Map
  an active price.", and an unknown price with "<tier>: <id> is not visible under app tag `<tag>`. Check the id, or set that
  product's app_tag metadata in Stripe.".
- `SPEC-10.12.7` A tier-config save must reload the live tier configuration, invalidate the public pricing cache, log
  the resolved configuration at info, write an `AdminTierConfigUpdated` audit entry (metadata `setting` = `tier_config`
  with the submitted values and the derived product ids written) and return the configuration with source `database`.
- `SPEC-10.12.8` `PUT /v1/admin/tier-settings` must require an admin and every one of `lifetime_slots`,
  `early_adopter_slots`, `early_adopter_trial_days`, `standard_trial_days`, `orgs_enabled`, `trial_period_days`; it must
  reject negative slot and trial values ("Must be non-negative") and a `trial_period_days` outside 0 to 365 ("Must be
  between 0 and 365") with 400 before any write.
- `SPEC-10.12.9` The tier-settings save must update the tier configuration row, update the Stripe configuration trial
  length, and write an `AdminTierConfigUpdated` audit entry (metadata `endpoint` = `tier-settings` and the six values) in
  one transaction, so a failure of any of them rolls back all.
- `SPEC-10.12.10` After commit the tier-settings save must reload the live tier configuration and invalidate the pricing
  cache, and return `{"tier_config": ..., "trial_period_days"}`.

### 10.13 IP bans, IP enrichment and auto-ban configuration

- `SPEC-10.13.1` `GET /v1/admin/ip-bans` must require an admin and return every currently active ban (IP, reason,
  strikes, banned_at, expires_at) as listed by the auto-ban service, which merges persisted rows with the live in-memory
  map; a service error must be returned as that error.
- `SPEC-10.13.2` `POST /v1/admin/ip-bans` with body `{"ip", "reason", "duration_secs"?}` must require the super admin and
  validate before touching any state: the IP (trimmed, IPv4 or IPv6) must parse, else 400 "'<input>' is not a valid IP
  address"; the trimmed reason must be non-empty (400 "reason is required") and at most 255 characters (400 "reason must
  be at most 255 characters"); `duration_secs` must default to 86400 when absent and otherwise lie within 60 to 31536000
  inclusive, else 400 "duration_secs must be between 60 and 31536000".
- `SPEC-10.13.3` A valid manual ban must go through the auto-ban service (so it is enforced from the next request and
  persisted to `ip_bans`), replacing the reason and expiry of an already banned address, and the response must be the
  success envelope with `ip` (normalized text) and `expires_at`.
- `SPEC-10.13.4` A manual ban must write an `AdminIpBanCreated` audit entry with metadata `ip`, `reason` (trimmed) and
  `expires_at`.
- `SPEC-10.13.5` `DELETE /v1/admin/ip-bans/{ip}` must require an admin, return 400 "'<input>' is not a valid IP address"
  for an unparseable path value, lift the ban through the auto-ban service, return 404 "IP ban" not found when the address
  was not banned, and on a lift write an `AdminIpBanLifted` audit entry (metadata `ip`) before answering with the no-data
  success envelope.
- `SPEC-10.13.6` `GET /v1/admin/ip-enrichment?ip=<addr>` must require an admin and return 400 "Invalid IP address" when
  the trimmed `ip` does not parse as an IPv4 or IPv6 address.
- `SPEC-10.13.7` When no enrichment service is configured (the offline dataset path is unset), or the address is
  private or reserved, or the dataset has no record for it, the enrichment endpoint must return the no-data success
  envelope with status 200 and not an error.
- `SPEC-10.13.8` When enrichment exists the response must carry `ip` (the trimmed input text), `asn`, `organization`,
  `isp`, `category` and `vpn` as the lowercase labels of their enums, `is_anonymizing` (true only for the VPN and proxy
  likelihoods, not for a data-center range), `proxy_type`, `provider`, `threat`, and `advisory` always true.
- `SPEC-10.13.9` `GET /v1/admin/auto-ban-config` must require an admin and return the resolved auto-ban configuration
  (`enabled`, `threshold`, `window_secs`, `ban_duration_secs`), its `source`, `updated_at` and `updated_by`.
- `SPEC-10.13.10` `PUT /v1/admin/auto-ban-config` must require an admin and reject a provided `threshold`, `window_secs`
  or `ban_duration_secs` below 1 with 400 on that field "Must be at least 1", store the provided values, hot-reload the
  running auto-ban service, log the resolved configuration at info, write an `AdminAutoBanConfigUpdated` audit entry
  (metadata `setting` = `auto_ban_config` and the submitted values) and return the configuration with source `database`.

### 10.14 Encryption key health and rotation

- `SPEC-10.14.1` A stored encrypted value must be reported `healthy` when some key in the application key set decrypts it,
  `unhealthy` with the decryption error as message when none does, and `no_data` (no data, no version) when the ciphertext
  or the nonce is absent; a missing stored version must be treated as the current version, and `needs_reencrypt` must be
  true whenever the value is not under the current key and version.
- `SPEC-10.14.2` Combining several value checks must yield `unhealthy` if any is (message listing each unhealthy label
  and error joined by "; "), else `healthy` if any has data, else `no_data`; `needs_reencrypt` must be true if any needs it,
  false if some has data and none needs it, and null otherwise.
- `SPEC-10.14.3` The key ids must be `stripe` (secret key, webhook secret), `totp` (active and pending secret of every
  user), `email` (SMTP and IMAP passwords), `mirzam` (API token) and `mokosh` (Google client secret); an unknown id must
  return 404 "Unknown key: <id>".
- `SPEC-10.14.4` `GET /v1/admin/key-health` must require an admin, run every key check, return a failing check as an
  error, and answer `{"status", "checks"}` with status `degraded` when any check is unhealthy, else `healthy`; a check
  that cannot be serialized must be logged at error with the key id.
- `SPEC-10.14.5` `GET /v1/admin/key-health/{key_id}` must require an admin and return the single check, or 404 for an
  unknown id.
- `SPEC-10.14.6` `GET /v1/admin/key-rotation/{key_id}/status` must require an admin and return `key_id`,
  `current_version`, `total`, `on_current_version`, `on_old_versions` and `rotation_complete`: for `totp` a row counts as
  current only when its active secret and any pending secret are on the current version; for the singleton stores the total
  is 1 when a secret is stored and 0 otherwise, and rotation is complete when nothing is stored or all stored values are
  under the current key; an unknown id must return 404 "Unknown key: <id>".
- `SPEC-10.14.7` `POST /v1/admin/key-rotation/{key_id}/reencrypt` must require an admin, return 404 for an unknown id,
  re-encrypt every value of that store not already under the current key (idempotently, sharing the pass of the
  `reencrypt-secrets` subcommand), write an `AdminKeyRotation` audit entry (metadata `key_id`, `reencrypted`, `total`,
  `undecryptable` count, `new_version`), and return `key_id`, `reencrypted`, `total` (rewritten plus already current plus
  undecryptable), the `undecryptable` values (reported, never cleared) and `key_version`.

### 10.15 Admin branding

- `SPEC-10.15.1` `GET /v1/admin/branding` must require an admin and return the stored singleton row resolved through the
  branding cache together with `updated_at` and `updated_by`.
- `SPEC-10.15.2` `PUT /v1/admin/branding` must validate every field before writing; a failing field must produce a 400
  validation error carrying that field name and an admin-facing message (never a 5xx, which the web tier would collapse
  into a generic line) and must write nothing.
- `SPEC-10.15.3` A valid `PUT /v1/admin/branding` must replace the row with `updated_by` set to the acting admin, store
  the new row in the api-side branding cache within the same request, log "Branding updated and hot-reloaded" with the
  brand name, and return the resolved branding with the row's `updated_at` and `updated_by`.
- `SPEC-10.15.4` A branding save must write an `AdminBrandingUpdated` audit entry with metadata `setting` = `branding`
  and the saved `brand_name`, `tagline`, `meta_description`, `og_image_url`, `newsletter_url`, `theme_css`,
  `theme_color_light` and `theme_color_dark` values.
- `SPEC-10.15.5` `POST` and `DELETE /v1/admin/branding/assets/{slot}` must accept only the slots `mark`, `favicon` and
  `mascot`, checked before any storage access; any other value must return a 400 validation error on field `asset` with
  the message "Unknown brand asset. Expected mark, favicon or mascot.".
- `SPEC-10.15.6` The asset upload must read the first multipart part that carries a filename, skip and drain parts
  without one, and enforce the avatar image policy (2 MiB, 4096 px, PNG/JPEG/WebP/GIF) while streaming: exceeding the
  byte cap must abort with a 400 on field `asset`, a body with no file part must be a 400 (empty image), and a multipart
  read failure must be a 400 on field `asset` ("Invalid multipart data" or "Failed to read field").
- `SPEC-10.15.7` The uploaded bytes must pass image validation before any derivation; a rejection must be logged at
  warn with the reason and returned as a 400 on field `asset` carrying the validation rule text.
- `SPEC-10.15.8` The upload must derive the stored files on the blocking thread pool, using the favicon icon set for
  `favicon`, the 64 px mark for `mark` and the 448/896 pair for `mascot`; a derivation error message must be returned as
  a 400 on field `asset`, and a failed task join must be logged at error with the slot and returned as an internal error
  "Could not process that image", never as an invalid-image error.
- `SPEC-10.15.9` A successful upload must replace the whole slot in one transaction (a failure leaves the previous brand
  intact), refresh the branding cache, log "Brand asset uploaded" with slot, MIME type and file count, write an
  `AdminBrandingUpdated` audit entry (metadata `setting` = `branding_asset`, `slot`, `action` = `upload`, `mime`) and
  return the resolved branding.
- `SPEC-10.15.10` `DELETE /v1/admin/branding/assets/{slot}` must clear the slot, succeed when the slot was already empty,
  refresh the branding cache, log "Brand asset cleared", write an `AdminBrandingUpdated` audit entry (`setting` =
  `branding_asset`, `slot`, `action` = `clear`) and return the resolved branding.

### 10.16 Admin feature toggles

- `SPEC-10.16.1` `GET /v1/admin/feature-toggles` must require an admin and list every feature in the registry, in
  registry order, with key, label, help, `enabled`, `updated_at`, `updated_by` and the updater's email; a feature with no
  stored row must read `enabled` false with no `updated_at` or `updated_by`, and a stored key absent from the registry
  must not be listed.
- `SPEC-10.16.2` `PUT /v1/admin/feature-toggles/{key}` with body `{"enabled": bool}` must require the super admin and
  return 404 "Feature" not found for a key that is not registered, storing nothing.
- `SPEC-10.16.3` The toggle upsert (with `updated_by` the acting admin) and its `AdminFeatureToggleUpdated` audit entry
  (metadata `key`, `enabled`) must be written in one transaction, so neither persists without the other.
- `SPEC-10.16.4` After the commit the handler must re-read the table into the process-wide snapshot; if the re-read
  fails it must log a warning "feature_toggles could not be re-read; keeping the last loaded snapshot" with the error and
  keep the previous snapshot, and a poisoned snapshot lock must be recovered rather than panic.
- `SPEC-10.16.5` The `PUT` response must be the refreshed entry for that feature; if the saved feature is missing from
  the registry listing the handler must return an internal error.

### 10.17 Admin rate limits

- `SPEC-10.17.1` `GET /v1/admin/rate-limits` must require an admin and return, in the paginated envelope, every currently
  active throttle: each `rate_limits` row whose window is still open and whose count is at or over the cap of the
  action's effective configuration (preset with any persisted override applied), plus each user at or over
  `RESEND_LIMIT_MAX` email-verification tokens or email-change requests within the last `RESEND_LIMIT_WINDOW_SECS`,
  reported under the pseudo-actions `email_verification` and `email_change`.
- `SPEC-10.17.2` Each entry must carry `action`, the raw `key` (the user id for the pseudo-actions), `count`,
  `max_requests` from the effective configuration (the resend constant for pseudo-actions), `window_start` and
  `retry_after` seconds computed at request time from the window start and never stored.
- `SPEC-10.17.3` An IP-keyed entry must expose `ip` and never a user; an email-keyed or user-id-keyed entry (and an
  unknown-subject key) must expose the resolved user id and email, or neither when no live user matches; a client-id
  keyed entry must expose neither; a pseudo-action entry must always carry its user.
- `SPEC-10.17.4` The list must be paginated in memory with `page` defaulting to 1 and at least 1 and `per_page` defaulting
  to 20 and clamped to 1..=100, and computing the start offset must saturate so that `page=2147483647` neither panics nor
  wraps.
- `SPEC-10.17.5` `POST /v1/admin/rate-limits/reset` with body `{"action", "key"}` must require an admin, trim both values,
  and return 400 "action and key are required" when either is empty.
- `SPEC-10.17.6` For the `email_verification` and `email_change` actions the reset must require `key` to be a user id
  (else 400 "key must be a user id for the '<action>' limiter"), return 404 "User" not found for an unknown user, and
  delete that user's in-window verification tokens or change requests so the count falls below the resend threshold.
- `SPEC-10.17.7` For every other action the reset must require a known preset (else 400 "unknown rate-limit action
  '<action>'"), delete the matching `rate_limits` row for `(key, action)`, and resolve the target user when the key is an
  email or user id.
- `SPEC-10.17.8` A reset must write an `AdminRateLimitReset` audit entry (metadata `action`, `key`, `target_user_id`,
  `target_email`, and resource `user` when a target user resolved) and answer with the no-data success envelope.
- `SPEC-10.17.9` `GET /v1/admin/rate-limit-configs` must require an admin and return one entry per known action in
  registry order with the effective `max_requests` and `window_seconds` (the persisted override when present, else the
  default), `default_max_requests` and `default_window_seconds` (the default resolved through the deployment providers
  before any database override), `overridden`, and the override's `updated_at` and `updated_by` (absent when not
  overridden).
- `SPEC-10.17.10` `PUT /v1/admin/rate-limit-configs/{action}` with body `{"max_requests", "window_seconds"}` must require
  the super admin, return 400 "unknown rate-limit action '<action>'" for an action that is not a known preset, and
  reject with 400 a `max_requests` outside 1..=1000000 ("max_requests must be between 1 and 1000000") or a
  `window_seconds` outside 1..=604800 ("window_seconds must be between 1 and 604800"); the same validation must be applied
  to limits restored from a settings archive.
- `SPEC-10.17.11` A valid override must be upserted with `updated_by` the acting admin so that it applies from the next
  request, an `AdminRateLimitConfigUpdated` audit entry (metadata `action`, `max_requests`, `window_seconds`) must be
  written, and the response must be the resulting configuration entry.
- `SPEC-10.17.12` `DELETE /v1/admin/rate-limit-configs/{action}` must require the super admin, return 400 for an unknown
  action, return 404 "Rate limit override" not found when no override existed, and otherwise delete it (reverting to the
  default), write an `AdminRateLimitConfigDeleted` audit entry (metadata `action`) and return the no-data success
  envelope.
- `SPEC-10.17.13` `GET /v1/admin/rate-limits/history` must require an admin, consume one call from that admin's
  `ADMIN_DIAGNOSTICS` budget before reading (a spent budget must return the rate-limit error), and return throttle events
  newest first with `since` defaulting to and never earlier than 24 hours ago and `limit` defaulting to 100 and clamped to
  1..=1000.
- `SPEC-10.17.14` Each history entry must carry `action`, `key`, `fired_at`, `expires_at` and the subject resolved as for
  active throttles (email or user id to user, IP to `ip`, client id or an action without a preset to neither) without
  dropping the row.
- `SPEC-10.17.15` `GET /v1/admin/rate-limits/overview?window&threshold&limit` must require an admin, consume exactly one
  `ADMIN_DIAGNOSTICS` call regardless of the number of actions, and return 400 validation errors on field `window`
  ("`window` must be one of `1h`, `6h`, `1d`", default `1h`) or field `threshold` ("`threshold` must be between 0.1 and
  1.0", default 0.7); `limit` must default to 5 and be clamped to 1..=100.
- `SPEC-10.17.16` The overview must return one entry per known action in registry order, each with `traffic` (action,
  effective `max_requests` and `window_seconds`, `bucket_width_seconds`, and the points in the requested window) and
  `approaching` rows: keys whose window is still open and whose count is at least `ceil(max_requests * threshold)` and
  not above `max_requests`, at most `limit` per action, each resolved to a user or IP as for active throttles, with email
  matching case-insensitive and users looked up in two batched queries.
- `SPEC-10.17.17` `GET /v1/admin/rate-limits/whitelist` must require an admin and return every whitelist entry with `id`,
  `kind`, `value`, `reason`, `added_by` and `added_at` (RFC 3339).
- `SPEC-10.17.18` `POST /v1/admin/rate-limits/whitelist` with body `{"kind", "value", "reason"?}` must require an admin,
  accept only the trimmed kinds `user`, `email` and `ip` (else 400 "kind must be one of 'user', 'email', or 'ip'"),
  require a non-empty trimmed value (else 400 "value is required"), and treat a missing reason as empty.
- `SPEC-10.17.19` An add must be idempotent on `(kind, value)`: a new row must write an `AdminRateLimitWhitelistAdded`
  audit entry (resource `rate_limit_whitelist`, metadata `kind`, `value`, `reason`) and be returned; an existing pair must
  write no audit entry and return success with null data.
- `SPEC-10.17.20` `DELETE /v1/admin/rate-limits/whitelist/{id}` must require an admin, return 404 "rate_limit_whitelist
  entry" not found when nothing was removed, and otherwise write an `AdminRateLimitWhitelistRemoved` audit entry carrying
  the removed row's `kind` and `value` and return the no-data success envelope.

### 10.18 Mailer suppressions, Mirzam, Mokosh and OAuth tenant assignments

- `SPEC-10.18.1` `GET /v1/admin/mailer-suppressions?page&per_page` must require an admin and return suppressed addresses
  newest first in the paginated envelope with the total count; `page` must default to 1 and be at least 1, `per_page`
  must default to 20 and be clamped to 1..=100.
- `SPEC-10.18.2` `DELETE /v1/admin/mailer-suppressions/{address}` must require a verified admin, return 404 "Suppressed
  address" not found when the address is not suppressed, and on removal write an `AdminMailerSuppressionDeleted` audit
  entry (metadata `address`) before answering with the no-data success envelope.
- `SPEC-10.18.3` `GET /v1/admin/mirzam` must require an admin and return the stored settings, the secrets provider, and
  `has_api_token` (true only when the governed secret `MIRZAM_API_TOKEN` is stored and not blank); the token value must
  never be returned, and a secret-read failure must be returned as an error.
- `SPEC-10.18.4` `PUT /v1/admin/mirzam` must treat a missing, empty or whitespace-only `api_token` as "leave the stored
  token unchanged", and must reject a non-empty token with the read-only-provider error when `SECRETS_STORAGE` is the
  read-only provider (`environment`), before any validation or write.
- `SPEC-10.18.5` `PUT /v1/admin/mirzam` must validate the four settings (`enabled`, `base_url`, `updates_list`,
  `notices_list`) as a whole and answer a failure with a 400 naming the field, writing nothing; switching `enabled` on
  with neither a new token nor a stored token must be a 400 on the token form field with "Set the API token before
  switching the integration on.".
- `SPEC-10.18.6` A valid Mirzam save must write the token (when given) to the declared secrets provider first, so a
  failed secret write aborts the save with its cause and leaves the settings row untouched, then replace the four
  settings with `updated_by` the acting admin.
- `SPEC-10.18.7` A Mirzam save must write an `AdminMirzamConfigUpdated` audit entry with metadata `setting` =
  `mirzam_config`, `enabled`, `base_url`, `updates_list`, `notices_list`, `token_changed`, and (only when a token was
  written) `secret` (the governed secret name) and `secret_store` (the provider), and must never include the token; the
  response must be the settings with `has_api_token` true when a token was written or one is stored.
- `SPEC-10.18.8` `POST /v1/admin/mirzam/check` must require an admin and return 400 on field `base_url` when the saved
  address or either saved list slug is blank, and 400 on the token form field "No API token is set. Save one before
  checking the connection." when no token is stored.
- `SPEC-10.18.9` The check must test both saved lists with the saved token and return the report in the success
  envelope with status 200 even when `ok` is false (a failing Mirzam is a result, not an API error); when `ok` is false
  it must log at warn the saved base URL and each failing list with its message.
- `SPEC-10.18.10` `GET /v1/admin/mokosh` must require an admin and return the stored Google client id, the secrets
  provider and `has_secret` (true only when the governed secret `MOKOSH_GOOGLE_CLIENT_SECRET` is stored and not blank);
  the secret value must never be returned.
- `SPEC-10.18.11` `PUT /v1/admin/mokosh` must treat a missing or blank `google_client_secret` as "leave the stored
  secret unchanged", reject a non-empty secret with the read-only-provider error under `SECRETS_STORAGE=environment`,
  and validate the client id (and the secret when given) before any write, answering a failure with a 400 naming the
  field.
- `SPEC-10.18.12` When the trimmed client id differs from a previously stored non-empty id and the body does not set
  `confirm_client_id_change`, the save must return 409 Conflict with the message "Changing the client id stops Google
  contact sync for every Mokosh tenant until each one reconnects their Google account: their existing permission was
  granted to the old client. Send the same change again with confirm_client_id_change to go ahead." and write nothing;
  setting an id when none was stored must not require confirmation.
- `SPEC-10.18.13` A non-empty client id with neither a new secret nor a stored secret must be refused with a 400 on the
  secret form field "Set the client secret too: an id without it authenticates as nothing.".
- `SPEC-10.18.14` A valid Mokosh save must write the secret (when given) to the declared provider first, so a failed
  secret write leaves the row untouched, then replace the client id with `updated_by` the acting admin.
- `SPEC-10.18.15` A Mokosh save must write an `AdminMokoshConfigUpdated` audit entry with metadata `setting` =
  `mokosh_config`, `google_client_id`, `client_id_changed`, `secret_changed`, and (only when a secret was written)
  `secret`, `secret_store` and `secret_sha256` (lowercase hex SHA-256 of the secret), and must never contain the secret
  value; the response must carry `has_secret` true when a secret was written or one is stored.
- `SPEC-10.18.16` `GET /v1/admin/oauth-clients/{client_id}/user-tenants` must require an admin and return every
  (user, tenant) assignment for that client oldest first as a flat array without pagination.
- `SPEC-10.18.17` `POST /v1/admin/oauth-clients/{client_id}/user-tenants` with body `{"user_id", "tenant_id", "role"}`
  must require an admin and upsert the assignment idempotently with the acting admin recorded, and must write an
  `OauthUserTenantAssigned` audit entry (resource `oauth_client` with the path id, metadata `user_id`, `tenant_id`,
  `role`, `assignment_id`) on every successful call, including when the data did not change.
- `SPEC-10.18.18` After an assignment the handler must revoke every outstanding refresh-token family of that user for
  that client, so the next token comes from a fresh authorization that re-runs tenant selection; a revocation failure
  must be returned as an error. The response must be the assignment row.
- `SPEC-10.18.19` `DELETE /v1/admin/oauth-clients/{client_id}/user-tenants/{assignment_id}` must require an admin, be
  idempotent when the assignment is already gone, and write an `OauthUserTenantUnassigned` audit entry on every call
  (resource `oauth_client`, metadata `assignment_id`, and `user_id` and `tenant_id` of the removed row or null when none
  was removed) before answering with the no-data success envelope.
- `SPEC-10.18.20` When the delete removed a row the handler must revoke the removed user's refresh-token families for the
  removed row's client; when nothing was removed it must not revoke anything.

### 10.19 Stripe catalog administration

- `SPEC-10.19.1` Every handler under `/v1/admin/stripe/` (products, prices, webhooks, permissions) must require an
  admin, and a Stripe API failure must be returned as an error mapped for the permission the call needs (products,
  prices or webhook endpoints) so a missing key permission is explained to the admin.
- `SPEC-10.19.2` A plan scope must be resolved from `tier_config`: the tiers are `free` (matched by `free_price_id`),
  `lifetime` (matched only by `lifetime_product_id`), `early_adopter` and `standard` (each matched by its price id or
  product id). For a product the scope must be every tier whose product id equals the product or whose price id is one of
  the product's prices, with the product's full price set; for a single price it must be every tier whose price id equals
  that price, with that one price id.
- `SPEC-10.19.3` `GET /v1/admin/stripe/products` must return each product with a `member_count` of members on its plan,
  computed from one grouped query for the whole page and not one query per product.
- `SPEC-10.19.4` `GET /v1/admin/stripe/prices` must return each price with a `member_count` (members on the tier the
  price maps to plus members who locked that price), computed from one grouped query for the whole page.
- `SPEC-10.19.5` `POST /v1/admin/stripe/products` (name, optional description and metadata) and
  `PUT /v1/admin/stripe/products/{id}` (optional name, description, metadata, active) must create or update the Stripe
  product and return it; an absent field must leave the Stripe value unchanged.
- `SPEC-10.19.6` `DELETE /v1/admin/stripe/products/{id}` must first resolve the product's prices and its plan and, when
  any member is on the plan, return 409 "Cannot archive this product: <n> member(s) is/are on it. Move them to another
  plan first." (singular "member ... is" for one) without making any Stripe write.
- `SPEC-10.19.7` When the plan has no members, the product archive must archive every active price of the product first,
  one at a time, and only then the product; if a price archive fails it must stop, log at error the product id, the
  failed price id, the already archived price ids and the error, leave the product active, and return an internal error
  "Archive incomplete: archived price(s) [<ids>] but failed on <id>; the product was left active. Retry the archive.".
- `SPEC-10.19.8` A completed product archive must write an `AdminStripePlanArchived` audit entry (metadata `product_id`,
  `archived_price_ids`, `member_count`), invalidate the public pricing cache, and return the no-data success envelope.
- `SPEC-10.19.9` `POST /v1/admin/stripe/products/{id}/unarchive` must set the Stripe product active without sending
  metadata (so existing metadata survives), must not restore any price and must not be member-guarded, then write an
  `AdminStripePlanUnarchived` audit entry (metadata `product_id`), invalidate the pricing cache and return the no-data
  success envelope.
- `SPEC-10.19.10` Two active prices on one product must be treated as the same price when they share lowercase currency,
  recurring interval and interval count, where a recurring price with no interval count counts as 1 and a one-time price
  (no interval) forms its own bucket.
- `SPEC-10.19.11` `POST /v1/admin/stripe/prices` (product id, unit amount, currency, interval) must, before calling
  Stripe, list the product's prices and return 409 when another active price holds the same key (requested interval
  lowercased with count 1): "This product already has an active <interval or one-time> <CURRENCY> price (<id>, <amount>).
  Archive it or use Replace to change its amount."; otherwise it must create the price, invalidate the pricing cache and
  return the price.
- `SPEC-10.19.12` A price amount in refusal messages must be formatted as `--` when absent, `$W.CC`, `€W.CC` or `£W.CC` for
  `usd`, `eur` or `gbp` (case-insensitive), and `W.CC <UPPERCASE CODE>` for any other currency, where `CC` is the two-digit
  minor-unit remainder.
- `SPEC-10.19.13` `DELETE /v1/admin/stripe/prices/{id}` must return 409 "Cannot archive this price: <n> member(s) is/are
  on it. Move them to another plan first." without any Stripe write when the price's plan has members; otherwise it must
  archive the price, write an `AdminStripePlanArchived` audit entry (metadata `product_id` null, `archived_price_ids` with
  the id, `member_count`), invalidate the pricing cache and return the no-data success envelope.
- `SPEC-10.19.14` `POST /v1/admin/stripe/prices/{id}/unarchive` must look the price up in the full catalog (active and
  archived), return 404 "Stripe price" not found when it is absent, return the duplicate-price 409 when another active
  price holds its key (the price itself ignored), and otherwise restore it, write an `AdminStripePlanUnarchived` audit
  entry (metadata `price_id`), invalidate the pricing cache and return the no-data success envelope.
- `SPEC-10.19.15` `POST /v1/admin/stripe/prices/{id}/replace` (unit amount, currency, interval) must return 404 "Stripe
  price" not found unless the old price is in the app-tagged catalog, create the replacement on the same product without
  running the duplicate-price check, then repoint references to the new price before archiving the old one: the
  `free_price_id`, `early_adopter_price_id` and `standard_price_id` columns that equal the old id (other columns
  unchanged), then every application price mapping from old to new (add the new mapping, then remove the old).
- `SPEC-10.19.16` After repointing a tier column the replace must leave the process-wide tier configuration snapshot equal
  to the row just written, then archive the old price directly (bypassing the member guard, so a replace succeeds while
  members exist), and must leave `users.locked_price_id` and subscription price ids untouched.
- `SPEC-10.19.17` Any failure after the new price was created (reading or writing the tier config, reloading the snapshot,
  moving a price mapping, archiving the old price) must be logged at error with the old, new and product ids, the failed
  step and the cause, and returned as an internal error "Price replace incomplete: created the new price <id>, but <step>
  failed: <cause>. The new price exists in Stripe; retry the replace or finish it by hand. Old price: <old id>.", never as
  success.
- `SPEC-10.19.18` A completed replace must write an `AdminStripePriceReplaced` audit entry (metadata `old_price_id`,
  `new_price_id`, `product_id`, `unit_amount`, `currency`, `interval`, `repointed_tier_columns`,
  `repointed_application_ids`), invalidate the pricing cache and return the new price.
- `SPEC-10.19.19` Every handler that creates, archives, unarchives or replaces a price or archives or unarchives a product
  must invalidate the public pricing cache after its Stripe write.
- `SPEC-10.19.20` `GET /v1/admin/stripe/webhooks` must list the Stripe webhook endpoints and
  `DELETE /v1/admin/stripe/webhooks/{id}` must delete one, returning the no-data success envelope.
- `SPEC-10.19.21` `POST /v1/admin/stripe/webhooks` (url, enabled events) must create the endpoint and, when Stripe returns
  a signing secret and the secrets provider is writable, store it as the governed secret `STRIPE_WEBHOOK_SECRET` with
  `updated_by` the acting admin, rebuild the Stripe runtime configuration from the stored row, reload the Stripe service
  and log the reload at info; a failure of any of those steps must be returned as an error.
- `SPEC-10.19.22` When the endpoint was created but `SECRETS_STORAGE` is the read-only provider (`environment`), the
  handler must log at error that the signing secret was not saved and where to write it, and return the read-only
  provider error rather than the endpoint.
- `SPEC-10.19.23` `GET /v1/admin/stripe/permissions` must make no change in Stripe or the database; when a key is
  configured it must probe the product, price and webhook-endpoint list calls and classify each, and when none is
  configured it must make no call.
- `SPEC-10.19.24` The permissions report must carry `configured`, `key_status` (`not_configured` when unconfigured,
  `rejected` when any probe was classified key-rejected, else `ok`) and a check for each of: products, prices and webhook
  endpoints (Write, `admin`, live-tested) and customers, checkout sessions, subscriptions (Write) and invoices (Read)
  (`checkout`, never live-tested and always reported untested).

### 10.20 Shared handler helpers

Helpers in `bunyip-api/src/handlers/mod.rs` used by several handler families.

- `SPEC-10.20.1` `live_free_price_id` must return the `free_price_id` currently held in the live `TierConfig` lock, so
  an admin edit takes effect without a restart, and must return `None` when no price id is configured (the caller then
  skips the $0 subscription).
- `SPEC-10.20.2` When the `TierConfig` lock is poisoned, `live_free_price_id` must log at `error` that the lock was
  poisoned, recover the data through the poison, and still return the stored `free_price_id`; it must not panic.
- `SPEC-10.20.3` `check_rate_limit` must resolve the effective cap (compiled constant, then environment override, then
  persisted override) before comparing, then increment the counter for `key` in the same call.
- `SPEC-10.20.4` When the counter exceeds the effective cap, `check_rate_limit` must return `AppError::RateLimited`
  carrying a `retry_after` read from the remaining window, on every over-limit request.
- `SPEC-10.20.5` A rate-limit trip must be logged at `error` with `category = "rate_limit"`, the `client` key, the
  `action` and `retry_after`, and only for the first over-limit request in a window (post-increment count equal to
  `max_requests + 1`); later over-limit requests in the same window must not log, and each new window logs its first
  trip again.
- `SPEC-10.20.6` `require_totp_if_enabled` must do nothing and succeed when the user has no TOTP enrollment or the
  enrollment is not verified; a trusted-device cookie must never satisfy it, only a live code.
- `SPEC-10.20.7` When the user has a verified TOTP, `require_totp_if_enabled` must fail with a validation error on field
  `totp_code` ("Two-factor code required") when the code is absent or empty after trimming and removing spaces.
- `SPEC-10.20.8` `require_totp_if_enabled` must verify a code containing `-` or longer than 6 characters as a recovery
  code and any other code as a TOTP code, and must fail with a validation error on field `totp_code` ("Invalid
  verification code") when verification returns false; errors from the verification service must propagate unchanged.

### 10.21 Authentication: sessions, registration and password login

Handlers in `bunyip-api/src/handlers/auth.rs` that mint sessions.

- `SPEC-10.21.1` `establish_op_session` must return `None` without side effects when no OIDC provider is configured.
- `SPEC-10.21.2` `establish_op_session` must first revoke the OP session whose `sid` the browser's OP session cookie
  carries, so a pre-login `sid` cannot shadow the new session; a revoke failure must be logged at `debug` and must not
  block the login.
- `SPEC-10.21.3` `establish_op_session` must create the OP session with the user id, request user agent, client IP, the
  caller's `acr`, `amr` and `remember`, and return the cookie built from the new `sid` with the `secure` flag and the
  domain from `Config::op_session_cookie_domain()` (never `cookie_domain`) together with the session row id.
- `SPEC-10.21.4` When OP session creation fails, `establish_op_session` must log at `warn` and return `None`, and the
  login must still complete without the OP session cookie.
- `SPEC-10.21.5` `link_hub_refresh_to_op_session` must do nothing when no session was established; otherwise it must
  bind the refresh token to the session id, and on failure must log at `warn` with `user_id` and `session_id` and must
  not fail the login.
- `SPEC-10.21.6` The ACR values recorded on an OP session must be `urn:bunyip:loa:pwd` for password login,
  `urn:bunyip:loa:mfa` after a TOTP-verified login and `urn:bunyip:loa:otp` for magic-link login.
- `SPEC-10.21.7` `revoke_op_sessions` must do nothing when no OIDC provider is configured; otherwise it must complete
  the database revoke before returning and must spawn the back-channel logout deliveries as a background task.
- `SPEC-10.21.8` Each back-channel delivery must POST the form field `logout_token` to the client's registered URI with
  a 5-second client timeout; it must log at `info` on a 2xx reply, at `warn` on a non-2xx reply, on a transport failure,
  and on a failure to mint the token, each with the client id, and must continue with the next target.
- `SPEC-10.21.9` When the back-channel revoke query fails, `revoke_op_sessions` must log at `warn` and return without
  panicking.
- `SPEC-10.21.10` `POST /v1/auth/register` must apply the `REGISTRATION` rate limit keyed by the client IP (the empty
  string when the IP is unknown) in every environment, before any other check.
- `SPEC-10.21.11` When `signup_bot_guard_enabled` is true, `register` must verify the honeypot `contact_channel` and the
  `signup_token` through the auth service and must return its error unchanged; when false, it must not check them.
- `SPEC-10.21.12` `register` must reject an invalid email format with a validation error before creating the account.
- `SPEC-10.21.13` `register` must create the account, then log the user in with `remember = false`, and respond `201`
  with `AuthResponse` (`user`, `expires_in`).
- `SPEC-10.21.14` `register` must set, in order, the stale-cookie clearing cookies, the access-token cookie, a
  refresh-token cookie with `remember = false`, and the OP session cookie when one was established (ACR password, AMR
  `["pwd"]`, `remember = false`), and must link the refresh token to that session.
- `SPEC-10.21.15` `register` must store `stripe_customer_id` and `payment_method_id` on the new user only when both are
  present, and must propagate a storage failure as an error; when only one is present it must store neither.
- `SPEC-10.21.16` `register` must send the account-created email inline with the address marked unverified, and on
  failure must log at `error` without the address and still respond `201`.
- `SPEC-10.21.17` If the login that follows registration returns a two-factor or approval challenge, `register` must
  fail with an internal error naming the unexpected challenge.
- `SPEC-10.21.18` `GET /v1/auth/register-challenge` must require no authentication and no rate limit, and must respond
  `200` with `{"token": <signup timing-challenge token>}`; a token-creation failure must propagate as an error.
- `SPEC-10.21.19` `POST /v1/auth/login` must apply the `LOGIN` rate limit to three keys in this order: `login_ip:<ip>`,
  `login_ip_email:<ip>:<lowercased email>` and `<lowercased email>`, using `unknown` for an unresolved IP, and must
  return the first rate-limit error.
- `SPEC-10.21.20` `login` must pass the trusted-device cookie value, the optional `device_id` and `remember` (default
  false) to the auth service, and must reject a body missing `email` or `password` with a `400` deserialization error.
- `SPEC-10.21.21` When login requires a second factor, `login` must respond `200` with `{"requires_2fa": true,
  "challenge_token": ...}` and set no cookies; when login is withheld pending email approval it must respond `200` with
  `{"requires_approval": true, "challenge_token": ...}` and set no cookies.
- `SPEC-10.21.22` On a successful login, `login` must respond `200` with `AuthResponse`, set the stale-cookie clearing
  cookies, the access-token cookie, a refresh-token cookie whose lifetime follows `remember`, and the OP session cookie
  when established (ACR password, AMR `["pwd"]`, `remember` as requested), and must link the refresh token to the
  session.

### 10.22 Authentication: magic link, approval, invite, refresh, logout, reset, redirect, probe

- `SPEC-10.22.1` `POST /v1/auth/magic-link` must apply the `MAGIC_LINK` rate limit keyed by the lowercased email,
  validate the email format, create the token through the auth service, and send the email from a background task.
- `SPEC-10.22.2` `request_magic_link` must respond `202` with no data once the token is created, without waiting for the
  send, and a send failure must be logged at `error` without the address.
- `SPEC-10.22.3` `POST /v1/auth/magic-link/verify` must apply the `LOGIN` rate limit keyed by the client IP (empty
  string when unknown) before verifying the token.
- `SPEC-10.22.4` `verify_magic_link` must respond `200` with `{"requires_2fa": true, "challenge_token": ...}` when a
  second factor is required and with `{"requires_approval": true, "challenge_token": ...}` when approval is required,
  setting no cookies in either case.
- `SPEC-10.22.5` On a successful magic-link verification `verify_magic_link` must respond `200` with `AuthResponse`, set
  a refresh-token cookie with `remember = true`, and establish the OP session with ACR `urn:bunyip:loa:otp`, AMR
  `["otp"]` and `remember = true`.
- `SPEC-10.22.6` When the magic link created a new account, `verify_magic_link` must send the account-created email
  inline with the address marked verified, and on failure must log at `error` without the address and still log in.
- `SPEC-10.22.7` `POST /v1/auth/login-approval/verify` must require no session, apply the `LOGIN` rate limit keyed
  `login_approval_verify:<ip>`, complete the approval from `challenge_token` and `code`, and return the auth service
  error unchanged on a bad or expired challenge or code.
- `SPEC-10.22.8` On success `verify_login_approval` must respond `200` with `AuthResponse`, set the refresh-token cookie
  with `remember = true`, and establish the OP session with ACR `urn:bunyip:loa:pwd`, AMR `["pwd"]` and `remember =
  true`.
- `SPEC-10.22.9` `POST /v1/auth/invite/accept` must apply the `LOGIN` rate limit keyed by the client IP, and when the
  invite needs a password and none was sent must respond `200` with `{"needs_password": true, "email": ...}` and set no
  cookies.
- `SPEC-10.22.10` On success `accept_admin_invite` must respond `200` with `AuthResponse`, set the refresh-token cookie
  with `remember = true`, and establish the OP session with ACR `urn:bunyip:loa:pwd`, AMR `["pwd"]` and `remember =
  true`.
- `SPEC-10.22.11` `POST /v1/auth/refresh` must read the `refresh_token` cookie; when it is absent it must log at `warn`
  and respond `401`.
- `SPEC-10.22.12` `refresh_token` must log `token_refresh: failed` at `warn` with the request id, error and IP and
  return the auth service error unchanged on failure; on success it must log at `info`, respond `200` with
  `{"expires_in": ...}`, and set the stale-cookie clearing cookies, a new access-token cookie and a new refresh-token
  cookie.
- `SPEC-10.22.13` `POST /v1/auth/logout` must succeed without a valid access token; when the caller is authenticated and
  carries a refresh-token cookie it must revoke that token, and a revoke failure must be logged at `warn` with the user
  id and must not stop the cookie clearing.
- `SPEC-10.22.14` `logout` must, for an authenticated caller, revoke the user's OP sessions and fan out back-channel
  logout, and in every case must respond `200` with no data and the cookie-clearing set from `AuthCookies::clear`.
- `SPEC-10.22.15` `GET /v1/auth/logout?url=` must accept the target only when its host equals the base domain or is a
  subdomain of it, where the base domain is `cookie_domain` without a leading `.` or, when unset, the host of
  `web_origin`; otherwise it must fail with a validation error on field `url` ("Invalid redirect URL", status `422`) and
  revoke nothing.
- `SPEC-10.22.16` For an allowed target `logout_redirect` must revoke the refresh token and OP sessions of an
  authenticated caller (a refresh revoke failure logged at `warn`, not blocking), clear the cookies, and respond `302`
  with `Location` set to the target.
- `SPEC-10.22.17` `POST /v1/auth/logout-all` must require authentication, revoke every session of the user through the
  auth service (propagating its error), revoke the OP sessions, and respond `200` with no data and the cookie-clearing
  set.
- `SPEC-10.22.18` `POST /v1/auth/password-reset` must apply the `PASSWORD_RESET` rate limit keyed by the lowercased
  email, validate the email format, and respond `202` with no data whether or not the auth service returned a token.
- `SPEC-10.22.19` When a reset token is returned, `request_password_reset` must send the reset email from a background
  task including the requester's country name when the IP resolves; a send failure must be logged at `error` without the
  address.
- `SPEC-10.22.20` `POST /v1/auth/password-reset/confirm` must apply the `LOGIN` rate limit keyed by the client IP,
  complete the reset with the token and new password (propagating the service error), send the password-changed email
  from a background task (failure logged at `error` without the address), and respond `200` with no data.
- `SPEC-10.22.21` `GET /v1/auth/password-reset/verify?token=` must check the token without consuming it and respond
  `200` with `{"valid": true}`, or the auth service error when it is invalid.
- `SPEC-10.22.22` `GET /v1/auth/redirect?url=` must apply the same host check as `SPEC-10.22.15` and fail with the `422`
  validation error on field `url` when it does not pass.
- `SPEC-10.22.23` `auth_redirect` must respond `302` to the target when the caller has a valid access token; otherwise
  when a refresh-token cookie is present it must try to refresh and, on success, respond `302` to the target with fresh
  access and refresh cookies after the stale-cookie clearing cookies.
- `SPEC-10.22.24` When there is no valid access token and the refresh is absent or fails (the failure logged at `warn`),
  `auth_redirect` must respond `302` to `<web_origin without trailing slash>/login?redirect=<url-encoded
  target>&checked=1`.
- `SPEC-10.22.25` `auth_redirect` must log only the path of the target URL, never its query string.
- `SPEC-10.22.26` `GET /v1/auth/setup/status` must respond `200` with `email_enabled`, `stripe_enabled` (whether the
  Stripe service is configured), `orgs_enabled` from the live `TierConfig`, and `features` mapping every registered
  feature toggle key to its boolean, read from in-process snapshots without any table access, and must recover a
  poisoned snapshot lock rather than panic.

### 10.23 Two-factor authentication

Handlers in `bunyip-api/src/handlers/totp.rs`.

- `SPEC-10.23.1` `POST /v1/auth/2fa/setup` must require authentication and must fail with a conflict error carrying
  `ALREADY_ENROLLED_MESSAGE` (status `409`) when 2FA is already enabled, before any password check so an enrolled
  account is not a password oracle.
- `SPEC-10.23.2` `setup_2fa` must fail with a validation error on field `current_password` when the body is absent or
  the password is empty ("Enter your current password"), when the account has no password ("No password set for this
  account"), or when the password does not verify ("Invalid password"); the password must not be trimmed and must be
  verified off the async workers.
- `SPEC-10.23.3` On success `setup_2fa` must start setup and respond `200` with `otpauth_uri`, `secret` and a one-time
  `setup_token`.
- `SPEC-10.23.4` `POST /v1/auth/2fa/setup/resume` must fail with the setup-token error when `setup_token` is absent or
  blank after trimming, and otherwise respond `200` with `otpauth_uri` and `secret` for the existing setup and no
  `setup_token` field.
- `SPEC-10.23.5` `POST /v1/auth/2fa/confirm` must fail with the setup-token error when `setup_token` is absent or blank,
  confirm setup with the token and code through the TOTP service (propagating its error), write a `TwoFactorEnabled`
  audit entry with the actor and client IP, and respond `200` with `{"codes": [...]}`.
- `SPEC-10.23.6` `POST /v1/auth/2fa/verify` must require no session, apply the `LOGIN` rate limit keyed
  `2fa_verify:<ip>` (empty IP when unknown), and verify the challenge token with the JWT service, failing with an
  internal error when the JWT service is not registered and with the token error when the challenge is invalid.
- `SPEC-10.23.7` Before checking the code, `verify_2fa` must read the per-account failure counter (key
  `TWO_FACTOR_KEY_PREFIX` plus user id, cap from the effective `TWO_FACTOR_VERIFY_FAILURES` configuration) without
  incrementing it, and when the count has reached the cap must fail with `RateLimited` carrying `retry_after` even if
  the code is correct.
- `SPEC-10.23.8` `verify_2fa` must strip spaces and surrounding whitespace from the code and verify it as a recovery
  code when it contains `-` or is longer than 6 characters, otherwise as a TOTP code.
- `SPEC-10.23.9` When verification returns false, `verify_2fa` must increment the per-account failure counter, respond
  with a validation error on field `code` ("Invalid verification code"), and a failure of the counter write must be
  logged at `warn` without changing that response.
- `SPEC-10.23.10` On a verified code `verify_2fa` must reset the per-account failure counter (a reset failure logged at
  `warn`, not failing the request) and write a `TwoFactorRecoveryCodeUsed` audit entry for a recovery code or a
  `TwoFactorVerified` entry for a TOTP code, failing with `InvalidCredentials` when the user row is missing.
- `SPEC-10.23.11` `verify_2fa` must complete the login from the challenge token and respond `200` with `AuthResponse`,
  setting the stale-cookie clearing cookies, access-token and refresh-token cookies, a trusted-device cookie only when
  the service returned a trusted token, and the OP session cookie when established.
- `SPEC-10.23.12` The OP session created by `verify_2fa` must carry ACR `urn:bunyip:loa:mfa`, AMR `["pwd", "mfa"]` and
  the `remember` value from the challenge, and the refresh token must be linked to it.
- `SPEC-10.23.13` `DELETE /v1/auth/2fa` must fail with `Forbidden` when the caller's role is `admin`, before any other
  check.
- `SPEC-10.23.14` `disable_2fa` must require the current password (validation error on field `password`: "No password
  set for this account" or "Invalid password") and then a TOTP or recovery code, with validation errors on field
  `totp_code` of "Two-factor code required" when absent or blank and "Invalid verification code" when wrong.
- `SPEC-10.23.15` After the checks `disable_2fa` must disable 2FA, revoke every trusted device of the user, write a
  `TwoFactorDisabled` audit entry, and respond `200` with no data.
- `SPEC-10.23.16` `POST /v1/auth/2fa/recovery-codes` must require the current password (same `password` validation
  errors), regenerate the codes, write a `TwoFactorRecoveryCodesRegenerated` audit entry, and respond `200` with
  `{"codes": [...]}`.
- `SPEC-10.23.17` `POST /v1/auth/2fa/rekey` must require the password and a fresh TOTP or recovery code exactly as
  `SPEC-10.23.14` does, stage a new secret without disabling the active one, write a `TwoFactorRekeyStarted` audit
  entry, and respond `200` with `otpauth_uri` and `secret` and no `setup_token`.
- `SPEC-10.23.18` `POST /v1/auth/2fa/rekey/confirm` must apply the `TWO_FACTOR_VERIFY_FAILURES` rate limit keyed
  `2fa_rekey_confirm:<user id>`, confirm the trimmed code through the TOTP service (propagating its error and leaving
  the active secret untouched on failure), revoke every trusted device, write a `TwoFactorRekeyed` audit entry, and
  respond `200` with `{"codes": [...]}`.
- `SPEC-10.23.19` `GET /v1/auth/2fa/status` must require authentication and respond `200` with `enabled` and
  `recovery_codes_remaining`, where the count is `0` when 2FA is not enabled.

### 10.24 Current user: profile, consent, sessions, trusted devices

Handlers in `bunyip-api/src/handlers/user.rs` under `/v1/users/me`.

- `SPEC-10.24.1` `self_user` must return the caller's `users` row from the copy already read during token verification
  when that copy exists and its id equals the requested id, and otherwise must query by id and fail with `404` ("User")
  when the row does not exist; a row for a different subject must never be served from the copy.
- `SPEC-10.24.2` `GET /v1/users/me` must require authentication and respond `200` with the caller's `UserResponse`.
- `SPEC-10.24.3` `PUT /v1/users/me/profile` must treat each of `first_name`, `last_name` and `phone` as three-state:
  absent leaves the column unchanged; present and empty after trimming clears it to NULL; present and non-empty writes
  the trimmed value.
- `SPEC-10.24.4` `update_current_user_profile` must reject a field longer than 64 characters (counted as characters
  after trimming) with a `400` validation error on that field ("<field> must be 64 characters or fewer") before writing
  anything.
- `SPEC-10.24.5` When `login_location_alerts` is present, `update_current_user_profile` must set it before the profile
  update; when absent it must leave it unchanged.
- `SPEC-10.24.6` The profile update must resolve "leave unchanged" inside the single UPDATE statement and not by writing
  back a previously read value, so a concurrent update of another field is not overwritten.
- `SPEC-10.24.7` After saving, `update_current_user_profile` must attempt the initial tier grant (trigger
  `ProfileCompleted`); a grant failure must be logged at `error` with the user id and must not fail the update.
- `SPEC-10.24.8` When the grant result is `Lifetime`, the handler must create the $0 Stripe subscription using the live
  free price id, and must respond `200` with the updated `UserResponse`.
- `SPEC-10.24.9` The $0 lifetime subscription helper must skip with an `info` log when no free price id is configured;
  otherwise it must re-read the user, create and persist a Stripe customer when the user has none, and create the free
  subscription; each failure (user missing at `warn`, re-read, customer create, customer persist or subscription create
  at `error`) must be logged with the user id and must not propagate.
- `SPEC-10.24.10` `POST /v1/users/me/consents` must fail with `404` ("OIDC provider not configured") when the OIDC
  provider is absent and with a `400` validation error on field `client_id` when the client is unknown or disabled.
- `SPEC-10.24.11` `grant_consent` must persist only the requested scopes that are in the client's `allowed_scopes`; when
  scopes were requested and none is allowed it must fail with a validation error on field `scopes`; when the request has
  no scopes it must succeed as a no-op write.
- `SPEC-10.24.12` `grant_consent` must log at `info` (target `consent_grant`) the user id, client id, requested and
  granted scopes before writing, union the scopes into the stored grant, and on a persistence failure must fail with an
  internal error "consent persist failed: <cause>"; on success it must respond `200` with no data.
- `SPEC-10.24.13` `GET /v1/users/me/oauth-clients/{client_id}/identity` must require authentication, respond `200` with
  only `name` and `logo_uri` of the client, `404` ("OIDC provider not configured") when no provider is configured and
  `404` ("unknown client_id") when the client is not found.
- `SPEC-10.24.14` The session and trusted-device lists must use `page` (1-indexed, default 1, minimum 1) and `per_page`
  (default 20, clamped to 1..=100), computing the offset in 64-bit arithmetic, and respond with the paginated envelope.
- `SPEC-10.24.15` `GET /v1/users/me/sessions` must list the caller's active refresh-token sessions with `id`,
  `device_info` (a readable label derived from the stored User-Agent), `ip_address`, `created_at`, `last_used_at` and
  `current`, where `current` is true only for the session whose hash equals the hash of the presented `refresh_token`
  cookie; the stored token hash must never be returned.
- `SPEC-10.24.16` `DELETE /v1/users/me/sessions/{session_id}` must fail with `404` ("Session") when the session does not
  exist and with `403` when it belongs to another user, and otherwise revoke it and respond `200` with no data.
- `SPEC-10.24.17` `POST /v1/users/me/sessions/revoke-others` must fail with `401` when no `refresh_token` cookie is
  present; otherwise it must revoke every active session except the one matching the cookie and respond `200` with
  `{"revoked": <count>}`.
- `SPEC-10.24.18` When the presented cookie matches no active session, `revoke_other_sessions` must revoke every session
  (keep id nil).
- `SPEC-10.24.19` `GET /v1/users/me/trusted-devices` must read the caller's devices and total in one per-user
  row-level-security transaction filtered by user id and respond with the paginated envelope of `TrustedDeviceInfo`.
- `SPEC-10.24.20` `POST /v1/users/me/trusted-devices/{id}/revoke` must look up and revoke in one per-user
  row-level-security transaction, respond `404` ("Trusted device") both for a missing id and for another user's device,
  and otherwise respond `200` with no data.

### 10.25 Current user: password, email and account deletion

- `SPEC-10.25.1` `PUT /v1/users/me/password` must run the fresh-code gate of `SPEC-10.20.6` to `SPEC-10.20.8` before
  changing anything, then change the password through the auth service with the current password (propagating its
  error), and respond `200` with no data.
- `SPEC-10.25.2` After a password change the handler must send the password-changed email from a background task and a
  send failure must be logged at `error` without failing the response.
- `SPEC-10.25.3` `POST /v1/users/me/email` must validate the new address format, run the fresh-code gate, then request
  the change through the auth service with the optional current password.
- `SPEC-10.25.4` When the service returns a token, `request_email_change` must send the verification email to the new
  address from a background task (failure logged at `error`) and respond `200` with `requires_relogin: false` and the
  message "Verification email sent to your new address. Please check your inbox."
- `SPEC-10.25.5` When the service returns no token (unverified account), `request_email_change` must respond `200` with
  `requires_relogin: true` and the message "Email address updated successfully. Please log in with your new email."
- `SPEC-10.25.6` `POST /v1/users/me/email/confirm` must require no session, confirm the change by token through the auth
  service (propagating its error), send a notification to the old address from a background task (failure logged at
  `error`), and respond `200` with the message "Email address updated successfully. Please log in with your new email."
- `SPEC-10.25.7` `POST /v1/users/me/email/verify` must require authentication, request a verification token through the
  auth service (propagating its error), send the verification email from a background task (failure logged at `error`),
  and respond `200` with the message "Verification email sent. Please check your inbox."
- `SPEC-10.25.8` `POST /v1/users/me/email/verify/confirm` must require no session, confirm by token through the auth
  service, and log at `info` whether the initial tier was granted or is pending the name save.
- `SPEC-10.25.9` When the verification closed the grant gate with tier `Lifetime`, `confirm_email_verification` must
  create the $0 Stripe subscription as in `SPEC-10.24.9`, and must respond `200` with `message` "Email verified
  successfully." and `membership_tier` set to the tier name, or the empty string when the grant is still pending.
- `SPEC-10.25.10` `DELETE /v1/users/me` must verify the current password (validation error on field `password`: "No
  password set for this account" or "Invalid password") and, when the account has 2FA enabled, a TOTP code (validation
  error on field `totp_code`: "Two-factor authentication code is required" when absent or empty, "Invalid two-factor
  authentication code" when wrong), before any change.
- `SPEC-10.25.11` `?purge` with value `1`, `true` or `yes` (after trimming) must hard-delete the row only when the
  deployment is non-production and `BUNYIP_E2E_BOOTSTRAP_ALLOW` is true (`Config::e2e_purge_enabled`); in every other
  case the delete must be a soft delete.
- `SPEC-10.25.12` A hard purge must delete the row, notify the external contact-list sync of the deletion, revoke every
  refresh token and OP session, log at `info`, skip the Stripe, audit and downstream webhook steps, and respond `200`
  with the auth cookies cleared.
- `SPEC-10.25.13` A soft delete must cancel the user's Stripe subscription immediately (second argument `false`) when
  its status is `active` or `past_due`, logging a cancel failure at `error` with the subscription id without aborting
  the delete.
- `SPEC-10.25.14` A soft delete must then mark the user deleted, notify the external contact-list sync of the deletion
  with the email read before the change, revoke all refresh tokens and OP sessions, write a `UserAccountDeleted` audit
  entry with actor, resource and IP, and respond `200` with no data and the auth cookies cleared.
- `SPEC-10.25.15` After a soft delete the handler must publish `AccountDeleted` on the event bus, spawn the downstream
  `account_deleted` fan-out, and spawn the `user.deleted` lifecycle event to the OIDC provider when one is configured,
  none of which may block or fail the response.
- `SPEC-10.25.16` The `account_deleted` fan-out must list active applications, logging an `error` and stopping when the
  list fails; it must skip applications with no or empty `webhook_url`, and for each other application dispatch the
  webhook and record the outcome.
- `SPEC-10.25.17` Recording a dispatch outcome must always write an `AccountDeleteWebhookDispatched` audit entry for the
  application with metadata `user_id`, `app_slug`, `status` (`delivered` or `failed`) and `error`, at severity `info` on
  delivery and `error` on failure.
- `SPEC-10.25.18` On a failed dispatch the recorder must also persist an `account_delete_dispatch_failures` row for the
  user and application slug; a failure of either write must be logged at `error` with the user id and application slug
  and must not stop the other write.

### 10.26 Profile avatar

Handlers in `bunyip-api/src/handlers/avatar.rs`.

- `SPEC-10.26.1` `POST /v1/users/me/avatar` must require authentication and read the first multipart part that carries a
  filename, draining and skipping any part without one, and ignore every part after the first file.
- `SPEC-10.26.2` `upload_avatar` must fail with a `400` validation error on field `avatar` ("Invalid multipart data" or
  "Failed to read field") when the multipart stream cannot be read, and with the shared `Empty` validation error on
  field `avatar` when no file part exists.
- `SPEC-10.26.3` `upload_avatar` must enforce the `ImagePolicy::avatar()` byte limit (2 MiB) while streaming and fail
  with the `TooLarge` validation error on field `avatar` as soon as the received bytes exceed it.
- `SPEC-10.26.4` `upload_avatar` must validate the bytes with the shared image validator, which judges file content and
  not the declared MIME type or filename, and the stored MIME type must be the one the validator returns; each rejection
  must be logged at `warn` with its reason and answered with a validation error on field `avatar`.
- `SPEC-10.26.5` `upload_avatar` must bound the stored image to 512 pixels on its long edge on the blocking thread pool,
  re-encoding in the image's own format with Lanczos3 resampling and keeping the aspect ratio, and must store an image
  already within 512 by 512 byte-for-byte unchanged.
- `SPEC-10.26.6` When the bytes cannot be decoded or re-encoded, `upload_avatar` must fail with a validation error on
  field `avatar` ("Could not read that file as an image.", "Could not read that image: <cause>" or "Could not re-encode
  that image: <cause>"); when the resize task fails to join it must log at `error` and fail with an internal error
  "Could not process that image".
- `SPEC-10.26.7` On success `upload_avatar` must upsert the MIME type and bytes for the user, log at `info` with user
  id, MIME type and size, and respond `200` with the refreshed `UserResponse`.
- `SPEC-10.26.8` `DELETE /v1/users/me/avatar` must be idempotent: it must clear the avatar whether or not one exists,
  log at `info`, and respond `200` with the refreshed `UserResponse`.
- `SPEC-10.26.9` `GET /v1/users/me/avatar` must require authentication, return only the caller's own avatar, and respond
  `404` ("Avatar") when none is stored.
- `SPEC-10.26.10` A served avatar must carry the stored MIME type as `Content-Type`, `Content-Disposition: inline`,
  `Cache-Control: private, max-age=300`, and must be exempt from response compression.

### 10.27 Public branding and the event stream

Handlers in `bunyip-api/src/handlers/branding.rs` and `bunyip-api/src/handlers/events.rs`.

- `SPEC-10.27.1` `GET /v1/events` must require authentication, respond with a `text/event-stream` carrying that user's
  events and global events with keepalive, key the subscription by the token subject, and be exempt from response
  compression so events are not held back.
- `SPEC-10.27.2` `GET /v1/branding` must require no authentication, respond `200` with the cached resolved branding
  values, and must not be in the rate-limit floor's exempt paths.
- `SPEC-10.27.3` `GET /v1/branding/assets/{kind}` must require no authentication, compare `kind` to a fixed allow-list
  before any query, and respond `404` ("Brand asset") for a kind not on the list.
- `SPEC-10.27.4` For an allowed kind, `public_branding_asset` must respond `404` ("Brand asset") when the slot is unset,
  and otherwise stream the stored bytes with the stored MIME type, `Content-Disposition: inline`, `Cache-Control:
  public, max-age=86400`, exempt from response compression.

### 10.28 Billing

Handlers in `bunyip-api/src/handlers/billing.rs`.

- `SPEC-10.28.1` `POST /v1/billing/setup-intent` must require no session, apply the `REGISTRATION` rate-limit budget
  keyed by the client IP (empty when unknown) and fail with `RateLimited` carrying `retry_after` when exceeded.
- `SPEC-10.28.2` `create_setup_intent` must reject an invalid email format and then verify the signup challenge token
  through the auth service, failing with its error when the token is absent or invalid, before any Stripe call.
- `SPEC-10.28.3` `create_setup_intent` must not look up whether the email is registered, so the response cannot reveal
  registration; on success it must respond `200` with `client_secret` and `customer_id`, and a Stripe failure must be
  returned as the mapped Stripe error.
- `SPEC-10.28.4` `GET /v1/billing/invoices` must require authentication and respond `200` with the invoices of the
  caller's Stripe customer, an empty list when the user has no Stripe customer, and the mapped Stripe error when the
  listing fails.
- `SPEC-10.28.5` `GET /v1/billing/invoices/{invoice_id}/download` must require authentication, fail with `404` ("No
  billing account found") when the user has no Stripe customer, and fetch the invoice from Stripe.
- `SPEC-10.28.6` `download_invoice` must respond `404` ("Invoice") when the invoice has no customer id or the customer
  is not the caller's, and `404` ("Invoice PDF") when it has no PDF URL, so a foreign invoice is indistinguishable from
  a missing one.
- `SPEC-10.28.7` For the caller's own invoice, `download_invoice` must respond `302` with `Location` set to the
  Stripe-hosted PDF URL.

### 10.29 Membership

Handlers in `bunyip-api/src/handlers/membership.rs` under `/v1/memberships`.

- `SPEC-10.29.1` `GET /v1/memberships/me` must require authentication and respond `200` with `status`, `price_locked`,
  `locked_price_amount`, `current_period_end`, `cancel_at_period_end` and `grace_period_end`, where the last two period
  fields come from the live Stripe subscription when the user has a Stripe customer.
- `SPEC-10.29.2` `get_membership` must report `current_period_end` as null and `cancel_at_period_end` as false when the
  user has no Stripe customer or the customer has no subscription, and must return the mapped Stripe error (not those
  defaults) when the Stripe lookup fails.
- `SPEC-10.29.3` `POST /v1/memberships/checkout` must lock the user row (`FOR UPDATE`, excluding deleted users) in a
  transaction while resolving the Stripe customer, so concurrent requests cannot create two customers, and must fail
  with `404` ("User") when the row is missing.
- `SPEC-10.29.4` `create_checkout` must fail with `409` ("You already have an active membership") when the user's
  membership status is `active`.
- `SPEC-10.29.5` When `price_id` is absent, `create_checkout` must use the active price whose product is the configured
  `standard_product_id`, and must fail with a validation error on field `price_id` ("No active price configured") when
  no standard product is configured or no active price exists for it; it must not use the first active price of another
  product.
- `SPEC-10.29.6` `create_checkout` must create a Stripe customer and persist its id inside the locked transaction when
  the user has none, commit before creating the session, and pass `eligible_for_trial` (the user's `trial_eligible()`)
  so a returning member gets no second free trial.
- `SPEC-10.29.7` On success `create_checkout` must log at `info` the user id and price id and respond `200` with
  `checkout_url` and `session_id`; Stripe failures must be returned as the mapped Stripe error.
- `SPEC-10.29.8` `POST /v1/memberships/cancel` must fail with an internal error when the JWT service is not registered,
  and with `409` ("No active membership to cancel") when the status is `canceled` or `none`.
- `SPEC-10.29.9` `cancel_membership` must, for a user with a Stripe customer and a subscription, cancel it at period end
  and leave the stored membership status to the webhook; for a user with no Stripe customer it must set the status to
  `canceled` and reset the tier immediately; Stripe errors must be returned as the mapped error.
- `SPEC-10.29.10` After cancelling, `cancel_membership` must re-read the user from the database (not the request-scoped
  row), log at `info`, set a new access-token cookie minted from the updated user, and respond `200` with the message
  "Membership will be canceled at end of billing period" and the user's current `membership_status`.
- `SPEC-10.29.11` `POST /v1/memberships/cancel-now` must apply the same internal-error and `409` preconditions as
  `SPEC-10.29.8`, cancel the Stripe subscription immediately when one exists, set the status to `canceled`, reset the
  tier, re-read the user, set a new access-token cookie, and respond `200` with "Membership canceled immediately" and
  `membership_status` `canceled`.
- `SPEC-10.29.12` `POST /v1/memberships/reactivate` must respond `404` ("No billing account found") without a Stripe
  customer, `404` ("Subscription") without a subscription, `409` ("Membership is not scheduled for cancellation") when
  the subscription is not set to cancel at period end, and otherwise reactivate it and respond `200` with no data.
- `SPEC-10.29.13` `POST /v1/memberships/billing-portal` must respond `404` ("No billing account found") without a Stripe
  customer and otherwise respond `200` with `{"url": <portal session url>}`.
- `SPEC-10.29.14` `GET /v1/memberships/payments` must respond `200` with `id`, `amount` (the amount paid), `currency`,
  `status`, `created` and `invoice_pdf` for each invoice of the user's Stripe customer, an empty list when the user has
  no customer, using `per_page` clamped to 1..=100 as the limit when given and no limit when absent.

### 10.30 Public pricing and admin pricing status

Handlers and cache in `bunyip-api/src/handlers/pricing.rs`.

- `SPEC-10.30.1` `GET /v1/pricing` must require no authentication and respond `200` with `enabled`, a top-level
  `trial_days` (the standard tier's trial length) and `tiers`, each tier carrying `tier`, `amount` (smallest currency
  unit from the mapped Stripe price), `currency`, `interval`, `trial_days`, `available` and `slots_remaining`.
- `SPEC-10.30.2` `resolve` must publish nothing (`enabled: false`, empty `tiers`, `trial_days` still the standard trial
  length) with reason `switch_off` when the pricing switch is off, `no_tier_mapped` when no visible tier has a non-blank
  price id, `stripe_not_configured` when Stripe has no secret key, and `stripe_list_failed` when listing prices fails,
  and must not return an error status for any of them.
- `SPEC-10.30.3` `resolve` must consider tiers in the order Lifetime (price id `free_price_id`, trial 0), Early Adopter
  (its own trial days), Standard (standard trial days), and must skip a tier whose visible flag is false or whose price
  id is absent or blank after trimming, producing no reason for a hidden tier.
- `SPEC-10.30.4` A mapped tier must be published only when its price id is in the Stripe price list, is active, and has
  a `unit_amount`; otherwise it must be omitted with reason `price_unresolved` naming the tier and price id and the
  detail `NotVisible` (naming the app tag), `Archived` or `NoAmount`, and the other tiers must still publish.
- `SPEC-10.30.5` `enabled` must be true only when at least one tier resolved.
- `SPEC-10.30.6` Availability must be: Standard always available with no count; Lifetime and Early Adopter available
  only while their slot cap minus live usage is above zero, with `slots_remaining` equal to that difference floored at
  0.
- `SPEC-10.30.7` Every unpublished reason must be logged exactly once per resolve, at `info` for `switch_off` and
  `no_tier_mapped` and at `warn` (with reason code, tier and price id) for the others.
- `SPEC-10.30.8` Reason codes must be `switch_off`, `no_tier_mapped`, `stripe_not_configured`, `stripe_list_failed` and
  `price_unresolved`, and the public body must never contain reasons, price ids or configuration state.
- `SPEC-10.30.9` `PricingCache` must keep one payload for `PRICING_CACHE_TTL_SECS` (60) seconds, and must resolve at
  most once for concurrent callers past an expiry (single flight): the first holds the gate and loads, the others wait
  and re-check the slot before loading.
- `SPEC-10.30.10` `PricingCache::invalidate` must drop the payload so the next read resolves again, and must be called
  by every admin action that can change the answer; a poisoned cache lock must be recovered, not panic.
- `SPEC-10.30.11` The slot-usage counts must be read inside the cached resolve, so they refresh on the cache TTL; when
  the count query fails the handler must log at `warn` and use `(0, 0)` usage.
- `SPEC-10.30.12` `GET /v1/admin/pricing/status` must require an admin, bypass `PricingCache`, run the same resolve, and
  respond `200` with `published` (enabled and at least one tier), `tiers`, and `reasons` each with `code`, `tier`,
  `price_id` and a rendered admin-facing `message`.

### 10.31 Stripe webhook

Handlers in `bunyip-api/src/handlers/webhook.rs`.

- `SPEC-10.31.1` `POST /v1/webhooks/stripe` must, when no real webhook signing secret is configured (unset or the
  placeholder), log at `error` and fail with an internal error before verifying any signature, so a forged event is
  never trusted.
- `SPEC-10.31.2` `stripe_webhook` must fail with `401` when the `Stripe-Signature` header is absent or not text, with
  the mapped Stripe error when signature verification fails, with a validation error on field `body` ("Invalid UTF-8" or
  "Invalid JSON") when the body is not UTF-8 JSON, and with validation errors on fields `type` ("Missing event type")
  and `id` ("Missing event id") when those are absent.
- `SPEC-10.31.3` Before running a handler, `stripe_webhook` must claim the event id by inserting a `processing` row into
  `stripe_webhook_events`, or by re-claiming an existing row only when its status is not `done` and its `received_at` is
  more than 15 minutes old; a database error on the claim or the status read must fail with an internal error.
- `SPEC-10.31.4` When the claim is not won and the existing row is `done`, `stripe_webhook` must log at `debug`, skip
  the handlers and respond `200` with an empty body; when the row is any other state, including absent, it must log at
  `warn` and respond `409` so Stripe retries.
- `SPEC-10.31.5` After the handler returns `Ok`, `stripe_webhook` must set the event row to `done` (a failure to do so
  must fail the request with an internal error) and respond `200`; after the handler returns an error it must delete the
  event row if still `processing`, then return that error, logging a failed delete at `error` with the event id.
- `SPEC-10.31.6` `stripe_webhook` must dispatch on the event type `checkout.session.completed`,
  `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`,
  `invoice.payment_succeeded` and `invoice.payment_failed`, and treat any other type as handled with a `debug` log and a
  `200`.
- `SPEC-10.31.7` Handlers must read the tier configuration from a snapshot of the live lock and, when the lock is
  poisoned, log at `error` and recover the data rather than fail.
- `SPEC-10.31.8` `membership_status_for` must map `active` and `trialing` to `Active`, `past_due` to `PastDue`, and
  `canceled`, `unpaid`, `incomplete`, `incomplete_expired` and `paused` to `Canceled`; any other status must log at
  `error` with the value and map to `Canceled`, and a subscription grants access only when the mapped status has access.
- `SPEC-10.31.9` `resolve_tier_for_product` must map a product id equal to the configured lifetime, early-adopter or
  standard product id to that tier, checked in that order, and return no tier otherwise, in which case the stored tier
  must be left unchanged.
- `SPEC-10.31.10` `checkout.session.completed` without `metadata.user_id` must log at `warn` and succeed without
  changes; an unparsable `user_id` or a missing session id must fail with a validation error (`user_id` "Invalid UUID",
  `id` "Missing checkout session id").
- `SPEC-10.31.11` The checkout handler must resolve the purchased price from the Stripe API (a failure propagates so
  Stripe retries), set the membership status to `Active`, and lock the price id and amount (cents) on the user only when
  a price resolved and its amount fits in 32 bits; otherwise it must log at `error` and leave the price unlocked.
- `SPEC-10.31.12` When the session metadata has `trial` equal to `true`, the checkout handler must mark the user's trial
  as used and log at `info`; it must not mark it otherwise.
- `SPEC-10.31.13` The checkout handler must send the welcome email and write a `MembershipCreated` audit entry with
  source `stripe_checkout`, and a failure of either must be logged at `error` with the user id without failing the
  event.
- `SPEC-10.31.14` `customer.subscription.created` must fail with a validation error when the subscription `id`,
  `customer` or `status` is missing and with `404` ("User") when no user has that Stripe customer id.
- `SPEC-10.31.15` Created and updated subscription events must, in one transaction, set the membership status from
  `membership_status_for` and, only when the status grants access and the product resolves to a tier, upgrade the tier.
- `SPEC-10.31.16` When the status grants access, created and updated events must re-sync the user's Stripe-sourced
  entitlements; on an updated event whose status does not grant access they must revoke all Stripe-sourced entitlements;
  a created event with a non-access status must not revoke. Admin-sourced entitlements must never be touched.
- `SPEC-10.31.17` Entitlement sync must collect the price ids across all subscription items, resolve each to its mapped
  applications (deduplicated), revoke the user's Stripe-sourced grants, then grant each mapped application with source
  `stripe`; any failure must propagate so Stripe retries and the retry converges.
- `SPEC-10.31.18` `customer.subscription.created` must write a `MembershipCreated` audit entry and
  `customer.subscription.updated` a `MembershipCanceled` entry when `cancel_at_period_end` is true or access is not
  granted, else a `MembershipReactivated` entry; an audit write failure must be logged at `error` without failing the
  event.
- `SPEC-10.31.19` `customer.subscription.updated` must do nothing when no user has the Stripe customer id, and must fail
  with a validation error when `id`, `customer` or `status` is missing.
- `SPEC-10.31.20` `customer.subscription.deleted` must change nothing (logging at `info`) for a user flagged as a
  lifetime member.
- `SPEC-10.31.21` `customer.subscription.deleted` must query Stripe for another active or trialing subscription of the
  same customer; when one exists it must keep the membership active and change nothing, and when the query fails it must
  log at `error` and return the Stripe error so the claim is released and Stripe retries.
- `SPEC-10.31.22` Otherwise `customer.subscription.deleted` must, in one transaction, set the status to `Canceled`,
  reset the tier and clear the grace period, then revoke Stripe-sourced entitlements (failures propagate), send the
  cancellation email and write a `MembershipCanceled` audit entry with source `stripe_subscription_deleted`, logging
  email or audit failures at `error` without failing the event.
- `SPEC-10.31.23` `invoice.payment_succeeded` and `invoice.payment_failed` must fail with a validation error on field
  `customer` when it is missing, and when no user has the customer id must log at `warn` and succeed without changes.
- `SPEC-10.31.24` `invoice.payment_succeeded` must record the amount paid (cents, `0` with an `error` log when it does
  not fit in 32 bits), and when the user had a grace period must, in one transaction, clear it and set the status to
  `Active`.
- `SPEC-10.31.25` `invoice.payment_succeeded` must write a `PaymentSucceeded` audit entry, a `GracePeriodEnded` entry
  when a grace period was cleared, and send the receipt email; each failure must be logged at `error` without failing
  the event.
- `SPEC-10.31.26` `invoice.payment_failed` must write a `PaymentFailed` audit entry at `Warning` severity with the
  amount due (`0` with an `error` log when it does not fit in 32 bits).
- `SPEC-10.31.27` When the user has no grace period, `invoice.payment_failed` must, in one transaction, set a grace
  period of 30 days from now and set the status to `GracePeriod`, write a `GracePeriodStarted` audit entry at `Warning`
  severity, and send the payment-failed email stating 30 days; an existing grace period must not be restarted.

### 10.32 Member and admin downloads

Handlers in `bunyip-api/src/handlers/download.rs`.

- `SPEC-10.32.1` Every asset URL in a download response must be `/v1/applications/{slug}/downloads/{asset}` with the
  slug and asset name percent-encoded, alongside `asset_name`, `size_bytes` and `content_type`.
- `SPEC-10.32.2` `GET /v1/applications/{slug}/downloads` must require a member, fail with `404` ("Downloads") when the
  release cache is disabled and with `404` ("Application") for an unknown or inactive slug.
- `SPEC-10.32.3` `list_app_downloads` must respond `200` with `release_tag: null` and no assets, not an error, when the
  caller is not entitled to a restricted product or the application has no complete download configuration; a database
  error while deciding entitlement must propagate.
- `SPEC-10.32.4` Otherwise `list_app_downloads` must respond `200` with the current release version as `release_tag` and
  the release's assets; a release lookup failure must be logged at `warn` and answered with `AppError::upstream`
  ("Forgejo upstream error", the helper being named for status `502`).
- `SPEC-10.32.5` `GET /v1/downloads` must require a member and fail with `404` ("Downloads") only when both the release
  cache and the OCI distribution are disabled.
- `SPEC-10.32.6` `list_all_downloads` must return `{"groups": [...]}` with one group per active application in the
  application list's order, and must compute groups concurrently.
- `SPEC-10.32.7` `list_all_downloads` must read an administrator's access as unrestricted without querying entitlements,
  and for other callers must read the caller's active entitlement application ids in one query under per-user row-level
  security.
- `SPEC-10.32.8` A group must be omitted when the caller lacks access and the application has no documentation; when the
  caller lacks access but the application has documentation, the group must be a locked docs-only group with
  `has_access` false, no `oci` and no assets.
- `SPEC-10.32.9` For a caller with access, a group must carry the OCI pull reference when OCI distribution is enabled
  and the application has one, and the release tag and assets when the release cache is enabled and the application has
  a complete download configuration; a group with access, no assets, no OCI reference and no documentation must be
  omitted.
- `SPEC-10.32.10` When the release fetch for one application fails, `list_all_downloads` must log at `warn` with the
  slug and error and return that group with an empty release tag and no assets, without failing the response.
- `SPEC-10.32.11` `GET /v1/applications/{slug}/downloads/{asset_name}` and `GET
  /v1/applications/{slug}/downloads/{version}/{asset_name}` must require a member and share one implementation; they
  must fail with `404` ("Downloads") when the release cache or the download cache is disabled, `404` ("Application") for
  an unknown slug, and `404` ("Asset") when the application has no download configuration.
- `SPEC-10.32.12` The versioned route must serve only the pinned release tag or a version recorded as pullable for the
  application and must answer `404` ("Asset") for any other tag; the default route must serve the pinned release and
  record the pin in the version history best-effort, logging a failure at `warn` without failing the download.
- `SPEC-10.32.13` A caller who is neither an administrator nor entitled to a restricted application must be refused with
  `404` ("Asset"), never `403`, after a `DownloadDeniedEntitlement` audit entry and before the rate limit is consumed.
- `SPEC-10.32.14` The download limiter must be acquired before any upstream call; when the concurrency cap denies it the
  handler must write a `DownloadDeniedRateLimit` audit entry with reason `concurrency` and fail with `RateLimited`
  (`download_concurrency_limit`, no retry-after), and when the daily cap denies it must write the entry with reason
  `daily_cap` and `reset_in_secs` and fail with `RateLimited` (`download_daily_limit`) carrying `reset_in_secs`.
- `SPEC-10.32.15` When the limiter admits the request, the handler must write a `DownloadRequested` audit entry with
  actor, application, IP, slug and asset name, fail with `404` ("Asset") when the release has no asset of that name, and
  key the cache row by the configured version, not by the version Forgejo returns.
- `SPEC-10.32.16` A cache fetch failure must be classified by the download engine: `NotFound` answers `404` ("Asset")
  with no audit entry; `Upstream` logs at `warn` and answers an upstream error ("Download upstream failed"); `Local`
  logs at `error` and answers an internal error ("Download failed"); both of the latter must write a
  `DownloadFailedUpstream` audit entry with the error text before answering.
- `SPEC-10.32.17` When the cached file cannot be opened the handler must log at `error` and fail with an internal error
  ("Cached file missing").
- `SPEC-10.32.18` A successful download must stream the file with the stored `Content-Type`, a `Content-Length` equal to
  the stored size, `Content-Disposition: attachment; filename="<asset name>"`, exempt from response compression, and the
  concurrency slot must stay held until the stream ends or is dropped.
- `SPEC-10.32.19` The stream must write exactly one terminal audit entry: `DownloadCompleted` (with `size_bytes`) on
  clean end of file, or `DownloadFailedUpstream` (with the error) on a mid-stream read error, and a failure of that
  audit write must be logged at `warn` without altering the stream.
- `SPEC-10.32.20` `POST /v1/admin/applications/{slug}/downloads/refresh` must require an admin, fail with `404`
  ("Downloads") when the release cache is disabled, `404` ("Application") for an unknown slug (inactive included), and a
  validation error on field `application` ("Application is not configured for downloads") without a download
  configuration.
- `SPEC-10.32.21` `admin_refresh_release` must invalidate the cached release, fetch it again, and respond `200` with the
  release tag and assets, or log at `warn` and answer an upstream error ("Forgejo upstream error") when the fetch fails.

### 10.33 Feedback intake

`POST /v1/feedback` in `bunyip-api/src/handlers/feedback.rs`.

- `SPEC-10.33.1` `submit_feedback` must read a multipart body whose text fields are `name`, `email`, `subject`, `tags[]`
  or `tags` (repeatable), `message`, `page_path` and the honeypot `website`, and whose file fields are attachments; it
  must ignore unknown text fields and fail with a validation error on field `attachment` ("Invalid multipart data" or
  "Failed to read field") when the stream cannot be read.
- `SPEC-10.33.2` Every multipart field, file or not, must be capped while streaming: a field over 5 MiB must fail with a
  validation error on its own field name ("Field exceeds 5 MB limit", on `attachment` for a file), and the cumulative
  size of all fields over 5 MiB must fail with a validation error on `attachment` ("Request exceeds 5 MB total limit").
- `SPEC-10.33.3` A request carrying a 21st `tags[]`/`tags` part must fail before reading that part with a validation
  error on field `tags` ("Maximum 20 tags allowed").
- `SPEC-10.33.4` A request with a 4th file part must fail with a validation error on field `attachment` ("Maximum 3
  attachments allowed").
- `SPEC-10.33.5` An attachment filename must be reduced to its base name and rejected with a validation error on field
  `attachment` when empty, longer than 200 bytes ("Filename exceeds 200 characters") or containing a control character
  ("Filename contains control characters").
- `SPEC-10.33.6` An attachment's stored MIME type must come from sniffing its bytes, never the declared type; a sniffed
  type outside `image/png`, `image/jpeg`, `image/webp`, `image/gif` and `text/plain` must fail with a validation error
  on `attachment` ("File content is not an allowed type") and be logged at `warn`.
- `SPEC-10.33.7` When no signature is recognised, an attachment must be accepted only if the declared type is
  `text/plain` and the bytes are valid UTF-8, with validation errors on `attachment` ("Could not verify file type from
  content" at `warn`, or "text/plain attachment is not valid UTF-8") otherwise.
- `SPEC-10.33.8` An image attachment's dimensions must be read from the header only (no pixel decoding) and rejected
  with a validation error on `attachment` ("Could not parse image dimensions" or "Image dimensions exceed limit", each
  logged at `warn`) when unreadable or when width or height exceeds 10000 pixels.
- `SPEC-10.33.9` Tags must be trimmed, blanks dropped, matched case-insensitively and mapped to `Bug` (`bug`, `bugs`),
  `Feature` (`feature`, `features`, `missing feature`, `missing features`), `Flow` (`flow`, `rough edge`, `rough edges`)
  or `Idea` (`idea`, `ideas`), deduplicated in first-seen order; any other tag must fail with a validation error on
  field `tags` ("Unsupported feedback tag: <tag>").
- `SPEC-10.33.10` Text fields must be trimmed with blank treated as absent; `name` must be at most 100 characters,
  `subject` at most 200, `page_path` at most 255 and must start with `/` ("Page path must be a relative path"),
  `message` is required ("Message is required") and at most 5000, `email` must pass email validation; each violation
  must be a validation error on its field.
- `SPEC-10.33.11` A submission must be spam when the honeypot `website` field is non-blank after trimming or the
  composite spam classifier returns a reason; the classifier must run even for a honeypot hit and must never clear a
  honeypot flag.
- `SPEC-10.33.12` The classifier must receive the sender email, message, tags, no IP ASN name, the registrable word and
  apex host derived from `config.email.base_url`, and the MX outcome of the sender's domain, which must be `Unknown`
  when no email was submitted or no domain can be extracted.
- `SPEC-10.33.13` The deployment registrable word must be the second-to-last dot-separated segment of the base URL host
  and the apex host its last two segments, both lowercased, with scheme, path and port stripped; both must be absent for
  an empty URL, an empty host or a single-segment host.
- `SPEC-10.33.14` The per-IP `FEEDBACK_SUBMIT` rate limit (key the client IP, `unknown` when unresolved) must be charged
  only for non-spam submissions and only after multipart parsing and validation succeed; spam submissions must still be
  stored and audited.
- `SPEC-10.33.15` The submission must be stored with the submitter IP and a user agent trimmed, blank treated as absent
  and cut to 256 characters, together with its attachments, and when the classifier returned a reason the reason must be
  stored for the row.
- `SPEC-10.33.16` The submission must write a `FeedbackSubmitted` audit entry with the client IP and metadata `status`,
  `has_email`, `page_path`, `ip` and `user_agent`.
- `SPEC-10.33.17` For a non-spam row only, the handler must create a `NewFeedback` admin notification and send the admin
  notification email from a background task, logging a send failure at `error` with the feedback id; for a spam row
  neither must happen.
- `SPEC-10.33.18` On success the handler must respond `201` with `{"id": <feedback id>, "message": "Feedback
  submitted"}`.
- `SPEC-10.33.19` `GET /v1/admin/feedback/{feedback_id}/attachments/{attachment_id}` must require an admin and respond
  `404` ("Attachment") when the attachment does not exist or belongs to a different feedback row.
- `SPEC-10.33.20` A served attachment must carry the stored MIME type, `Content-Disposition: inline` with the filename
  quoted and its double quotes escaped, and be exempt from response compression.

### 10.34 Feedback administration

Admin handlers in `bunyip-api/src/handlers/feedback.rs`; all require an admin session.

- `SPEC-10.34.1` `GET /v1/admin/feedback` must use `page` (default 1, minimum 1) and `per_page` (default 20, maximum
  100) and respond with the paginated admin summaries.
- `SPEC-10.34.2` `list_feedback` must accept `bucket` only as `active`, `closed` or `spam`, `tag` only as `Bug`,
  `Feature`, `Flow` or `Idea` (blank ignored), and `q` of at most 128 bytes after trimming, each violation being a
  validation error on its parameter, and must pass `tag`, `has_attachment`, `has_response` and the trimmed `q` as
  filters.
- `SPEC-10.34.3` `GET /v1/admin/feedback/new-count` must respond `200` with `{"count": n}` of rows with status `new`
  that are not spam, and a database failure must propagate as an error status, never as a zero count.
- `SPEC-10.34.4` `GET /v1/admin/feedback/{id}` must respond `404` ("Feedback") when absent and otherwise the admin
  detail with its attachments and a `spam_reason` field that is the stored classifier reason or null.
- `SPEC-10.34.5` `POST /v1/admin/feedback/{id}/respond` must require a verified admin, respond `404` ("Feedback") when
  absent, trim the response, reject an empty one ("Response is required") or one over 5000 characters, and reject a
  `status` that does not parse ("Invalid feedback status"), defaulting the status to `Responded` when absent.
- `SPEC-10.34.6` `respond_to_feedback` must store the response with the status and responding admin id, write a
  `FeedbackResponded` audit entry with `previous_status` and `new_status`, and when the row has an email address send
  the response email inline; a send failure must be logged at `error` with the feedback id and must not fail the
  request.
- `SPEC-10.34.7` `PUT` status update must respond `404` ("Feedback") when absent, reject an unparsable status ("Invalid
  feedback status"), update the status, and write a `FeedbackResponded` audit entry with `previous_status` and
  `new_status`.
- `SPEC-10.34.8` `DELETE /v1/admin/feedback/{id}` must respond `404` ("Feedback") when no row was deleted, otherwise
  write a `FeedbackDeleted` audit entry and respond `200` with an empty object.
- `SPEC-10.34.9` `mark-spam` and `unmark-spam` must set `is_spam` to true or false respectively, write a
  `FeedbackMarkedSpam` or `FeedbackUnmarkedSpam` audit entry, and respond `200` with the admin detail and attachments.
- `SPEC-10.34.10` `POST /v1/admin/feedback/{id}/archive` must move the row to the archive, respond `404` ("Feedback")
  when no row matched, otherwise write a `FeedbackArchived` audit entry and respond `200` with an empty object.
- `SPEC-10.34.11` `GET` of the archive list must use the same `page` and `per_page` rules as `SPEC-10.34.1`; `POST
  /v1/admin/feedback/archive/{archive_id}/restore` must restore the row, write a `FeedbackRestored` audit entry and
  respond `200` with the restored admin detail and attachments.
- `SPEC-10.34.12` `GET` export must respond `200` as `text/csv; charset=utf-8` with `Content-Disposition: attachment;
  filename="feedback.csv"` and an `x-request-id` header, a header row
  `id,name,email,subject,tags,message,page_path,status,admin_response,responded_at,is_spam,created_at,updated_at`, and
  one CRLF-terminated row per feedback row.
- `SPEC-10.34.13` In the export a field containing a comma, a double quote or a newline must be wrapped in double quotes
  with inner quotes doubled, tags must be joined with `|`, and timestamps must be RFC 3339.

### 10.35 Feedback spam gate: classifier and MX lookup

Classifier in `bunyip-api/src/handlers/feedback_classifier.rs` and resolver in `bunyip-api/src/handlers/mx_check.rs`.

- `SPEC-10.35.1` `classify_feedback_spam` must evaluate four signals in this order and return the reason of the first
  that fires: sender-domain mimicry, sender domain with no MX records, URL plus at least three tags, hosting-range IP;
  it must return `None` when none fires, and must hold no state and perform no I/O.
- `SPEC-10.35.2` The mimicry signal must not fire without a sender email, a non-blank registrable word and a non-blank
  apex host; it must not fire when the sender domain equals the apex or ends with `.<apex>`; it must fire when any
  dot-separated segment of the lowercased sender domain contains the lowercased registrable word, with the reason
  "sender domain <domain> mimics the recipient's registrable word <word>".
- `SPEC-10.35.3` The no-MX signal must fire only when a sender email with a non-empty domain was submitted and the MX
  outcome is `NoMx`, with the reason "sender domain <domain> has no MX records; cannot receive mail"; `HasMx` and
  `Unknown` must never fire it.
- `SPEC-10.35.4` The URL signal must fire only when the tag count is at least 3 and the case-insensitive message
  contains `http://` or `https://` followed by a non-whitespace character, scanning every marker occurrence, with the
  reason "message carries a URL and <n> tags; SEO fan-out shape".
- `SPEC-10.35.5` The hosting signal must fire only when a non-blank ASN name is supplied and its lowercase form contains
  one of `interserver`, `ovh`, `linode`, `digitalocean`, `amazon`, `aws`, `hetzner`, `google cloud`, `microsoft azure`,
  `oracle cloud`, `vultr`, `contabo` (first match in that order), with the reason "submitted from hosting-range IP (ASN
  names <pattern>)".
- `SPEC-10.35.6` `domain_of` must return the lowercased, trimmed text after the last `@`, and `None` when there is no
  `@`, the domain is empty, or it is longer than 253 bytes.
- `SPEC-10.35.7` `MxResolver::lookup` must return `HasMx` when the MX answer set is non-empty, `NoMx` when it resolves
  with no MX answers or the resolver reports no records found (NXDOMAIN), and `Unknown` for any other resolver error and
  for a lookup exceeding 2 seconds, so that a DNS outage never flags feedback.
- `SPEC-10.35.8` The production resolver must cache every outcome per lowercase domain for one hour and serve a cached
  outcome without a new lookup while it is younger than that.
- `SPEC-10.35.9` The production resolver must read the system resolver configuration and use the public fallback
  configuration only when reading it fails.


### 10.36 Support tickets

Admin handlers in `bunyip-api/src/handlers/support.rs`; all require an admin session.

- `SPEC-10.36.1` `GET /v1/admin/support/tickets` must use `page` (default 1, minimum 1) and `per_page` (default 20,
  maximum 100), compute the offset in 64-bit arithmetic with saturating multiplication and a floor of 0, and respond
  with the paginated tickets, most recent activity first, and the total ticket count.
- `SPEC-10.36.2` `GET /v1/admin/support/tickets/{id}` must respond `404` ("Support ticket not found") for an unknown id
  and otherwise `{"ticket": ..., "messages": [...]}` with the full thread, oldest first.
- `SPEC-10.36.3` `POST /v1/admin/support/tickets/{id}/reply` must fail with a validation error on field `message` ("A
  reply message is required") when the trimmed message is empty, and with `404` ("Support ticket not found") for an
  unknown id, before sending anything.
- `SPEC-10.36.4` The reply must go to the ticket's requester email with the subject unchanged when it already starts
  with `re:` (case-insensitive) and otherwise prefixed `Re: `.
- `SPEC-10.36.5` The reply must thread onto the latest message: `In-Reply-To` is that message's id in angle brackets,
  and `References` is its stored references plus its own id, each in angle brackets and space separated, omitted when
  empty.
- `SPEC-10.36.6` After the mail is sent the handler must record an outbound message (sender from
  `config.email.from_email`, recipient the requester, the trimmed text, the sent message id, bare ids without angle
  brackets for `in_reply_to` and references) and set the ticket status to `pending`; a send failure must propagate as an
  error with nothing recorded.
- `SPEC-10.36.7` On success the reply must respond `200` with `{"status": "sent"}`.

### 10.37 Host secrets and host configuration routes

Handlers in `bunyip-api/src/handlers/host_auth.rs`, `host_secrets.rs` and `host_config.rs`, serving values to a
registered calling app over HTTP Basic machine-client credentials.

- `SPEC-10.37.1` Each host route must authenticate in this order: failed-authentication cap for the client IP, Basic
  credentials, client lookup, secret verification, the route's read throughput cap, then the key's entitlement, then
  whether the key is served, then whether a value is set, so an unauthenticated caller learns nothing about which keys
  exist and an authenticated one learns nothing about keys it may not read.
- `SPEC-10.37.2` When the failed-authentication count for the client IP has reached the effective cap (read without
  incrementing, compared with `>=`), the route must log at `error` (category `rate_limit`, client, action, route) and
  fail with `RateLimited` whose `retry_after` is the effective window seconds, falling back to the compiled window with
  a `warn` log when the effective configuration cannot be read.
- `SPEC-10.37.3` A request without HTTP Basic credentials must be refused as an invalid client ("HTTP Basic client
  credentials are required"), an unknown or disabled client or a failed secret verification must return the error of the
  machine-client check, and each of the three must count one failed authentication against the client IP and be logged
  at `warn` with the route label (and the client id where known).
- `SPEC-10.37.4` A failure to record a failed authentication must be logged at `error` with the route label and must not
  change the refusal returned; when the client IP is unknown nothing is recorded.
- `SPEC-10.37.5` After authentication the route must charge the route's read cap keyed by the client id and fail with
  `RateLimited` when exceeded; the secrets route must use `HOST_SECRET_READ` and `HOST_SECRET_AUTH_FAILURES` and the
  config route `HOST_CONFIG_READ` and `HOST_CONFIG_AUTH_FAILURES`, so one route's burst never spends the other's budget.
- `SPEC-10.37.6` `GET /v1/host/secrets/{key}` must answer `403` for a key absent from the registration's
  `allowed_secret_keys`, and `GET /v1/host/config/{key}` must answer `403` for a key absent from `allowed_config_keys`,
  before looking the key up, with the same answer whether or not the key exists, and log at `warn` the client id, name,
  key and route; neither route may read the other's allow-list.
- `SPEC-10.37.7` An allow-listed key the build does not serve must log at `error` with the client and key and answer
  `404` ("<key> is not a host secret this deployment serves" or "<key> is not a host configuration value this deployment
  serves"); a served secret with no value must answer `404` ("<key> is not set; an administrator sets it under Host
  configuration") and a served configuration key with no value `404` ("<key> has no value on this deployment; an
  operator sets it in bunyip's own configuration").
- `SPEC-10.37.8` A secret value is resolved with the database pool and the application encryption key set and a
  resolution failure must propagate as an error; a configuration value is resolved from the loaded configuration.
- `SPEC-10.37.9` On success each route must log at `info` the client id, client name and key and must respond `200` with
  `{"key": <key>, "value": <value>}`; no log line, error or other response may contain a value.

### 10.38 Mailer relay

Handlers in `bunyip-api/src/handlers/mailer.rs`.

- `SPEC-10.38.1` `POST /v1/mailer/send` must read a JSON body with required `to`, `subject`, `text` and optional `html`,
  and reject a body missing a required field with a `400` deserialization error.
- `SPEC-10.38.2` `relay_send` must authenticate the caller in the order and with the failure handling of `SPEC-10.37.2`
  to `SPEC-10.37.4`, using the `MAILER_AUTH_FAILURES` budget keyed by client IP, taking `retry_after` from the stored
  window (the full configured window with a `warn` log when it cannot be read), and log the refusal lines with a "mailer
  relay" prefix.
- `SPEC-10.38.3` After authentication `relay_send` must charge `MAILER_SEND` keyed by the client id, validate the
  message (a validation error naming the failing field and message), and relay it attributed to the client's name; relay
  errors must propagate.
- `SPEC-10.38.4` `relay_send` must respond `200` with `{"status": "sent", "message_id": ...}` for a delivered message
  and `{"status": "suppressed"}` without a `message_id` for a suppressed recipient, never reporting a suppressed message
  as sent.
- `SPEC-10.38.5` `POST /v1/mailer/webhooks/feedback` must, when `MAILER_WEBHOOK_SECRET` is unset, log at `error` and
  fail with an internal error before reading the body, and must fail with `401` when the signature header is absent.
- `SPEC-10.38.6` `relay_feedback_webhook` must verify the signature over the raw body and ingest the bounce or complaint
  event through the suppression list, failing with the ingest error and writing nothing for an unverified or malformed
  event.
- `SPEC-10.38.7` For an accepted event the handler must log at `warn` the suppressed address and reason and respond
  `200` with `{"status": "recorded", "reason": <reason>}`.

### 10.39 System configuration

Admin handlers in `bunyip-api/src/handlers/system_config.rs`; both require an admin session.

- `SPEC-10.39.1` `GET /v1/admin/system-config` must respond `200` with `path` (the file-layer directory),
  `login_approval_enabled`, `signup_bot_guard_enabled`, `country_allow` and `country_deny` (comma-and-space joined), and
  `provenance`, all resolved from one configuration stack read once.
- `SPEC-10.39.2` `provenance` must contain one entry per system setting key with `key`, `serving` (the serving provider
  or null for the built-in default), `condition` (`use`, `default`, `overridden` or `shadowed`) and `providers` (every
  holding provider, highest priority first), and must never contain a configuration value.
- `SPEC-10.39.3` `PUT /v1/admin/system-config` must accept only `login_approval_enabled`, `signup_bot_guard_enabled`,
  `country_allow` and `country_deny`, each optional; any other field, including `cors_origin`, `web_origin` and
  `cookie_domain`, must be ignored and never persisted.
- `SPEC-10.39.4` A country list must be split on commas and whitespace, each code must be exactly two ASCII letters and
  be uppercased, blanks skipped; an invalid code must fail with a validation error on field `country` ("'<code>' is not
  a 2-letter ISO country code") before anything is written.
- `SPEC-10.39.5` The save must hold the process-wide save lock across reading the current settings, merging the
  submitted fields (absent fields keep their current values) and writing, so overlapping saves cannot revert each
  other's fields; a write failure must fail with an internal error naming the directory and cause.
- `SPEC-10.39.6` After the write the handler must write one `SystemConfigUpdated` audit entry per changed setting with
  the actor, old and new values and metadata `key`, `previous`, `new` (keys `LOGIN_APPROVAL_ENABLED`,
  `SIGNUP_BOT_GUARD_ENABLED`, `COUNTRY_ALLOW`, `COUNTRY_DENY`), log one `info` line naming the changed keys, and write
  nothing when no setting changed; an audit write failure must fail the request.
- `SPEC-10.39.7` The `PUT` response must be `200` with the same body as `SPEC-10.39.1`, built from the saved settings
  and a configuration stack loaded after the write.

## 11. Web application core (root, api client, routes, skin, views, assets, image build)

### 11.1 Process entry point and router (`bunyip-web/src/main.rs`)

Refines `SPEC-2.3.1` to `SPEC-2.3.4`.

- `SPEC-11.1.1` On startup `main` must run, in this order: initialise tracing; build `Config::from_env`; build the `Api`
  client from `api_url`; install the asset version, the SSE origin, the community flag and the default share image
  into `views::layout`; await `branding::load_at_startup`; spawn `branding::spawn_refresh`; await
  `feature_flags::load_at_startup`; spawn `feature_flags::spawn_refresh`; spawn `server_status::spawn_recovery_poll`
  with `api_url`; build `AppState` and the router; bind the listener; serve. The listener must not be bound before
  both startup fetches have returned or timed out (`SPEC-2.3.1`).
- `SPEC-11.1.2` Tracing must use `EnvFilter::try_from_default_env()` and must fall back to the filter `info` when the
  environment filter variable is unset or unparseable.
- `SPEC-11.1.3` The SSE subscriber origin installed into `views::layout` must be `Config::api_public_origin` (the
  browser-facing origin), not `Config::api_url` (the internal server-to-server origin); the asset version must be the
  compile-time `ASSET_VERSION` value; the community flag must be `Config::community_enabled()`; the default share
  image must be `Config::default_share_image()`.
- `SPEC-11.1.4` `AppState` must be built with four `TtlCache` instances, keyed by upstream path and decoded type:
  `/v1/pricing` (`PricingResponse`, `PRICING_CACHE_TTL_SECS`), `/v1/applications` (`Vec<Application>`,
  `APPLICATIONS_CACHE_TTL_SECS`), `/v1/auth/setup/status` (`SetupStatus`, `SETUP_STATUS_CACHE_TTL_SECS`) and
  `/v1/application-docs` (`Vec<DocumentedApp>`, `DOCUMENTED_APPS_CACHE_TTL_SECS`).
- `SPEC-11.1.5` The router must register these public `GET` routes: `/healthz`, `/`, `/pricing`, `/our-story`,
  `/roadmap`, `/terms`, `/privacy`, `/docs`, `/docs/:slug`, `/apps/:slug/docs` and `/apps/:slug/docs/:doc_slug`.
- `SPEC-11.1.6` The `/feedback` route must accept `GET` and `POST`, and must raise the request body limit for that
  route only to `content::FEEDBACK_BODY_LIMIT_BYTES`; every route without an explicit limit keeps axum's default body
  limit.
- `SPEC-11.1.7` The router must register these authentication routes: `/login` (`GET`, `POST`), `/login/2fa` (`GET`,
  `POST`), `/login/approval` (`GET`, `POST`), `/logout` (`POST` only), `/register` (`GET`, `POST`), `/magic-link`
  (`GET`, `POST`), `/password-reset` (`GET`, `POST`), `/password-reset/confirm` (`GET`, `POST`), `/invite/accept`
  (`GET`, `POST`), `/settings/confirm-email` (`GET`), `/settings/verify-email` (`GET`) and `/onboarding` (`GET`,
  `POST`).
- `SPEC-11.1.8` The router must register these signed-in application routes: `GET` `/dashboard`, `/applications`,
  `/downloads`, `/downloads/:slug/:asset`, `/billing`, `/checkout/success`, `/membership-required`, `/membership`,
  `/community`; and `POST` `/membership/subscribe`, `/membership/cancel`, `/membership/cancel-now`,
  `/membership/reactivate`, `/membership/billing-portal`.
- `SPEC-11.1.9` The router must register these settings routes: `GET` `/settings`; `POST` `/settings/profile`,
  `/settings/email`, `/settings/password`, `/settings/2fa/disable`, `/settings/account/delete`,
  `/settings/verify-email/resend`, `/settings/sessions/revoke-others`, `/settings/sessions/:id/revoke`,
  `/settings/trusted-devices/:id/revoke`, `/settings/2fa/setup/confirm`, `/settings/2fa/rekey/confirm`; and `GET` plus
  `POST` for each of `/settings/2fa/setup`, `/settings/2fa/recovery-codes` and `/settings/2fa/rekey`.
- `SPEC-11.1.10` `POST /settings/avatar` must carry a route-level body limit of 3 MiB (3 * 1024 * 1024 bytes). The
  router must also register `POST /settings/avatar/remove`, `GET /me/avatar`, `GET /brand/:kind`, `GET /favicon.ico`
  and `GET`/`POST` `/oauth2/consent`.
- `SPEC-11.1.11` `GET /organizations` must be registered unconditionally; the feature gate must be applied inside the
  handler, so switching the feature on or off needs no router rebuild.
- `SPEC-11.1.12` The admin route table must be added by merging `routes::admin::routes()` into the
  router (`SPEC-11.19.1`).
- `SPEC-11.1.13` `/assets` must be served by `ServeDir` rooted at the `assets` directory relative to the process
  working directory, and each response lacking a `Cache-Control` header must receive
  `Cache-Control: public, max-age=31536000, immutable`.
- `SPEC-11.1.14` Any request that matches no registered route or nested service must be answered by
  `skin::public::not_found` (a branded page carrying a real 404 status), not by axum's default 404 (`SPEC-2.3.4`).
- `SPEC-11.1.15` The router must apply layers so that, outermost first, a request meets: compression, the CSP header
  layer, client-IP resolution, the CSRF origin check, the unknown-host gate (`SPEC-2.3.4`). Because each layer wraps
  the fallback too, the 404 fallback must also be compressed, CSP-stamped and CSRF-checked.
- `SPEC-11.1.16` The CSRF layer must be `csrf::enforce_origin_with` with an empty exemption list, so no path is exempt
  from the Origin/Referer check.
- `SPEC-11.1.17` The client-IP layer must be `client_ip::forward_client_ip` with state `Arc` of
  `Config::trusted_proxies`, and the server must be started with `into_make_service_with_connect_info::<SocketAddr>()`
  so the socket peer is available to that layer (`SPEC-2.3.3`).
- `SPEC-11.1.18` Response compression must use `DefaultPredicate` and additionally must not compress a response whose
  content type is `application/octet-stream`, `application/gzip`, `application/zip`, `application/x-tar`,
  `application/x-xz`, or starts with `font/`; text content types (HTML, CSS, JavaScript, JSON) must still be
  compressed.
- `SPEC-11.1.19` The process must bind a single `tokio::net::TcpListener` to `Config::bind_addr` after the router is
  built (`SPEC-2.3.2`). A bind failure must abort the process by panic with the message `bind`, and a failure of
  `axum::serve` must abort it by panic with the message `serve`.
- `SPEC-11.1.20` After binding, the process must print a startup banner to standard output with the line
  `bunyip-web` plus a brand suffix, the line `Web listening on  http://<bind_addr>` and the line
  `API backend       <api_url>`, and must log `bunyip-web listening on <bind_addr>` at info level. The brand suffix
  must be `  (<name> - <tagline>)` when both are set (the separator in code is a middle dot, U+00B7), `  (<name>)`
  or `  (<tagline>)` when only one is set, and empty
  when the branding record has neither; a compiled-in name must never be substituted.

### 11.2 Application state and response builders (`bunyip-web/src/web.rs`)

- `SPEC-11.2.1` `AppState` must hold the `Api` client, the shared `Config`, and the four TTL caches of `SPEC-11.1.4`,
  and must be cheaply cloneable per request.
- `SPEC-11.2.2` `AppState::pricing` must read through the pricing cache; when the cache has never read a value and the
  fetch fails it must return `PricingResponse::default()` (unpublished, no tiers) so nav and footer hide every link to
  `/pricing`; the failure itself is logged by the cache (`SPEC-11.8.4`).
- `SPEC-11.2.3` `AppState::public_applications` must fetch `/v1/applications` without a session cookie and must share
  one cache slot across all anonymous visitors; on a cold failure it must return an empty list. It must not be used
  by any surface a signed-in visitor can reach: `/dashboard`, `/applications` and the landing page keep a per-request
  cookie-bearing fetch.
- `SPEC-11.2.4` `AppState::documented_apps` must return the cache's `Err(ApiError)` on a cold failure so the `/docs`
  hub can render "could not load" with the error message and request id; it must never turn the failure into an empty
  list.
- `SPEC-11.2.5` `AppState::setup_status` must return `None` only when the cache has never read the status, and
  otherwise the cached value by clone.
- `SPEC-11.2.6` `AppState::stripe_enabled` must return the cached `stripe_enabled` flag when the status is known, and
  `true` when it is not; the `true` fallback must be preceded by a `warn` log naming the endpoint
  `/v1/auth/setup/status`.
- `SPEC-11.2.7` Source files that render the public chrome (`handlers/mod.rs`, `handlers/auth_pages.rs`,
  `handlers/dashboard.rs`, `skin/content.rs`, `skin/public.rs`) must not call `auth_api::setup_status(`,
  `api::auth::setup_status(` or `calls::pricing(` directly, and must not call `calls::applications(` directly except
  `handlers/dashboard.rs` and `skin/public.rs`; a unit test must fail the build on a violation.
- `SPEC-11.2.8` The handlers `skin/public.rs::landing` and `handlers/dashboard.rs::{dashboard, applications,
  membership, settings}` must issue their independent upstream fetches concurrently with `tokio::join!` and must not
  use `tokio::try_join!`; a unit test must fail the build on a violation.
- `SPEC-11.2.9` `html` must return a 200 HTML response and `html_status` an HTML response with the given status;
  `html_cookies` must return a 200 HTML response with one `Set-Cookie` header appended (not replaced) per supplied
  cookie string, in order; `status_cookies` must return a bodiless response with the given status and the same
  appended cookies.
- `SPEC-11.2.10` `redirect` must return status 303 with a `Location` header, and `redirect_cookies` must additionally
  append one `Set-Cookie` header per supplied cookie string (`SPEC-2.3.3`).
- `SPEC-11.2.11` A `Set-Cookie` string or a redirect target that is not a valid header value must not be dropped
  silently: the failure must be logged at `warn` naming the cookie name or the path. A cookie string that is not a
  valid header value is skipped, and a redirect target that is not a valid header value is replaced by `/`.

### 11.3 Server configuration (`bunyip-web/src/config.rs`)

- `SPEC-11.3.1` `Config::from_env` must read configuration only from the process environment and must treat an
  empty value as unset.
- `SPEC-11.3.2` `BUNYIP_API_URL` (default `http://localhost:4401`) must set `api_url`, the internal origin without a
  `/v1` suffix used for all server-to-server calls; `BUNYIP_BIND_ADDR` (default `0.0.0.0:4400`) must set `bind_addr`.
- `SPEC-11.3.3` `BUNYIP_API_PUBLIC_ORIGIN` must set `api_public_origin` and must default to the resolved `api_url`;
  `BUNYIP_OIDC_ISSUER` must set `oidc_issuer` and must default to the resolved `api_url`.
- `SPEC-11.3.4` `BUNYIP_APP_DOMAIN` (default empty) must set `app_domain`; `BUNYIP_COMMUNITY_URL` (default empty) must
  set `community_url`. `community_enabled()` must be true exactly when `community_url` is non-empty, and
  `domain_or_localhost()` must return `app_domain`, or `localhost` when it is empty.
- `SPEC-11.3.5` `TRUSTED_PROXY_CIDR` must be parsed as a comma-separated list of CIDR ranges; entries are trimmed,
  blank entries are dropped, and an entry that does not parse must be skipped with a `warn` log carrying the entry
  and the parse error, without aborting startup. An unset, empty or all-invalid list means no proxy is trusted.
- `SPEC-11.3.6` `CSP_CONNECT_SRC` and `CSP_FORM_ACTION` must each be parsed as a comma-separated list, trimmed with
  blank entries dropped, into `CspConfig::connect_src` and `CspConfig::form_action`. The entries are not validated at
  parse time.
- `SPEC-11.3.7` `Config::cookies_secure(peer, headers)` must return true only when `peer` is inside a configured
  trusted-proxy range and the first comma-separated element of `X-Forwarded-Proto`, trimmed, equals `https`
  ignoring ASCII case; with no peer, an untrusted peer, no header or any other protocol it must return false.
- `SPEC-11.3.8` `Config::apex_url()` must return `None` when `app_domain` is empty, and otherwise
  `<scheme>://<app_domain>` where the scheme is `https` when `api_public_origin` starts with `https://` and `http`
  otherwise. This scheme guess is display-only and must not be used to decide cookie security.
- `SPEC-11.3.9` `Config::default_share_image()` must return `None` when `apex_url()` is `None`, and otherwise the apex
  URL followed by the versioned asset path of `DEFAULT_SHARE_IMAGE_PATH` (`/assets/bunyip-hero-718.webp`).
- `SPEC-11.3.10` `Config` must not carry the product name, tagline, meta description, Open Graph image or theme
  colours; those are fields of the admin-managed branding record (`SPEC-11.5.3`).

### 11.4 Request authentication (`bunyip-web/src/auth.rs`)

- `SPEC-11.4.1` `req_cookie` must return the `Cookie` request header as a string, or `None` when the header is absent
  or not valid UTF-8.
- `SPEC-11.4.2` `authenticate(api, None)` must return an anonymous `AuthCtx` (`user` `None`, no `set_cookies`,
  `forward` `None`, `feedback_badge` `None`) without calling `bunyip-api`.
- `SPEC-11.4.3` `authenticate` with a cookie must first call `GET /v1/users/me` with that cookie. On success with no
  role mismatch it must return the user, no `set_cookies`, and `forward` equal to the original cookie.
- `SPEC-11.4.4` After a successful `/users/me`, if the cookie holds an `access_token` whose payload carries a string
  `role` claim that does not match the user's role per `SPEC-11.4.8`, `authenticate` must call `POST /v1/auth/refresh`
  exactly once. On refresh success it must merge the returned cookies into the original cookie (`SPEC-11.4.9`),
  re-read `/users/me` with the merged cookie, and return that user (the pre-refresh user if the re-read fails), the
  refresh `Set-Cookie` strings as `set_cookies`, and the merged cookie as `forward`. On refresh failure it must
  return the pre-refresh user with the original cookie and no `set_cookies`.
- `SPEC-11.4.5` When `/users/me` answers 401, `authenticate` must call `POST /v1/auth/refresh` once. On success it
  must re-read `/users/me` with the merged cookie and return that user (`None` if the re-read fails), the rotated
  cookies as `set_cookies` and the merged cookie as `forward`. On refresh failure it must return an anonymous user
  with `forward` equal to the original cookie.
- `SPEC-11.4.6` When `/users/me` fails with any status other than 401 (including a transport failure, status 0), the
  result must be an anonymous user with no `set_cookies` and `forward` equal to the original cookie.
- `SPEC-11.4.7` The role claim must be read without verifying the token signature: the `access_token` cookie value is
  split on `.`, the second segment is base64url-decoded without padding and parsed as JSON, and the `role` field must
  be a string. A missing cookie, a token with fewer than two segments, a payload that does not decode or parse, or a
  missing or non-string `role` must yield no claim, and the mismatch check is then skipped.
- `SPEC-11.4.8` A user role and a claim string match only when the role is not `Unknown` and its wire string equals
  the claim exactly; an unrecognised role or claim must be treated as a mismatch so a refresh is attempted.
- `SPEC-11.4.9` `merge_cookies(original, set_cookies)` must parse the original `Cookie` header into name/value pairs,
  apply each `Set-Cookie` string by its first `name=value` pair (attributes ignored), let a later value replace an
  earlier one, delete a name whose new value is empty, and render the result sorted by cookie name as
  `name=value; name=value`.
- `SPEC-11.4.10` `AuthCtx::is_signed_in` must be true exactly when `user` is `Some`.

### 11.5 Branding cache and brand-asset proxy (`bunyip-web/src/branding.rs`)

Refines `SPEC-2.3.1`.

- `SPEC-11.5.1` The process-wide branding cache must start empty and, until a fetch succeeds, return the shared default
  `Branding` (every field empty), which renders unbranded chrome.
- `SPEC-11.5.2` `BrandingCache::refresh` on success must replace the whole stored record, so a field cleared upstream
  is cleared here too. On failure with a stored record it must keep the record and log at `warn`; on failure with
  nothing stored it must log at `error` and keep serving the empty default. Both logs must carry the endpoint
  `/v1/branding`, the status, code, message and request id.
- `SPEC-11.5.3` The product name, tagline, meta description, Open Graph image, newsletter URL, theme CSS, theme
  colours and asset versions must come only from `GET /v1/branding`; a failed fetch must never substitute a
  compiled-in value.
- `SPEC-11.5.4` `branding::fetch` must call `GET /v1/branding` without a cookie.
- `SPEC-11.5.5` `load_at_startup` must bound the fetch at `BRANDING_STARTUP_TIMEOUT_SECS` (5) seconds. A timeout must
  be treated as a failed fetch with status 0, code `TIMEOUT` and the message
  `the startup branding fetch did not answer within 5s`, logged per `SPEC-11.5.2` (`SPEC-2.3.1`).
- `SPEC-11.5.6` `spawn_refresh` must start a task that sleeps `BRANDING_REFRESH_SECS` (60) seconds and then refreshes,
  repeating forever; the first refresh happens after the first sleep, not immediately.
- `SPEC-11.5.7` `admin_get` must call `GET /v1/admin/branding` and `admin_update` must call `PUT /v1/admin/branding`
  with the supplied JSON body, both forwarding the supplied cookie; a non-2xx answer must surface as the
  `ApiError` carrying the API's field-level message.
- `SPEC-11.5.8` `admin_upload_asset` must send a multipart form with one file part named `asset` carrying the given
  filename and declared MIME type to `POST /v1/admin/branding/assets/<slot>`; a MIME string that is not valid must
  fail before any request with status 0, code `NETWORK_ERROR` and the message `invalid brand asset mime: <cause>`.
  `admin_clear_asset` must call `DELETE /v1/admin/branding/assets/<slot>`.
- `SPEC-11.5.9` `BRAND_ASSET_KINDS` must be exactly `mark`, `mascot`, `mascot-2x`, `favicon-ico`, `favicon-16`,
  `favicon-32`, `favicon-48`, `favicon-192`, `favicon-512`, `apple-touch-icon`. `GET /brand/:kind` must answer 404
  without any upstream request when `kind` is not in that list, so a crafted segment cannot reach another endpoint.
- `SPEC-11.5.10` For a listed `kind`, `GET /brand/:kind` must fetch `/v1/branding/assets/<kind>` without forwarding a
  cookie and, on a 2xx upstream status, stream the body with status 200, the upstream `Content-Type` (or
  `application/octet-stream` when absent or not text) and `Cache-Control: public, max-age=86400`.
- `SPEC-11.5.11` `GET /brand/:kind` must answer 404 (never a redirect) for a non-2xx upstream status, logged at `debug`
  with the kind and status, and for an upstream transport failure, logged at `warn` with the kind, status and
  message.
- `SPEC-11.5.12` When building a brand image response fails, the handler must log at `error` with the kind and the
  builder error and answer 404.
- `SPEC-11.5.13` `GET /favicon.ico` must, when the current branding record's `favicon_version` is non-empty, try the
  upstream `favicon-ico` asset and stream it on 2xx with `Cache-Control: public, max-age=86400` and the upstream
  `Content-Type` (default `image/x-icon`). On a non-2xx status or transport failure it must log at `warn` and fall
  back to the committed file.
- `SPEC-11.5.14` The committed fallback for `GET /favicon.ico` is the file `assets/favicon.ico` relative to the working
  directory, served with `image/x-icon` and `Cache-Control: public, max-age=86400`; when it cannot be read the
  handler must log at `error` with the path and cause and answer 404.

### 11.6 Feature-flag snapshot (`bunyip-web/src/feature_flags.rs`)

Refines `SPEC-2.3.1`.

- `SPEC-11.6.1` A flag refresh must call `GET /v1/auth/setup/status` and, on success, install `orgs_enabled` and the
  full `features` map into the process-wide cells, replacing the previous values.
- `SPEC-11.6.2` A failed flag read must never switch a feature on. At startup it must log at `error` (endpoint,
  status, code, message, request id) stating that organizations and teams stay off; on a later refresh it must log at
  `warn` and keep the last installed values.
- `SPEC-11.6.3` `load_at_startup` must bound the read at `FLAGS_STARTUP_TIMEOUT_SECS` (5) seconds; a timeout must be
  reported at the startup `error` level as status 0, code `TIMEOUT`, message
  `the startup feature-flag read did not answer within 5s`.
- `SPEC-11.6.4` `spawn_refresh` must start a task that sleeps `FLAGS_REFRESH_SECS` (60) seconds and then refreshes,
  repeating forever.
- `SPEC-11.6.5` Flag reads must happen only at startup and on that interval, never per request.

### 11.7 Upstream reachability state (`bunyip-web/src/server_status.rs`)

- `SPEC-11.7.1` The process must hold one global reachability flag, initially reachable.
- `SPEC-11.7.2` `note_status(status)` must mark the API unreachable when `status` is 500 to 599 and reachable for any
  other status, including 4xx.
- `SPEC-11.7.3` `note_transport_error()` must mark the API unreachable.
- `SPEC-11.7.4` While the flag is unreachable, `banner()` must render a full-width element with `role="status"` and
  `aria-live="polite"` containing the text `Service unavailable. Reconnecting` followed by the ellipsis character
  (U+2026); while reachable it must render nothing.
- `SPEC-11.7.5` `spawn_recovery_poll(api_url)` must start a task that wakes every 10 seconds, does nothing while the
  flag is reachable, and while unreachable sends `GET <api_url without trailing slash>/health` with a plain client;
  a 2xx answer must mark the API reachable. A send error or non-2xx answer must leave the flag unchanged.

### 11.8 TTL cache for chrome payloads (`bunyip-web/src/ttl_cache.rs`)

- `SPEC-11.8.1` The freshness windows must be `PRICING_CACHE_TTL_SECS` = 30, `APPLICATIONS_CACHE_TTL_SECS` = 30,
  `DOCUMENTED_APPS_CACHE_TTL_SECS` = 30 and `SETUP_STATUS_CACHE_TTL_SECS` = 60 seconds.
- `SPEC-11.8.2` `get_or_fetch` must return the stored value without calling the fetch closure when it was stored less
  than the TTL ago; at exactly the TTL or later it is expired.
- `SPEC-11.8.3` On an expired or empty slot, callers must queue on one async gate, re-check freshness after acquiring
  it, and only then fetch, so a burst of concurrent callers makes at most one upstream call and the rest serve the
  winner's value. The slot's read lock must not be held across an await, and a poisoned lock must be recovered rather
  than panic.
- `SPEC-11.8.4` A failed fetch must be logged at `error` with the endpoint, target type, status, code, message,
  request id, the `CacheSource` served and the note describing what the page loses.
- `SPEC-11.8.5` On a failed fetch with a stored value the cache must serve that stale value (`StaleOnError`) and must
  leave the stored timestamp unchanged, so the next call after the TTL fetches again; with nothing stored it must
  return the `ApiError` (`NoValueOnError`) and never an empty payload.

### 11.9 Content-Security-Policy (`bunyip-web/src/security.rs`)

Refines `SPEC-2.3.4`.

- `SPEC-11.9.1` `csp_layer` must set `Content-Security-Policy` on every response that does not already carry that
  header, so a stricter per-route policy (for example the admin attachment sandbox) is never replaced.
- `SPEC-11.9.2` The policy must be the directives, in this order, joined by `; `: `default-src 'self'`,
  `base-uri 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `form-action`, `img-src 'self' data: https:`,
  `font-src 'self'`, `style-src 'self' 'unsafe-inline'`, `script-src 'self'`, `connect-src`.
- `SPEC-11.9.3` `form-action` must be `'self'`, then `api_public_origin`, then `https://*.<app_domain>` only when
  `app_domain` is non-empty, then `https://checkout.stripe.com` and `https://billing.stripe.com`, then each
  configured extra `form_action` host.
- `SPEC-11.9.4` `connect-src` must be `'self'`, then `api_public_origin`, then `https://api.pwnedpasswords.com`, then
  each configured extra `connect_src` host.
- `SPEC-11.9.5` Configured extra hosts must be appended only to `connect-src` and `form-action`; `script-src`,
  `default-src` and `frame-ancestors` must never be relaxed by configuration, and with no extras the policy must be
  byte-identical to the default.
- `SPEC-11.9.6` `script-src` must be exactly `'self'`: no third-party host, `'unsafe-inline'` or `'unsafe-eval'`, and
  no Font Awesome, unpkg or Google Fonts host may appear anywhere in the policy. Server values must reach the client
  as `data-*` attributes, never as executable script.
- `SPEC-11.9.7` Production view and handler source (everything above each file's first `#[cfg(test)]`) must contain no
  inline `<script>` body, no HTML event-handler attribute and no off-origin `<script src>`; a unit test must fail
  the build on a violation.
- `SPEC-11.9.8` No browser script under `assets/js` may contain an empty `catch` body or a promise `.catch` that drops
  the error without logging; a unit test must fail the build on a violation.
- `SPEC-11.9.9` The shared document head must not link a remote font or icon stylesheet, the Font Awesome build
  directory must not exist under the crate, and the two vendored font files `inter-v20-latin.woff2` and
  `jetbrains-mono-v24-latin.woff2` must exist under `assets/vendor/fonts/`; a unit test must fail the build otherwise.
- `SPEC-11.9.10` Source files must not contain the retired business-tier and organization marketing strings listed in
  `removed_business_tier_and_org_copy_stay_removed`; a unit test must fail the build when one returns.
- `SPEC-11.9.11` If the assembled policy is not a valid header value (for example a configured extra host with a
  control character), `csp_layer` must abort startup by panic with the message `CSP policy is valid header value`.

### 11.10 Client-IP middleware re-export (`bunyip-web/src/client_ip.rs`)

Refines `SPEC-2.3.3`.

- `SPEC-11.10.1` `crate::client_ip` must re-export the whole public surface of `web_kit::client_ip` and must define no
  behavior of its own.
- `SPEC-11.10.2` As implemented by the re-exported middleware, the end-user address must be taken from the first
  `X-Forwarded-For` entry (falling back to `X-Real-IP`) only when the socket peer is inside a configured trusted
  proxy range; otherwise nothing is resolved and no address is forwarded to `bunyip-api`.
- `SPEC-11.10.3` The browser `User-Agent`, truncated to 512 characters, must be captured for every request,
  independent of the trusted-proxy check, so `bunyip-api` records a real device label.

### 11.11 CSRF middleware re-export (`bunyip-web/src/csrf.rs`)

- `SPEC-11.11.1` `crate::csrf` must re-export the whole public surface of `web_kit::csrf` and must define no behavior
  of its own.
- `SPEC-11.11.2` As implemented by the re-exported middleware, every request whose method is not `GET`, `HEAD` or
  `OPTIONS` and whose path is not in the exemption list must be refused with status 403 and a `warn` log unless the
  host of its `Origin` header (or, when `Origin` is absent, its `Referer` header) equals its `Host` header; a request
  with neither header, or without `Host`, must be refused.

### 11.12 Formatting and display helpers (`bunyip-web/src/util.rs`)

- `SPEC-11.12.1` `format_stripe_amount(None, _)` must return `--`. For `Some(cents)` it must render
  `<whole>.<two-digit fraction>` with `whole = cents / 100` (integer division) and fraction `|cents % 100|`, prefixed
  `$` for `usd`, the euro sign (U+20AC) for `eur`, the pound sign (U+00A3) for `gbp` (currency matched ignoring
  case), and for any other currency suffixed with a space and the upper-cased currency code.
- `SPEC-11.12.2` `price_period` must return `year` when the interval is exactly `year` and `month` for every other
  value including an absent interval; `price_with_period` must join the formatted amount and the period as
  `<amount>/<period>`.
- `SPEC-11.12.3` `entry_price` must return `None` unless the pricing payload is published; otherwise the formatted
  price-with-period of the cheapest tier among those that are `available` and have interval exactly `month`, or `None`
  when there is none.
- `SPEC-11.12.4` `tier_price` must return `None` when the pricing payload is not published or the tier is
  `MembershipTier::Unknown`; otherwise the price-with-period of the first tier equal to the given tier regardless of
  its availability, or `None`.
- `SPEC-11.12.5` `pricing_currency` must return the first non-empty tier currency, or `usd` when there is none.
- `SPEC-11.12.6` `app_host` must return `<subdomain>.<domain>` only when the subdomain is non-empty after trimming and
  the domain is non-empty, and `None` otherwise; the slug must never be guessed into a host. `app_link` must prefix
  `https://` and `app_launch_link` must additionally append `/dashboard`; both are `None` exactly when `app_host` is.
- `SPEC-11.12.7` `app_gradient` must return `from-primary to-primary` for a missing or empty group id, and otherwise the
  element of `APP_GRADIENTS` (four Tailwind pairs) at index `fnv1a(group_id) % 4`, using the 64-bit FNV-1a hash with
  offset `0xcbf29ce484222325` and prime `0x100000001b3`, so the accent is stable across processes and independent of
  card position.
- `SPEC-11.12.8` `has_active_membership` must be false for no user and otherwise true when the user is an admin, a
  lifetime member, has a `trial_ends_at` that parses as RFC 3339 and lies in the future, or has membership status
  `Active` or `GracePeriod`.
- `SPEC-11.12.9` `relative_time` must return the input unchanged when it is not RFC 3339, and otherwise (negative ages
  clamped to zero) return: `just now` for up to one minute; `<n> minutes ago` for under an hour; `<n> hour(s) ago`
  for under a day; `yesterday` for one day; `<n> days ago` for 2 to 6 days; `<n> week(s) ago` for 7 to 29 days;
  `<n> month(s) ago` (30-day months) for 30 to 364 days; and `<n> year(s) ago` (365-day years) beyond, with the
  singular form exactly when `n` is 1.
- `SPEC-11.12.10` `rel_time` must render a `<time>` element whose `datetime` is the input, whose `title` is the input
  formatted as `YYYY-MM-DD HH:MM UTC` (the raw input when it does not parse), and whose text is `relative_time`.
- `SPEC-11.12.11` `urlenc` must pass `A-Z a-z 0-9 - _ . ~` through, encode a space as `+`, and percent-encode every
  other byte of the UTF-8 form as `%XX` with upper-case hex.
- `SPEC-11.12.12` `days_until` must return `None` for an unparseable timestamp or one not strictly in the future, and
  otherwise the remaining seconds divided by 86400 rounded up to a whole number of days.

### 11.13 API client transport (`bunyip-web/src/api/mod.rs`)

Refines `SPEC-2.3.3`.

- `SPEC-11.13.1` `Api::new(api_url)` must build the base as `api_url` with trailing slashes removed plus `/v1` and
  hold one shared `reqwest::Client` (cloned, not rebuilt, per `Api` clone) with the `gzip` feature enabled so the
  client advertises and decodes gzip; a unit test must fail the build if the `reqwest` dependency loses `gzip`.
- `SPEC-11.13.2` `Api::send` must issue the request to `<base>/v1<path>` with `Accept: application/json`, the supplied
  cookie as the `Cookie` header when present, the optional JSON body, and the client-IP headers of `SPEC-11.13.7`.
  It must return a `Resp` for every HTTP response including 4xx and 5xx, and `Err` only for a transport failure.
- `SPEC-11.13.3` A transport failure in `send`, `post_form` or `get_stream` must be logged at `warn` with the error
  and URL, must call `server_status::note_transport_error`, and must be returned as `ApiError` with status 0, code
  `NETWORK_ERROR` and the transport error text as message, with no request id.
- `SPEC-11.13.4` For every HTTP response in `send`, `post_form` and `get_stream`, `server_status::note_status` must be
  called with the status.
- `SPEC-11.13.5` `Resp` must carry the request path, the status, the parsed body, every `Set-Cookie` header value
  (values that are not valid UTF-8 are omitted), the `Retry-After` header parsed as whole seconds (absent or
  non-numeric gives `None`), and the trimmed non-empty `X-Request-Id` header (otherwise `None`). The request id must
  come from the header, not the body envelope.
- `SPEC-11.13.6` The body of a buffered response must be parsed as JSON; an empty or whitespace-only body gives
  `Value::Null`. A body that cannot be read or is not valid JSON gives `Value::Null` and must be logged at `warn`
  with the path and status.
- `SPEC-11.13.7` When the client-IP middleware resolved an address for the current request, `send`, `post_form` and
  `get_stream` must send it as `X-Forwarded-For`; when it did not (untrusted peer, background task) the header must
  be omitted, never invented. When a browser `User-Agent` was captured it must replace the outbound `User-Agent`.
- `SPEC-11.13.8` `Api::get_root(path)` must request `<api_url>/<path>` without the `/v1` prefix and without cookie or
  client-IP headers, for the root-level endpoints (`/health`, `/healthz`, `/version`); a transport failure must be
  returned with status 0 and code `FETCH_FAILED`, and it must not update `server_status`.
- `SPEC-11.13.9` `Api::get_stream` must forward the supplied cookie, return the raw `reqwest::Response` without reading
  the body, and send no `Accept` header, so large downloads stream without buffering.
- `SPEC-11.13.10` `Api::post_form` must POST the multipart form to `<base>/v1<path>` with `Accept: application/json`
  and the supplied cookie.
- `SPEC-11.13.11` `get`, `post`, `put` and `delete` must be `send` with the matching method; `Resp::ok()` must be true
  exactly for statuses 200 to 299.

### 11.14 API error mapping and decoding (`bunyip-web/src/api/mod.rs`)

- `SPEC-11.14.1` `error_from(resp)` must build an `ApiError` with the response status; `code` from `error.code` or
  `REQUEST_FAILED`; `message` from a non-empty `error.message` or `Request failed (<status>)`; `retry_after` from the
  `Retry-After` header, else `error.details.retry_after`; `bucket` from `error.details.bucket`; and `request_id` from
  the response header.
- `SPEC-11.14.2` `ok_data(resp)` must return the body's `data` member (`Null` when absent) for a 2xx response and
  `error_from` otherwise.
- `SPEC-11.14.3` `parse::<T>` must deserialize `data` (absent as `Null`) for a 2xx response and return `error_from`
  otherwise; `parse_bare::<T>` must deserialize the entire body instead, for the one endpoint that answers without the
  envelope.
- `SPEC-11.14.4` A 2xx body that does not match `T` must be returned as an `ApiError` with status 0, code
  `DECODE_ERROR` and the message `We could not read the response from the server. Please try again.`, with the
  response request id attached, after logging at `error` the endpoint, the target type name and the serde message.
- `SPEC-11.14.5` `ApiError::user_message` must return, in order: the fixed decode message for code `DECODE_ERROR`;
  for status 429 with a `retry_after`, `Too many attempts. Please try again <humanized>.` plus
  ` (bucket: <b>)` when a bucket is known; for status 0, `Couldn't reach the server. Please try again in a moment.`;
  for 500 to 599, `An unexpected error occurred. Please try again later.`; for an empty message,
  `An unexpected error occurred`; otherwise the API's message. Raw transport and 5xx text must never reach the
  browser.
- `SPEC-11.14.6` `humanize_retry_after(secs)` must return `in about an hour` for 3600 or more, `in about a minute` for
  under 60, and otherwise `in about <ceil(secs/60)> minutes`.
- `SPEC-11.14.7` `ApiError::user_message_with_reference` must append ` Reference: <request_id>.` to `user_message`
  when a request id is present and otherwise equal `user_message`.
- `SPEC-11.14.8` `ApiError::verification_message` must return `You have requested too many verification emails. Please
  try again <humanized>.` for a 429 with a `retry_after`, and `user_message` otherwise.

### 11.15 Auth and account API calls (`bunyip-web/src/api/auth.rs`)

All calls below forward the supplied cookie when one is a parameter, return a non-2xx answer as the `ApiError` of
`SPEC-11.14.1`, and return `Set-Cookie` strings only where stated.

- `SPEC-11.15.1` `list_trusted_devices` must call `GET /users/me/trusted-devices?page=<p>&per_page=<n>`;
  `revoke_trusted_device` must call `POST /users/me/trusted-devices/<id>/revoke` with `id` percent-encoded.
- `SPEC-11.15.2` `parse_login` must return `TwoFactorRequired` when the data has `requires_2fa` true,
  `ApprovalRequired` when it has `requires_approval` true, each carrying `challenge_token`, and otherwise decode an
  `AuthResponse` into `SignedIn(user)`; a decode failure must be returned as the
  `DECODE_ERROR` of `SPEC-11.14.4` naming the endpoint.
- `SPEC-11.15.3` `setup_status` must call `GET /auth/setup/status` without a cookie, and `me` must call
  `GET /users/me`.
- `SPEC-11.15.4` `refresh` must call `POST /auth/refresh` and return the response's `Set-Cookie` strings on 2xx and the
  `ApiError` otherwise.
- `SPEC-11.15.5` `logout` must call `POST /auth/logout` and return the response's `Set-Cookie` strings whatever the
  status.
- `SPEC-11.15.6` `login` must call `POST /auth/login` with `{email, password, remember}` and return the parsed
  `LoginOutcome` plus the response cookies; `verify_magic_link` must call `POST /auth/magic-link/verify` with
  `{token}` and no cookie and return the same.
- `SPEC-11.15.7` `verify_2fa` must call `POST /auth/2fa/verify` and `verify_login_approval` must call
  `POST /auth/login-approval/verify`, each with `{challenge_token, code}`, and return the user and the response
  cookies.
- `SPEC-11.15.8` `request_magic_link` must call `POST /auth/magic-link` with `{email}`; `request_password_reset` must
  call `POST /auth/password-reset` with `{email}`; `confirm_password_reset` must call
  `POST /auth/password-reset/confirm` with `{token, new_password}`; none forwards a cookie.
- `SPEC-11.15.9` `register` must call `POST /auth/register` with `{email, password, contact_channel, signup_token}`
  where `contact_channel` is the honeypot value, forward no cookie, and return the user and the response cookies.
- `SPEC-11.15.10` `register_challenge` must call `GET /auth/register-challenge` and return the `token` string, or
  `None` on any failure, so the form embeds an empty token.
- `SPEC-11.15.11` `accept_invite` must call `POST /auth/invite/accept` with `{token}` plus `password` only when one is
  given; when the data has `needs_password` true it must return the email (empty if absent) with no user, otherwise
  the decoded user, always with the response cookies.
- `SPEC-11.15.12` `update_profile` must call `PUT /users/me/profile` with a body holding only the supplied keys among
  `first_name`, `last_name`, `phone`: `Some("")` clears the column, `None` leaves it unchanged.
- `SPEC-11.15.13` `upload_avatar` must POST a multipart form with one file part named `avatar` (given filename and
  declared MIME) to `/users/me/avatar`, failing before any request with status 0, code `NETWORK_ERROR` and message
  `invalid avatar mime: <cause>` for an invalid MIME; `remove_avatar` must call `DELETE /users/me/avatar`;
  `fetch_avatar` must stream `GET /users/me/avatar`.
- `SPEC-11.15.14` `change_password` must call `PUT /users/me/password` with `{current_password, new_password}` plus
  `totp_code` only when non-empty.
- `SPEC-11.15.15` `request_email_change` must call `POST /users/me/email` with `{new_email}` plus
  `current_password` and `totp_code` only when non-empty, and return whether the data's `requires_relogin` is true
  (false when absent) with the response cookies; `confirm_email_change` must call `POST /users/me/email/confirm` with
  `{token}` and no cookie.
- `SPEC-11.15.16` `confirm_email_verification` must call `POST /users/me/email/verify/confirm` with `{token}` and no
  cookie and return the data's `membership_tier` string (empty when absent); `request_email_verification` must call
  `POST /users/me/email/verify`.
- `SPEC-11.15.17` `delete_account` must call `DELETE /users/me` with `{password}` plus `totp_code` when given, and
  return the response cookies.
- `SPEC-11.15.18` `setup_2fa` must call `POST /auth/2fa/setup` with `{current_password}`; `resume_2fa_setup` must call
  `POST /auth/2fa/setup/resume` with `{setup_token}`; `confirm_2fa` must call `POST /auth/2fa/confirm` with
  `{code, setup_token}`; `status_2fa` must call `GET /auth/2fa/status`.
- `SPEC-11.15.19` `begin_rekey` must call `POST /auth/2fa/rekey` with `{password}` plus `totp_code` only when
  non-empty; `confirm_rekey` must call `POST /auth/2fa/rekey/confirm` with `{code}`; `disable_2fa` must call
  `POST /auth/2fa/disable` with `{password}` plus `totp_code` only when non-empty; `regenerate_recovery_codes` must
  call `POST /auth/2fa/recovery-codes` with `{password}`.

### 11.16 Application, membership and billing API calls (`bunyip-web/src/api/calls.rs`)

- `SPEC-11.16.1` `client_identity` must call `GET /users/me/oauth-clients/<client_id>/identity` with the client id
  percent-encoded.
- `SPEC-11.16.2` `list_sessions` must call `GET /users/me/sessions?page=<p>&per_page=<n>`; `revoke_session` must call
  `DELETE /users/me/sessions/<id>` with the id percent-encoded; `revoke_other_sessions` must call
  `POST /users/me/sessions/revoke-others`.
- `SPEC-11.16.3` `pricing` must call `GET /pricing` without a cookie and decode the bare, un-enveloped body
  (`parse_bare`).
- `SPEC-11.16.4` `applications` must call `GET /applications` with the optional cookie and return the `applications`
  list; `application_groups` must call `GET /application-groups` and return the `groups` list.
- `SPEC-11.16.5` `membership` must call `GET /memberships/me` and return `None` when the data is null;
  `payment_history` must call `GET /memberships/payments`; `invoices` must call `GET /billing/invoices`.
- `SPEC-11.16.6` `checkout` must call `POST /memberships/checkout` with `{price_id}` when given and `{}` otherwise.
- `SPEC-11.16.7` `cancel`, `cancel_now` and `reactivate` must call `POST /memberships/cancel`,
  `/memberships/cancel-now` and `/memberships/reactivate` respectively and return the response `Set-Cookie` strings,
  because the calls change the token claims; `billing_portal` must call `POST /memberships/billing-portal`.
- `SPEC-11.16.8` `downloads_all` must call `GET /downloads` and return the `groups` list; `download_asset` must stream
  `GET /applications/<slug>/downloads/<asset>` with both segments percent-encoded and return the raw response
  untouched.
- `SPEC-11.16.9` `submit_feedback` must POST a multipart form to `/feedback` always containing `message`, and
  containing `name`, `email`, `subject`, `page_path` and `website` only when non-empty, one `tags[]` text part per
  tag, and one file part named `attachments` per attachment with its filename and MIME; an invalid attachment MIME
  must fail before any request with status 0, code `NETWORK_ERROR` and message `invalid attachment mime: <cause>`.
- `SPEC-11.16.10` `documented_apps` must call `GET /application-docs`, `app_docs` must call
  `GET /applications/<slug>/docs` and `app_doc` must call `GET /applications/<slug>/docs/<doc_slug>`, with every
  slug percent-encoded and no cookie.

### 11.17 Admin API calls (`bunyip-web/src/api/admin.rs`)

All calls forward the supplied admin cookie and return a non-2xx answer as the `ApiError` of `SPEC-11.14.1`.

- `SPEC-11.17.1` Read calls must use these paths: `stats` `GET /admin/stats`; `system_health` `GET /admin/health`
  (returning only its `health` block); `integration_status` `GET /admin/integrations`; `provider_status`
  `GET /admin/providers/status`; `feedback_new_count` `GET /admin/feedback/new-count` (returning the integer
  `count`); `api_version` the root-level `GET /version` via `Api::get_root`.
- `SPEC-11.17.2` `users` must call `GET /admin/users?page=<p>&per_page=<n>` and append: `&search=` when `search` is
  non-empty; `&active=false` for status `suspended`, nothing for `all`, and `&active=true` for every other status;
  `&tier=` when `tier` is non-empty; `&verified=<bool>` when given; `&sort=<s>&dir=<d>` when `sort` is non-empty;
  every text value passed through `urlenc`.
- `SPEC-11.17.3` User mutation calls must use: `update_user_role` `PUT /admin/users/<id>/role` `{role}`;
  `update_user_email` `PUT /admin/users/<id>/email` `{email, verified}`; `verify_user_email`
  `POST /admin/users/<id>/email/verify`; `reset_user_two_factor` `POST /admin/users/<id>/two-factor/reset`;
  `delete_user` `DELETE /admin/users/<id>`; `suspend_user` `PUT /admin/users/<id>/status` `{active:false}`;
  `reactivate_user` the same with `{active:true}`; `admin_reset_password` `POST /admin/users/<id>/reset-password`;
  `get_user` `GET /admin/users/<id>`.
- `SPEC-11.17.4` Two-factor-gated calls must send the admin's code as `totp_code`: `grant_lifetime`
  `POST /admin/users/<id>/lifetime`, `revoke_lifetime` `POST /admin/users/<id>/lifetime/revoke`, `set_user_tier`
  `POST /admin/users/<id>/tier` `{tier, totp_code}`, and `delete_application` `DELETE /admin/applications/<id>` with
  `{password, totp_code}`.
- `SPEC-11.17.5` `grant_membership` and `revoke_membership` must call `POST /admin/memberships/grant` and
  `POST /admin/memberships/revoke` with `{user_id}`.
- `SPEC-11.17.6` Application calls must use: `applications` `GET /admin/applications` (returning `applications`);
  `create_application` `POST /admin/applications`; `update_application` `PUT /admin/applications/<id>`;
  `reorder_applications` `PUT /admin/applications/reorder` `{ordered_ids}`; `set_application_group`
  `PUT /admin/applications/<id>/group` `{group_id}` (null clears);
  `set_application_restricted` `PUT /admin/applications/<slug>/restricted` `{requires_entitlement}`.
- `SPEC-11.17.7` Application-group calls must use: `application_groups` `GET /admin/application-groups` (returning
  `groups`); `create_application_group` `POST /admin/application-groups`; `update_application_group`
  `PUT /admin/application-groups/<id>`; `delete_application_group` `DELETE /admin/application-groups/<id>`.
- `SPEC-11.17.8` Entitlement calls must use: `list_user_entitlements` `GET /admin/users/<id>/entitlements`;
  `grant_user_entitlement` `POST /admin/users/<id>/entitlements` `{slug}`; `revoke_user_entitlement`
  `POST /admin/users/<id>/entitlements/revoke` `{slug}`.
- `SPEC-11.17.9` `audit_logs` must call `GET /admin/audit-logs?page=<p>&per_page=<n>` and append `&admin_only=true` when
  requested and `&user_id=`, `&action=`, `&severity=`, `&since=`, `&q=` for each filter that is set, values passed
  through `urlenc`.
- `SPEC-11.17.10` `error_logs` must call `GET /admin/logs`, with `?category=<urlenc>` only when a non-empty category is
  given.
- `SPEC-11.17.11` Seed calls must use: `import_seed` `POST /admin/seed/import` with the parsed JSON as body;
  `seed_templates` `GET /admin/seed/templates`; `import_seed_template` `POST /admin/seed/import?template=<urlenc>`
  with no body.
- `SPEC-11.17.12` IP calls must use: `ip_bans` `GET /admin/ip-bans`; `ip_enrichment`
  `GET /admin/ip-enrichment?ip=<urlenc>` returning `None` for null data; `create_ip_ban` `POST /admin/ip-bans`
  `{ip, reason, duration_secs}`; `unban_ip` `DELETE /admin/ip-bans/<urlenc ip>`.
- `SPEC-11.17.13` Invite calls must use: `admin_invites` `GET /admin/invites?page=<p>&per_page=<n>` plus `&status=` and
  `&email=` (via `urlenc`) when set; `create_admin_invite` `POST /admin/invites` `{email}`; `revoke_admin_invite`
  `DELETE /admin/invites/<urlenc id>`.
- `SPEC-11.17.14` Mailer-suppression calls must use: `list_mailer_suppressions`
  `GET /admin/mailer-suppressions?page=<p>&per_page=<n>`; `delete_mailer_suppression`
  `DELETE /admin/mailer-suppressions/<urlenc address>`.
- `SPEC-11.17.15` Rate-limit calls must use: `rate_limits` `GET /admin/rate-limits?page=<p>&per_page=<n>`;
  `reset_rate_limit` `POST /admin/rate-limits/reset` `{action, key}`; `rate_limit_whitelist`
  `GET /admin/rate-limits/whitelist`; `add_rate_limit_whitelist` `POST /admin/rate-limits/whitelist`
  `{kind, value, reason}`; `delete_rate_limit_whitelist` `DELETE /admin/rate-limits/whitelist/<urlenc id>`;
  `rate_limit_history` `GET /admin/rate-limits/history?` with `since=<urlenc>&` and `limit=<n>&` when given;
  `rate_limit_overview` `GET /admin/rate-limits/overview?window=<urlenc>&threshold=<f64>&limit=<n>`.
- `SPEC-11.17.16` Rate-limit configuration calls must use: `rate_limit_configs` `GET /admin/rate-limit-configs`;
  `set_rate_limit_config` `PUT /admin/rate-limit-configs/<urlenc action>` `{max_requests, window_seconds}`;
  `delete_rate_limit_config` `DELETE /admin/rate-limit-configs/<urlenc action>`.
- `SPEC-11.17.17` Feature-toggle calls must use: `feature_toggles` `GET /admin/feature-toggles`; `set_feature_toggle`
  `PUT /admin/feature-toggles/<urlenc key>` `{enabled}`.
- `SPEC-11.17.18` Feedback calls must use: `feedback` `GET /admin/feedback?page=<p>&per_page=<n>&bucket=<b>` plus
  `&tag=`, `&has_attachment=<bool>`, `&has_response=<bool>`, `&q=` when set; `feedback_detail`
  `GET /admin/feedback/<id>`; `update_feedback_status` `PUT /admin/feedback/<id>/status` `{status}` with the wire
  string; `respond_to_feedback` `POST /admin/feedback/<id>/respond` `{response, status:"responded"}`;
  `feedback_archive` `GET /admin/feedback/archive?page=<p>&per_page=<n>`; `restore_feedback`
  `POST /admin/feedback/archive/<archive_id>/restore`; `mark_feedback_spam` / `unmark_feedback_spam`
  `POST /admin/feedback/<id>/mark-spam|unmark-spam`; `delete_feedback` `DELETE /admin/feedback/<id>`;
  `archive_feedback` `POST /admin/feedback/<id>/archive`.
- `SPEC-11.17.19` Stripe calls must use: `stripe_config` `GET /admin/stripe`; `update_stripe_config`
  `PUT /admin/stripe`; `list_stripe_products` / `create_stripe_product` `GET|POST /admin/stripe/products`;
  `update_stripe_product` `PUT /admin/stripe/products/<id>`; `archive_stripe_product`
  `DELETE /admin/stripe/products/<id>`; `unarchive_stripe_product` `POST /admin/stripe/products/<id>/unarchive`;
  `list_stripe_prices` / `create_stripe_price` `GET|POST /admin/stripe/prices`; `archive_stripe_price`
  `DELETE /admin/stripe/prices/<id>`; `unarchive_stripe_price` `POST /admin/stripe/prices/<id>/unarchive`;
  `replace_stripe_price` `POST /admin/stripe/prices/<id>/replace`; `list_stripe_webhooks` / `create_stripe_webhook`
  `GET|POST /admin/stripe/webhooks` (the create response carries the signing secret exactly once);
  `delete_stripe_webhook` `DELETE /admin/stripe/webhooks/<id>`; `check_stripe_permissions`
  `GET /admin/stripe/permissions`.
- `SPEC-11.17.20` Settings calls must use: `email_config` / `update_email_config` `GET|PUT /admin/email`;
  `test_email_config` `POST /admin/email/test`; `send_test_email` `POST /admin/email/test-send` with no body;
  `mirzam_config` / `update_mirzam_config` `GET|PUT /admin/mirzam`; `check_mirzam_connection`
  `POST /admin/mirzam/check`; `mokosh_config` / `update_mokosh_config` `GET|PUT /admin/mokosh`;
  `system_config` / `update_system_config` `GET|PUT /admin/system-config`; `tier_config` / `update_tier_config`
  `GET|PUT /admin/tier-config`; `update_tier_settings` `PUT /admin/tier-settings`; `pricing_status`
  `GET /admin/pricing/status`; `auto_ban_config` / `update_auto_ban_config` `GET|PUT /admin/auto-ban-config`.
- `SPEC-11.17.21` `restore_account` must call `POST /account/restore` with the parsed backup bundle as body.
- `SPEC-11.17.22` Application documentation calls must use: `app_docs` `GET /admin/applications/<app_id>/docs`;
  `create_app_doc` `POST /admin/applications/<app_id>/docs` `{slug, title, body, sort_order}`; `update_app_doc`
  `PUT /admin/application-docs/<doc_id>` with the same body; `delete_app_doc`
  `DELETE /admin/application-docs/<doc_id>`.

### 11.18 Wire data model (`bunyip-web/src/api/types.rs`)

- `SPEC-11.18.1` Every wire enum declared with `wire_enum!` (`UserRole`: `subscriber`, `admin`; `MembershipStatus`:
  `none`, `active`, `past_due`, `canceled`, `incomplete`, `grace_period`; `MembershipTier`: `lifetime`, `free`,
  `early_adopter`, `standard`; `FeedbackStatus`: `new`, `reviewed`, `responded`, `closed`; `IntegrationState`:
  `configured`, `unconfigured`, `failing`) must decode from a string, map any unrecognised string to the `Unknown`
  variant instead of failing the response, serialize `Unknown` as `unknown`, and default to `Unknown`.
- `SPEC-11.18.2` An `Unknown` role must never compare equal to `Admin`, and a defaulted or unknown membership tier,
  status or role must never widen access; authorization is enforced by `bunyip-api`.
- `SPEC-11.18.3` Every field of a wire struct must carry `#[serde(default)]` unless it is listed in `ESSENTIAL_FIELDS` in
  `scripts/check-serde-compat.nu`; the essential `User` fields are `id`, `email`, `role`, `email_verified` and
  `two_factor_enabled`, and a login decode must succeed with only those.
- `SPEC-11.18.4` `User.membership_status` must default to `None` when absent, and `membership_tier` must accept the
  legacy wire name `subscription_tier` as an alias.
- `SPEC-11.18.5` `User::display_name` must return the trimmed first name when non-empty and otherwise the email local
  part (the whole email when the local part is empty); `avatar_initial` must return the ASCII-upper-cased first
  character of the display name, or `?` when empty; `avatar_src` must be `None` without a non-empty
  `avatar_updated_at` and otherwise `/me/avatar?v=<percent-encoded timestamp>`.
- `SPEC-11.18.6` `SetupStatus` must default `email_enabled`, `stripe_enabled` and `orgs_enabled` to false and
  `features` to an empty map, so an older API leaves every feature dark.
- `SPEC-11.18.7` `PaginatedResponse<T>` must default `items` to an empty list and the counters to 0 without requiring
  `T: Default`; `page_size` is optional.
- `SPEC-11.18.8` The API-derived defaults that keep a surface usable must be: `AppDownloadGroup.has_access` true,
  `AdminApplication.is_hosted` true, the `*_editable` flags of the email, Stripe, newsletter-integration and
  host-integration settings true, `TierConfigResponse.*_visible` true and `PricingTier.available` true.
- `SPEC-11.18.9` `PricingResponse::published()` must be true exactly when `enabled` is true and `tiers` is non-empty;
  `PricingTier.amount` is required and `PricingTier.tier` defaults to `Unknown`.
- `SPEC-11.18.10` `MirzamCheckResult`, `TestEmailResult` and `SmtpTestResult` must default `ok` to false, so a body
  missing the field reads as a failed check, never a pass.
- `SPEC-11.18.11` `Branding` must default every field to empty. `mark_src`, `mascot_src`, `mascot_src_2x` and
  `favicon_src(kind)` must return `None` when the matching version string is empty and otherwise
  `/brand/<kind>?v=<percent-encoded version>`, using kinds `mark`, `mascot`, `mascot-2x` and the given favicon kind.
- `SPEC-11.18.12` `AppRestoreStatus` must decode from an object tagged on `state` with values `restored` or
  `skipped` (the latter carrying `reason`); an unknown state is a decode error.
- `SPEC-11.18.13` The provider-status types (`ProviderStatusAggregateResponse`, `ProviderAppState`,
  `ProviderAppStatusRow`, `ProviderDiscrepancy`, `ProviderKindEntry`, `ProviderStatusReport`) must be re-exported from
  `bunyip_domain::services::provider_status`, not redeclared, so a field added there is a compile error here.

### 11.19 Admin route table (`bunyip-web/src/routes/`)

- `SPEC-11.19.1` `routes::admin::routes()` must return one `Router<AppState>` holding every admin-panel and account
  backup route, and `routes/mod.rs` must expose it as `routes::admin`.
- `SPEC-11.19.2` The table must register, with method(s): `GET /admin`, `/admin/status`, `/admin/providers/status`,
  `/admin/audit-logs`, `/admin/logs`, `/admin/seed`, `/admin/seed/export`; `POST /admin/seed/import`,
  `/admin/seed/template`; `GET`+`POST /admin/invites`; `POST /admin/invites/:invite_id/revoke`; `GET /admin/ip-bans`;
  `POST /admin/ip-bans/add`, `/admin/ip-bans/unban`; `GET /admin/rate-limits`; `POST /admin/rate-limits/reset`,
  `/admin/rate-limits/config`, `/admin/rate-limits/config/reset`, `/admin/rate-limits/whitelist/add`,
  `/admin/rate-limits/whitelist/remove`.
- `SPEC-11.19.3` The table must register the user routes `GET /admin/users`, `GET /admin/users/:id`, and `POST`
  `/admin/users/:id/{role,email,email/verify,two-factor/reset,delete,suspend,reactivate,reset-password,lifetime,
  lifetime/revoke,tier}`, the membership routes `GET /admin/memberships` and `POST
  /admin/memberships/:user_id/{grant,revoke}`, and the entitlement routes `GET /admin/entitlements`, `GET
  /admin/users/:user_id/entitlements`, `POST /admin/users/:user_id/entitlements/{grant,revoke}` and `POST
  /admin/applications/:slug/restricted-toggle`.
- `SPEC-11.19.4` The table must register the feedback routes `GET /admin/feedback`, `/admin/feedback/export`,
  `/admin/feedback/closed`, `/admin/feedback/spam`, `/admin/feedback/archive`, `/admin/feedback/:id`,
  `/admin/feedback/:id/attachments/:attachment_id`, and `POST /admin/feedback/archive/:archive_id/restore`,
  `/admin/feedback/:id/{respond,status,mark-spam,unmark-spam,archive,delete}`. The literal tab and archive paths
  must be registered before the `:id` detail route.
- `SPEC-11.19.5` The table must register the application routes `GET`+`POST /admin/applications`, `GET
  /admin/applications/new`, `GET /admin/applications/:id/edit`, `POST /admin/applications/reorder`, `POST
  /admin/applications/:id/{distribution,delete,field,group}`, `GET`+`POST /admin/applications/:id/docs`, `POST
  /admin/applications/:id/docs/:doc_id` and `/delete`, and the group routes `GET`+`POST /admin/application-groups`,
  `GET /admin/application-groups/new`, `GET /admin/application-groups/:id/edit`, `POST /admin/application-groups/:id`
  and `/delete`.
- `SPEC-11.19.6` The table must register the configuration routes `GET`+`POST` for each of `/admin/tier-settings`,
  `/admin/features`, `/admin/branding`, `/admin/email`, `/admin/system-config`, `/admin/mirzam`, `/admin/mokosh`,
  `/admin/auto-ban-settings` and `/admin/stripe`, plus `POST /admin/tier-settings/catalog`, `/admin/email/test`,
  `/admin/email/test-send`, `/admin/mirzam/check`, `GET /admin/mailer-suppressions`, `POST
  /admin/mailer-suppressions/:address/delete`, and the Stripe management routes `POST /admin/stripe/products`,
  `/admin/stripe/products/:id`, `/admin/stripe/products/:id/{archive,unarchive}`, `/admin/stripe/prices`,
  `/admin/stripe/prices/:id/{replace,archive,unarchive}`, `/admin/stripe/webhooks` and
  `/admin/stripe/webhooks/:id/delete`.
- `SPEC-11.19.7` `POST /admin/branding/assets/:slot` must carry a route-level body limit of 3 MiB and
  `POST /admin/branding/assets/:slot/clear` must be registered without a raised limit.
- `SPEC-11.19.8` The table must register `GET /integrations/backup`, `GET /integrations/backup/download` and
  `POST /integrations/backup/restore`; the restore route must carry a route-level body limit of 9 MiB.
- `SPEC-11.19.9` The table must not apply any authentication or authorization layer; every handler must authorize the
  caller itself before acting, and `bunyip-api` remains the authoritative gate.

### 11.20 Skin and views module boundaries

- `SPEC-11.20.1` The `skin` module (`skin::content`, `skin::public`) must hold only the app-specific marketing, legal,
  documentation, feedback, landing and not-found pages; layout scaffolding, UI helpers and the auth, dashboard and admin
  handlers must not live in it.
- `SPEC-11.20.2` `views::common` and `views::ui` must re-export the `web_kit::common` and `web_kit::ui` items unchanged,
  so that `crate::views::common::*` and `crate::views::ui::*` call sites resolve without edits.
- `SPEC-11.20.3` `views::layout` must re-export `web_kit::shell::*`, so the shared shell scaffolding (`asset`, `NavItem`,
  `nav_links`, `theme_controls`, `admin_block`, `admin_block_grid`, `sse_subscriber_script`, `palette_value` and the
  `APP_*` class constants) resolves from `views::layout`.

### 11.21 Document head and scripts

- `SPEC-11.21.1` `document(title, body)` must render exactly what `document_with_avatar_picker(title, body, false)`
  renders.
- `SPEC-11.21.2` The document must start with the HTML doctype, open `<html lang="en">`, and declare
  `<meta charset="UTF-8">` and a viewport meta with content `width=device-width, initial-scale=1.0`.
- `SPEC-11.21.3` The document must emit `<meta name="description">` with the branding record's `meta_description` only
  when that field is non-empty; when empty it must emit no description tag and must not substitute a default sentence.
- `SPEC-11.21.4` The document must emit one `theme-color` meta with media `(prefers-color-scheme: light)` when
  `palette_value(theme_color_light)` is `Some`, and one with media `(prefers-color-scheme: dark)` when
  `palette_value(theme_color_dark)` is `Some`; an unset field must emit no tag and no compiled-in colour.
- `SPEC-11.21.5` The `<title>` must be `document_title(title, branding)` (see `SPEC-11.22.1`).
- `SPEC-11.21.6` The document must link the stylesheet `/assets/styles.css` through `asset()`.
- `SPEC-11.21.7` When `palette_value(theme_css)` is `Some`, the document must emit one `<style>` block whose body is
  `:root{` + the record's CSS + `}`, inserted without escaping (the record is validated api-side to contain no angle
  bracket); when it is `None` the document must emit no such block.
- `SPEC-11.21.8` The document head must load `/assets/js/theme.js` as a synchronous script (no `defer`, so the stored
  theme lands on `<html>` before first paint) and `/assets/js/app.js` with `defer`, in that order.
- `SPEC-11.21.9` Every `<script>` the document emits must have a same-origin `/assets/` `src` and an empty body, and
  the document must contain no CDN reference and no `on*` event-handler attribute, so that `script-src 'self'` holds.
- `SPEC-11.21.10` The shared head of a page rendered through `document()` must not load htmx or `app-reorder.js`; those
  scripts are emitted only by the admin users page and the admin applications page.
- `SPEC-11.21.11` The document must always inline the avatar slot rule (`AVATAR_SLOT_CSS`) in a `<style>` element so a
  stale cached stylesheet cannot leave the topbar avatar unstyled.
- `SPEC-11.21.12` When `with_avatar_picker` is true the document must additionally inline `AVATAR_PICKER_CSS` and load
  `/assets/js/avatar-picker.js` with `defer`; when false it must emit neither (the string `avatar-picker` must not
  appear in the output).
- `SPEC-11.21.13` The document body must render, in order, the `server_status::banner()` markup, the caller's body, and
  the toast surface `<div id="bunyip-toast-root">`; the toast surface must carry no `aria-live` attribute.
- `SPEC-11.21.14` The toast surface class (`TOAST_ROOT_CLASS`) must be `fixed` at `top-20` (below the `h-16` header
  bar), `pointer-events-none`, and bounded at phone width by `left-4` with `sm:left-auto`.
- `SPEC-11.21.15` Every `/assets/...` URL that `document_with_avatar_picker` emits in a `src` or `href` must end with
  `?v=` followed by the build asset version.

### 11.22 Sharing metadata, favicons and palette

- `SPEC-11.22.1` `document_title(page, branding)` must return `page` alone when `brand_name` is empty, else `page`, a
  space, the middle dot character (U+00B7), a space, and `brand_name`.
- `SPEC-11.22.2` `social_meta` must emit no markup when `brand_name` and `meta_description` are empty and there is no
  share image.
- `SPEC-11.22.3` When at least one of brand name, meta description or share image exists, `social_meta` must emit
  `og:type` = `website`, `og:title` and `twitter:title` both equal to `document_title(page, branding)`, and a
  `twitter:card` meta.
- `SPEC-11.22.4` The `twitter:card` value must be `summary_large_image` when a share image exists and `summary` when it
  does not.
- `SPEC-11.22.5` `social_meta` must emit `og:site_name` only when `brand_name` is non-empty.
- `SPEC-11.22.6` `social_meta` must emit `og:description` and `twitter:description` only when `meta_description` is
  non-empty.
- `SPEC-11.22.7` `social_meta` must emit `og:image` and `twitter:image` only when a share image exists.
- `SPEC-11.22.8` The share image must be the record's `og_image_url` when non-empty, else the committed default image
  when one is installed, else none.
- `SPEC-11.22.9` `social_meta` must never emit `og:url`.
- `SPEC-11.22.10` `favicon_links` must emit exactly seven links, in this order: `icon` sizes `any` (`favicon-ico`),
  `icon` 16x16 (`favicon-16`), 32x32 (`favicon-32`), 48x48 (`favicon-48`), 192x192 (`favicon-192`), 512x512
  (`favicon-512`), and `apple-touch-icon` 180x180 (`apple-touch-icon`).
- `SPEC-11.22.11` Each favicon link's `href` must be `branding.favicon_src(kind)` when the record has an uploaded
  favicon source, else the committed file served through `asset()`: `/assets/favicon.ico`,
  `/assets/favicon-16x16.png`, `/assets/favicon-32x32.png`, `/assets/favicon-48x48.png`,
  `/assets/favicon-192x192.png`, `/assets/favicon-512x512.webp`, `/assets/apple-touch-icon.png`.
- `SPEC-11.22.12` A favicon link's `type` must be the derived type when the derived URL is used (`image/png` for every
  size except `any`, which has none) and the committed type otherwise (`image/png` except the committed 512x512, which
  is `image/webp`, and the `any` icon, which has none).
- `SPEC-11.22.13` Every `derived_kind` referenced by a favicon link must appear in `crate::branding::BRAND_ASSET_KINDS`,
  because the `/brand/{kind}` proxy relays only that allow-list and any other kind would render a broken icon.

### 11.23 Brand mark and wordmark

- `SPEC-11.23.1` `brand_name()` must return the current branding record's `brand_name`, which is the empty string when
  nothing is branded and nothing has loaded; every site that renders it must omit its markup when it is empty.
- `SPEC-11.23.2` `brand_mark` must render `<img src=mark_src alt="" width="28" height="28">` with a `bg-card` surface
  when `branding.mark_src()` is `Some`, and the `alt` must be empty because the mark sits inside a link that already
  carries the product name.
- `SPEC-11.23.3` `brand_mark` must render the built-in inline SVG glyph (three reeds and two eye circles, drawn in
  `currentColor`) when `branding.mark_src()` is `None`.
- `SPEC-11.23.4` `brand()` must render a link to `/` containing the brand mark and the brand name text, with the link
  and the name span both carrying `min-w-0` and the name span sized with a fluid `clamp(...)` font size and
  `break-words`, never a fixed Tailwind text step.

### 11.24 Public shell

- `SPEC-11.24.1` `public_shell` must render a full-height column containing, in order, the header, a `<main
  class="flex-1">` holding the content, the footer, and the feedback launcher only when `show_feedback` is true.
- `SPEC-11.24.2` The public header must be a sticky `h-16` bar with a primary navigation (hidden below `md`) linking
  `/our-story` ("Our Story"), `/roadmap` ("Roadmap") and `/docs` ("Documentation") unconditionally.
- `SPEC-11.24.3` The header and the footer must link `/pricing` ("Pricing") only when the `pricing` argument is true
  (the pricing page is published), so no rendered page links to a 404 pricing route.
- `SPEC-11.24.4` The header and the footer must each render exactly one `/applications` link ("Applications") when
  `app_links_allowed` is true and none when it is false, and must never render a per-application entry.
- `SPEC-11.24.5` The Documentation entries must be plain `/docs` links built from no fetched data, so they render the
  same working link when the application list cannot be read.
- `SPEC-11.24.6` For a signed-out visitor the header must render the theme controls, a "Sign up" link to `/register`
  hidden below `sm` (`hidden sm:inline-flex`) and a "Sign in" link to `/login` visible at every width.
- `SPEC-11.24.7` For a signed-in visitor the header must render the theme controls, a "Dashboard" link to `/dashboard`,
  an "Admin" link to `/admin` only when the user's role is `UserRole::Admin` (an `Unknown` role gets none), and the
  profile menu.
- `SPEC-11.24.8` The footer must render four groups: the brand (mark, wordmark, tagline paragraph only when the tagline
  is non-empty, and a line of brand name, the middle dot character (U+00B7) and `cfg.domain_or_localhost()`), "Product"
  (the links above), "Account" ("Sign in" `/login`, "Sign up" `/register`) and "Legal" ("Terms of Service" `/terms`,
  "Privacy Policy" `/privacy`).
- `SPEC-11.24.9` The footer must end with a line made of the copyright sign, the current UTC four-digit year, a space,
  `cfg.domain_or_localhost()` and ". All rights reserved.".
- `SPEC-11.24.10` The feedback launcher must be a fixed bottom-right link with `href="/feedback"`,
  `aria-label="Open feedback page"`, the marker `data-feedback-link` and the hover label "Have feedback?".
- `SPEC-11.24.11` Every authenticated shell (`dashboard_shell`, `admin_shell`) must mount the feedback launcher;
  `public_shell` must mount it only when `show_feedback` is true (the login, registration, consent and `/feedback`
  pages pass false).

### 11.25 Authenticated shells and navigation

- `SPEC-11.25.1` `shell_nav_sections` must return, for an admin shell, a leading section holding one "User Dashboard"
  item (`/dashboard`, icon `layout-dashboard`) followed by the admin items; for a non-admin shell whose user is an
  admin, a leading section holding one "Admin Panel" item (`/admin`, icon `shield`) followed by the dashboard items;
  otherwise only the dashboard items. The sidebar and the below-`md` disclosure must both render from this one list.
- `SPEC-11.25.2` `dashboard_items` must return, in order: "Dashboard" `/dashboard`; "Community" `/community` (external)
  only when the user has an active membership and `community_enabled()` is true; "Organizations" `/organizations` only
  when `orgs_enabled()` is true; "Applications" `/applications`; "Membership & Billing" `/membership`; "Documentation"
  `/docs`; "Settings" `/settings`.
- `SPEC-11.25.3` While the organizations feature flag is off, no rendered authenticated shell may contain a link to
  `/organizations` or the word "Organizations"; when it is on, the entry must appear in both the sidebar and the
  below-`md` disclosure.
- `SPEC-11.25.4` `admin_items` must return these items, in order, as (title, href): Admin Dashboard `/admin`; System
  Status `/admin/status`; Provider Status `/admin/providers/status`; Users `/admin/users`; Applications
  `/admin/applications`; Application Groups `/admin/application-groups`; Entitlements `/admin/entitlements`; Branding
  `/admin/branding`; Email `/admin/email`; the newsletter-integration entry `/admin/mirzam`; the suite-host settings
  entry `/admin/mokosh`; Mailer Suppressions `/admin/mailer-suppressions`; System Settings `/admin/system-config`;
  Feature Toggles `/admin/features`; Stripe `/admin/stripe`; Pricing Tiers `/admin/tier-settings`; Feedback
  `/admin/feedback`; Audit Logs `/admin/audit-logs`; Error Logs `/admin/logs`; Seed Data `/admin/seed`; Admin Invites
  `/admin/invites`; IP Bans `/admin/ip-bans`; Auto-ban Settings `/admin/auto-ban-settings`; Rate Limits
  `/admin/rate-limits`.
- `SPEC-11.25.5` Only the admin "Feedback" item may carry a badge (the `feedback_badge` argument); every other nav item
  must carry none, and a non-admin shell must ignore the argument.
- `SPEC-11.25.6` Every word of every admin nav title must start with an uppercase letter.
- `SPEC-11.25.7` Every nav item's `icon` in every shell variant must be a name for which
  `web_kit::ui::icon_is_known` is true, because an unknown name renders an empty `<svg>`.
- `SPEC-11.25.8` `mobile_nav` must render `<details class="relative md:hidden" data-menu data-mobile-nav>` whose
  `<summary>` has `aria-label="Open navigation"` and a `menu` icon, and whose panel is a `<nav aria-label="Main">`
  with `max-h-[70vh]` and `overflow-y-auto` rendering every item of `shell_nav_sections` via `nav_links`.
- `SPEC-11.25.9` `sidebar` must render an `<aside>` that is hidden below `md` (`hidden md:flex`), fills the shell
  (`h-full`), clips its own overflow, and holds a fixed `h-16` brand row (plus an "Admin" pill in the admin variant)
  above a `<nav aria-label="Main">` that is the only scroll container (`flex-1 overflow-y-auto`).
- `SPEC-11.25.10` `dashboard_shell` must treat the user as admin only when `role == UserRole::Admin`, compute membership
  with `util::has_active_membership`, render no feedback badge, and render the sidebar, the top bar with the mobile
  nav, a scrolling `<main>`, the feedback launcher and the SSE subscriber script.
- `SPEC-11.25.11` `admin_shell` must render the admin sidebar and the mobile nav with the supplied `feedback_badge`, a
  top bar, a scrolling `<main>`, the feedback launcher and the SSE subscriber script.
- `SPEC-11.25.12` Both authenticated shells must lay out as a viewport-height shell at `md` and up (`APP_SHELL_CLASS`:
  `md:h-screen md:overflow-hidden`), with the content column (`APP_COLUMN_CLASS`) clipping overflow and `<main>`
  (`APP_MAIN_CLASS`) as the scroll container, so the sidebar and the content pane scroll independently of the document.

### 11.26 Top bar, profile menu and avatar badge

- `SPEC-11.26.1` `app_topbar` must render `<header class="relative z-40 flex h-16 ...">` containing the mobile nav, an
  `<h1>` with the bare page title (truncating), the top-bar destinations, the theme controls and the profile menu.
- `SPEC-11.26.2` The top bar must render one ghost icon link per `TOPBAR_DESTINATIONS` entry, in this order:
  `/applications` ("Applications", icon `app-window`) and `/docs` ("Documentation", icon `file-text`), each with
  `aria-label` and `title` equal to the label and with no breakpoint class, so it is one click at every width.
- `SPEC-11.26.3` `profile_menu` must render `<details data-menu>` whose summary shows the avatar badge (`h-8 w-8`), the
  display name (hidden below `sm`) and a chevron, and whose panel shows the display name and email (truncating), a
  "Profile" link to `/settings`, and a `POST /logout` form with a "Log out" submit button.
- `SPEC-11.26.4` `avatar_badge` must render `<span data-avatar-slot data-initial=INITIAL>` containing
  `<img alt="Profile photo" data-avatar-image>` only when `user.avatar_src()` is `Some`, and always a
  `<span data-avatar-initial aria-hidden="true">` with the user's initial, hidden with `display:none` when the image is
  present.

### 11.27 Shared view helpers

- `SPEC-11.27.1` `filter_chip_select(name, current, options)` must render a `<select name=NAME data-submit-on-change>`
  with one `<option value=V>` per `(value, label)` pair, with `selected` set exactly on the option whose value equals
  `current`.
- `SPEC-11.27.2` `error_box_for(headline, e)` must render `error_box_detailed(headline, Some(e.user_message()),
  e.request_id)`, so a load failure shows its cause and request id and not the bare headline.
- `SPEC-11.27.3` `aria_invalid(b)` must return the literal string `"true"` or `"false"`, never a valueless attribute.
- `SPEC-11.27.4` `field_invalid_class(base, extra)` must return `base`, the `aria-[invalid=true]:` border, ring-1 and
  ring variants for the destructive colour, and `extra`, so invalidity is one attribute flip on both the server redraw
  and the client path.
- `SPEC-11.27.5` `field_error_slot(field, msg)` must always render
  `<p id="FIELD-error" data-field-error="FIELD" role="alert" class="mt-1 text-sm text-destructive-text">`, holding
  `msg` when `Some` and carrying the `hidden` class when `None`, so the `aria-describedby` target always exists.
- `SPEC-11.27.6` A form that uses the per-field error pattern must render its `<form>` with `novalidate` so the themed
  inline errors replace the browser's native validation bubbles.
- `SPEC-11.27.7` `avatar_picker(user)` must delegate to `web_kit::avatar::avatar_picker` with the upload endpoint
  `/settings/avatar` and the remove endpoint `/settings/avatar/remove`, and `User` must implement
  `web_kit::avatar::Avatar` by delegating to its inherent `avatar_src` and `avatar_initial`.
- `SPEC-11.27.8` Every handler that renders `avatar_picker` must respond through
  `dashboard_response_with_avatar_picker`, because the plain shell ships neither the picker stylesheet nor its
  controller.

### 11.28 Password field view

- `SPEC-11.28.1` `password_field` must set `autocomplete` to `current-password` for `PwRole::Current` and
  `new-password` for `PwRole::New` and `PwRole::Confirm`, unless `PwField.autocomplete` is `Some`, in which case that
  value must win (a control-level `off` is how identity-confirmation forms stop password-manager pre-fill).
- `SPEC-11.28.2` `password_field` must render `<label for=ID>` and `<input id=ID name=NAME type="password">` with class
  `dashboard_input()` plus `pr-10`, adding `autofocus`, `required` and `placeholder` only when the matching
  `PwField` member is set; the helper must never add `required` on its own.
- `SPEC-11.28.3` `password_field` must mark the input with `data-pw-new` for `PwRole::New` and `data-pw-confirm` for
  `PwRole::Confirm`, and with neither for `PwRole::Current`.
- `SPEC-11.28.4` When `PwField.label_suffix` is `Some`, `password_field` must render it on the label's own row, opposite
  the label.
- `SPEC-11.28.5` `password_field` must render, for every role, a `type="button"` reveal toggle with
  `data-pw-toggle=ID`, `aria-pressed="false"` and `aria-label="Show password"`, containing both pre-rendered `eye` and
  `eye-off` glyph spans so the script only flips ARIA state.
- `SPEC-11.28.6` `guard_message()` must render an empty, `hidden` `<p data-pw-guard-msg role="alert">` that the guard
  script fills.
- `SPEC-11.28.7` `script()` must render `<script src=asset("/assets/js/password-field.js") defer>`.
- `SPEC-11.28.8` No handler may hand-roll an `<input type="password">` that a user types into; each must render through
  `password_field`, so none is left without the reveal toggle.

### 11.29 Landing page

- `SPEC-11.29.1` `GET /` (`landing`) must fetch the public render context and the application list concurrently, so the
  miss cost is the slower of the two.
- `SPEC-11.29.2` The landing application list must come from a fresh cookie-forwarding `GET /v1/applications` call when
  the request carries a session cookie, and from the shared cookie-free `public_applications` cache otherwise, because
  the anonymous list omits entitlement-restricted applications.
- `SPEC-11.29.3` When the cookie-forwarding application fetch fails, the landing page must log the failure naming the
  endpoint, the error code and the request id, and must render without application cards; the failure must not be
  silent.
- `SPEC-11.29.4` The landing page must render through `public_shell` with `show_feedback = true`, with the page title
  label `Home` (never marketing copy), and must set the cookies from the render context on the response.
- `SPEC-11.29.5` The hero and final call-to-action links must go to `/membership` labelled "Go to Membership" for a
  signed-in visitor and to `/register` for a signed-out one (hero label "Start free trial", final label "Create your
  account"); the "See pricing" link to `/pricing` must render only when pricing is published.
- `SPEC-11.29.6` The hero trust chips must be, in order, "No credit card required", `trial_chip(trial_days)` and
  "Cancel anytime".
- `SPEC-11.29.7` `trial_chip(days)` must return `"{days}-day trial"` when `days > 0` and `"Free trial"` otherwise, never
  printing "0-day".
- `SPEC-11.29.8` `brand_or_platform(name)` must return `"The platform"` when the name is empty and the name otherwise,
  and `try_phrase(name)` must return `"Try it"` when empty and `"Try {name}"` otherwise, so no copy names a compiled-in
  product.
- `SPEC-11.29.9` The landing page must render six feature cards, in order, as (icon, title): `key` "Single sign-on";
  `credit-card` "Stripe-ready billing"; `users` "Membership and entitlements"; `shield` "MFA, magic links, trusted
  devices"; `trending-up` "Admin console"; `message-square-quote` "In-app feedback". No card may name the brand, claim
  organizations, teammates or invitations, or use an icon name unknown to `icon_is_known`.
- `SPEC-11.29.10` `hero_mascot` must render an `aspect-square` box; when `branding.mascot_src()` is `Some` it must
  render that image with `alt="Product illustration"`, without `width`, `height` or `loading` attributes, and with
  `srcset="SRC 1x, SRC2X 2x"` when `mascot_src_2x()` is `Some`.
- `SPEC-11.29.11` When no mascot is uploaded, `hero_mascot` must render the committed hero: `src` the 448-pixel WebP and
  `srcset` the 448-pixel file at 1x and the 718-pixel file at 2x (all through `asset()`), `width="718"
  height="760"`, a descriptive `alt` naming no product, and no `loading` attribute (it is the LCP element).
- `SPEC-11.29.12` `hero_mascot` must render the tagline caption (wrapped in straight double quotes) only when the
  branding tagline is non-empty.
- `SPEC-11.29.13` The "Wired into your stack" application section must render only when `app_links_allowed` is true and
  the application list is non-empty.
- `SPEC-11.29.14` Each application card must show the application's `icon_url` image (alt = display name) or the
  `package` icon, the display name, the description (empty when absent), and a "Learn more" link with
  `target="_blank" rel="noopener noreferrer"` only when `app_link(app, domain)` is `Some`.
- `SPEC-11.29.15` The newsletter section must render only when the branding record's `newsletter_url` is non-empty; it
  must be a `POST` form to that URL with a required `type=email` input named `email` (`maxlength=254`,
  `autocomplete=email`), a honeypot text input named `website` (`tabindex=-1`, `autocomplete=off`) inside an
  `sr-only` `aria-hidden` wrapper, and a "Subscribe" submit button, and must load no script.
- `SPEC-11.29.16` The newsletter blurb must be "{brand} news and release notes, straight to your inbox." when branded
  and "News and release notes, straight to your inbox." when not.
- `SPEC-11.29.17` The final call-to-action sentence must be `try_phrase(brand)`, a space, `trial_phrase(trial_days)`
  and ". Bring your team along.".

### 11.30 Not-found and unknown-host pages

- `SPEC-11.30.1` `not_found_content()` must render a "404" mark, an `<h1>` "Page not found" and a "Back home" link to
  `/`, and every route that decides it has nothing to serve must reuse it.
- `SPEC-11.30.2` The router fallback `not_found` must answer status 404 (never a soft 200) with the branded page inside
  `public_shell` with `show_feedback = false` and the title "Not found".
- `SPEC-11.30.3` `UNKNOWN_HOST_HEADER` must equal `x-bunyip-unknown-host`.
- `SPEC-11.30.4` `unknown_host_gate` must pass a request straight to the next handler when its path starts with
  `/assets/` or `/brand/`, equals `/favicon.ico`, or the request lacks `UNKNOWN_HOST_HEADER`.
- `SPEC-11.30.5` For every other request that carries `UNKNOWN_HOST_HEADER` the gate must answer status 404 with
  `unknown_host_content(cfg.apex_url(), cfg.app_domain)` inside `document("Not found", ...)`, taking only the config so
  rendering can never call `/v1`.
- `SPEC-11.30.6` `unknown_host_content` must render the brand mark and name, "404", "Page not found" and "This address
  doesn't exist or is temporarily unavailable.", must not use `public_shell`, and must contain no host-relative link.
- `SPEC-11.30.7` When the apex URL is `Some`, `unknown_host_content` must render a "Go to {domain}" link to it and a
  paragraph with `data-redirect-to=APEX` and `data-redirect-after="10000"` reading "Taking you to {domain}" followed by
  an ellipsis; when it is `None` it must render neither a link nor a redirect.
- `SPEC-11.30.8` The unknown-host gate must be layered after the router fallback and inside both the CSRF and CSP
  layers, so its response carries the CSP.

### 11.31 Pricing page

- `SPEC-11.31.1` `GET /pricing` must answer status 404 with the shared not-found content (title "Not found",
  `show_feedback = false`) unless the pricing payload is published (enabled and at least one tier resolved to a price).
- `SPEC-11.31.2` A published pricing page must render with title "Pricing" and `show_feedback = true`, using the
  Stripe-enabled flag from `AppState::stripe_enabled()` and the signed-in state of the visitor.
- `SPEC-11.31.3` The pricing grid width class must be `max-w-md` for 0 or 1 tiers, `md:grid-cols-2 max-w-4xl` for 2 and
  `md:grid-cols-3 max-w-4xl` for 3 or more.
- `SPEC-11.31.4` The page must render one card per tier in the API's order, titled `tier_name(tier)`, with the
  description "Everything around the product, nothing in it", the price `format_stripe_amount(Some(amount), currency)`,
  the period `price_period(interval)`, the five `PERSONAL` bullets and the line "Grace period if payment fails"; no
  amount, period or tier may be a literal.
- `SPEC-11.31.5` `card_value_line(is_lifetime, trial_days)` must return "Price locked for life when you join" when the
  tier is Lifetime or `trial_days <= 0`, and "Free {n}-day trial, then price locked for life" otherwise.
- `SPEC-11.31.6` `scarcity_line(slots, available)` must return "Only 1 spot left" for `Some(1)` when available, "Only
  {n} spots left" for `Some(n)` with `n > 0` when available, and the empty string otherwise.
- `SPEC-11.31.7` Each card's call to action must be a disabled "Sold out" button when the tier is not available; else,
  when Stripe is enabled, a link labelled "Go to Membership" to `/membership` for a signed-in visitor or "Sign up" to
  `/register` otherwise; else a disabled "Payment is not configured" button.
- `SPEC-11.31.8` The scarcity line must render only when non-empty.
- `SPEC-11.31.9` The page subhead must be the tier-agnostic "The business layer for your PSA. No credit card required."
  and must not print one tier's trial length as global.
- `SPEC-11.31.10` `trial_phrase(days)` must return `"free for {days} days"` when `days > 0` and `"free"` otherwise.

### 11.32 Our story, roadmap and legal pages

- `SPEC-11.32.1` `GET /our-story` must render an `<h1>` "Our Story" and two sections, the first headed
  `why_heading(brand)` and the second "The business shell", with the page title "Our Story" and `show_feedback = true`.
- `SPEC-11.32.2` `why_heading(brand)` must return "Why this exists" when `brand` is empty and `"Why {brand}?"`
  otherwise, and the story copy must use the brand name, or "The platform" when it is empty, as its subject.
- `SPEC-11.32.3` `GET /roadmap` must render an `<h1>` "Roadmap" and three sections, in order "Shipping soon", "Planned"
  and "Exploring", each rendering its two `(title, description)` cards from the matching constant, with the page title
  "Roadmap" and `show_feedback = true`.
- `SPEC-11.32.4` `GET /terms` must render an `<h1>` "Terms of Service", the line "Last updated: " + `POLICY_LAST_UPDATED`,
  and seven sections in this order: "1. Acceptance of Terms", "2. Description of Service", "3. Membership and Payment",
  "4. Grace Period", "5. Acceptable Use", "6. Limitation of Liability", "7. Contact", with the page title "Terms of
  Service".
- `SPEC-11.32.5` `GET /privacy` must render an `<h1>` "Privacy Policy", the line "Last updated: " +
  `POLICY_LAST_UPDATED`, and six sections in this order: "1. Introduction", "2. Information We Collect", "3. How We Use
  Your Information", "4. Data Security", "5. Your Rights", "6. Cookies", with the page title "Privacy Policy".
- `SPEC-11.32.6` The legal pages must name the service by `cfg.domain_or_localhost()`, and their contact links must be
  `mailto:support@{domain}` on the terms page and `mailto:privacy@{domain}` on the privacy page.
- `SPEC-11.32.7` `POLICY_LAST_UPDATED` must be changed only in the same commit that reviews the policy bodies for
  accuracy, never to make the page look fresh.

### 11.33 Feedback page

- `SPEC-11.33.1` `sanitize_page_path(raw)` must trim `raw` and return it only when it starts with `/` and is at most 255
  bytes long, and `None` otherwise (an absent value, never a rewritten one).
- `SPEC-11.33.2` `GET /feedback` must render the form with the title "Feedback" and `show_feedback = false`, taking the
  hidden `page_path` from `?from=` through `sanitize_page_path` and rendering no hidden input when it yields `None`.
- `SPEC-11.33.3` For a signed-in visitor `GET /feedback` must pre-fill Name with the user's first and last name trimmed,
  with empty halves omitted and the rest joined by one space, and Email with the user's email; an anonymous visitor
  must get empty fields.
- `SPEC-11.33.4` The form must be `<form method="post" action="/feedback" enctype="multipart/form-data" novalidate
  data-feedback-form>` with these controls: `name` (`maxlength=100`), `email` (`type=email`, `maxlength=254`),
  `subject` (`maxlength=200`), tag checkboxes named `tags` with the values Bug, Feature, Flow and Idea, a honeypot
  `website` input in a `hidden` wrapper (`tabindex=-1`, `autocomplete=off`), a `required` `aria-required` textarea
  `message` (`maxlength=16000`), and a multiple file input `attachments` accepting
  `image/png,image/jpeg,image/webp,image/gif,text/plain`.
- `SPEC-11.33.5` Each of the name, email, subject and message inputs must carry `aria-describedby="FIELD-error"` and
  `aria-invalid` from `aria_invalid(error present)`, followed by its `field_error_slot`, and the form must show the
  attachment hint "PNG, JPEG, WebP, GIF, or plain text. Up to 3 files, 5 MB each.".
- `SPEC-11.33.6` The `/feedback` POST route's body limit (`FEEDBACK_BODY_LIMIT_BYTES`) must be 16 MiB, applied to that
  route only.
- `SPEC-11.33.7` `read_feedback_multipart` must start from `page_path = "/feedback"` and map the text parts `name`,
  `email`, `subject`, `message` and `website` verbatim (lossy UTF-8), replace `page_path` only when
  `sanitize_page_path` yields `Some`, collect each non-empty trimmed `tags` part in order, and ignore any other text
  field.
- `SPEC-11.33.8` For a file part, `read_feedback_multipart` must skip a zero-length part, then return
  `Err("Each attachment must be 5 MB or smaller. \"NAME\" exceeds the limit.")` for a part over 5 MiB, then
  `Err("Up to 3 attachments only.")` when 3 attachments are already held, then `Err("Only PNG, JPEG, WebP, GIF, and
  plain text files are allowed.")` when the part's content type (default `application/octet-stream`) is not one of
  `image/png`, `image/jpeg`, `image/webp`, `image/gif`, `text/plain`.
- `SPEC-11.33.9` An accepted attachment's filename must be reduced to its final path component, falling back to
  `attachment`, so no path separator reaches the API.
- `SPEC-11.33.10` A multipart read failure must return `Err("Could not read form: {e}")` (next-field failure) or
  `Err("Could not read field: {e}")` (field-body failure), and the failure cause must be logged with the error.
- `SPEC-11.33.11` `POST /feedback` validation must run in this order and stop at the first failure: Name (checked only
  when non-blank) with `trim_bounded(.., "Name", 100)`; Email (only when non-blank) with `validate::email`; Subject
  (only when non-blank) with `trim_bounded(.., "Subject", 200)`; Message, which must be non-blank ("Please enter a
  message.") and at most 16000 characters ("Message must be 16000 characters or fewer").
- `SPEC-11.33.12` A field validation failure must redraw the form with the message in that field's own inline slot
  (keyed by the input id), the visitor's input preserved (fields and checked tags) and the captured `page_path`
  preserved unless it is the default `/feedback`.
- `SPEC-11.33.13` A multipart read or attachment-ceiling failure must redraw the form with a top-of-form error banner
  and an empty draft; a failure of `submit_feedback` must redraw with a banner holding `e.user_message()` and the draft
  preserved.
- `SPEC-11.33.14` On success `POST /feedback` must render the thank-you state in place of the form (no `<form>`),
  headed "Thanks. We read everything.", with a "Send more feedback" link to `/feedback?from=ENCODED` (or `/feedback`
  when the path is the default) and a "Back to home" link to `/`.
- `SPEC-11.33.15` `POST /feedback` must submit with the visitor's forwarded session cookie, when present, and must pass
  the honeypot `website` value to the API.

### 11.34 Documentation pages

- `SPEC-11.34.1` The embedded documentation set must be exactly `getting-started` ("Getting Started"),
  `downloading-apps` ("Downloading Apps") and `membership` ("Membership & Access"), compiled in from
  `bunyip-web/src/skin/docs/*.md`, each non-empty, with unique slugs; internal developer runbooks must not be surfaced
  under `/docs`.
- `SPEC-11.34.2` `render_markdown` must enable tables, strikethrough, footnotes and task lists and must drop every raw
  `Html` and `InlineHtml` event, so embedded or fetched markdown cannot inject live HTML.
- `SPEC-11.34.3` Embedded documentation links must be relative (no `](/` site-root path), and the `downloading-apps`
  document must contain the `<username>` placeholder in a fenced code block.
- `SPEC-11.34.4` `GET /docs` must render title "Docs" with `show_feedback = true`, an `<h1>` "Documentation", the
  `docs_index_note` line, and a link `/docs/{slug}` per embedded guide, fetching the documented-application list
  concurrently and rendering even when that fetch fails.
- `SPEC-11.34.5` On `GET /docs`, when the documented-application list failed, the page must render an "Application
  documentation" heading with `error_box_for("Could not reach the API to load application documentation.", e)`; when
  it is empty, no application heading or link; otherwise a link `/apps/{slug}/docs` per application labelled with its
  display name, or its slug when the display name is empty.
- `SPEC-11.34.6` `docs_layout` must render a two-column shell (menu above the article below `md`, beside it from `md`)
  around `docs_menu`.
- `SPEC-11.34.7` `docs_menu` must render a `<nav aria-label="Documentation sections">` with a "Docs home" link to
  `/docs`, a "Guides" heading with a `/docs/{slug}` link per guide, and then: when the documented-application list is
  unavailable, the text "Could not load application documentation."; when it is empty, nothing; otherwise an
  "Applications" heading with a `/apps/{slug}/docs` link per application.
- `SPEC-11.34.8` In `docs_menu`, the link whose `href` equals the active path must carry `bg-accent
  text-accent-foreground` and `aria-current="page"`, and every other link must carry neither.
- `SPEC-11.34.9` `GET /docs/{slug}` for an unknown slug must answer status 404 with "Document not found", "No such
  doc." and a "Back to documentation" link to `/docs`, rendered inside the same `docs_layout`.
- `SPEC-11.34.10` `GET /docs/{slug}` for a known slug must render the markdown inside `<article
  class="docs-article">` with the page title "{doc title} " + the middle dot character (U+00B7) + " Docs" and the
  scoped `DOCS_CSS` in a `<style>`.
- `SPEC-11.34.11` Personalization must replace the escaped token `&lt;username&gt;` in the rendered HTML with the
  signed-in reader's email, HTML-escaped and wrapped in `<span class="docs-fill">`, only when a user is signed in, the
  document contains the token and the query `raw` is not true.
- `SPEC-11.34.12` When the document has the token and a user is signed in, the page must show a note above the article:
  "Personalized with your {brand} username. " (or "Personalized with your username. " when unbranded) and a "Show the
  generic version" link to `/docs/{slug}?raw=1` when personalized, else "Showing the generic version. " and a
  "Personalize with your username" link to `/docs/{slug}`; otherwise no note.

### 11.35 Application documentation pages

- `SPEC-11.35.1` `app_display_name(slug, apps, documented)` must return the documented-list entry's display name when it
  matches the slug and is non-empty, else the public catalog entry's display name, else the slug.
- `SPEC-11.35.2` `GET /apps/{slug}/docs` and `GET /apps/{slug}/docs/{doc_slug}` must fetch the render context, the
  public application list and the documented-application list concurrently.
- `SPEC-11.35.3` `GET /apps/{slug}/docs` must render the heading "{app name} documentation" inside `docs_layout` with the
  title "{app name} docs", and show one link `/apps/{slug}/docs/{doc.slug}` per page, or the empty state "No
  documentation for this app yet." when the list is empty.
- `SPEC-11.35.4` When `calls::app_docs` fails, `GET /apps/{slug}/docs` must log at error level the endpoint, slug,
  message and code, and must render `error_box_for("Could not reach the API to load documentation.", e)` in place of
  the list instead of an empty state; it must not answer 500.
- `SPEC-11.35.5` `GET /apps/{slug}/docs/{doc_slug}` must render, on success, a back link "{app name} documentation" to
  `/apps/{slug}/docs` and the document body through `render_markdown` in `<article class="docs-article">` with the
  scoped `DOCS_CSS`, titled "{doc title} " + the middle dot character (U+00B7) + " {app name} docs".
- `SPEC-11.35.6` When `calls::app_doc` fails, `GET /apps/{slug}/docs/{doc_slug}` must log at warn level the endpoint,
  slug, doc slug, message and code, and render "Document not found" / "No such page." with a "Back to {app name} docs"
  link, inside `docs_layout`, with the title "Docs".

### 11.36 Static assets and generated artifacts

- `SPEC-11.36.1` Every `/assets/...` URL written into markup must be produced by `asset()` so it carries
  `?v=ASSET_VERSION`; a bare `src="/assets/..."` or `href="/assets/..."` literal in production view code is forbidden,
  because `/assets` is served immutable for one year.
- `SPEC-11.36.2` Every `/assets/<file>` string literal with a static extension (`.webp`, `.png`, `.jpg`, `.jpeg`,
  `.svg`, `.ico`, `.js`, `.css`, `.woff`, `.woff2`, `.ttf`, `.otf`) in production source must name a file that exists
  under `bunyip-web/assets/`.
- `SPEC-11.36.3` `bunyip-web/assets/styles.css` is generated: it must be byte-identical to the output of
  `bun run build:css` (`tailwindcss --input input.css --output assets/styles.css --minify`) over `input.css` and the
  `@source` crates, must never be edited by hand, and must declare the `--color-amber-<step>` `oklch(...)` palette and
  the `text-brand-primary-800` rule that the contrast tests read.
- `SPEC-11.36.4` `bunyip-web/assets/vendor/htmx-2.0.3.min.js` must be byte-identical to the published htmx 2.0.3
  distribution (sha384 `0895/pl2MU10Hqc6jd4RvrthNlDiE9U1tWmX7WRESftEDRosgxNsQG/Ze9YMRzHq`) and must be served from this
  origin, never from a CDN.
- `SPEC-11.36.5` The fonts Inter and JetBrains Mono must be self-hosted as `latin` and `latin-ext` `woff2` files under
  `bunyip-web/assets/vendor/fonts/`, each family shipped with its SIL Open Font License 1.1 text
  (`inter-OFL.txt`, `jetbrains-mono-OFL.txt`) beside it.
- `SPEC-11.36.6` The committed icon set must exist as `favicon.ico` (16x16 and 32x32 images), `favicon-16x16.png`,
  `favicon-32x32.png`, `favicon-48x48.png`, `favicon-192x192.png`, `favicon-512x512.webp` and `apple-touch-icon.png`
  (180x180), the fallbacks of `SPEC-11.22.11`.
- `SPEC-11.36.7` The committed hero art must exist as `bunyip-hero-448.webp` and `bunyip-hero-718.webp` (718 by 760
  pixels), the fallbacks of `SPEC-11.29.11`.
- `SPEC-11.36.8` `bunyip-web/assets/mokosh-logo.png` must remain at that path, because a committed migration stores
  `/assets/mokosh-logo.png` as an OAuth client logo URI for the consent screen.
- `SPEC-11.36.9` `bunyip-web/assets/.gitkeep` must keep the `assets` directory present in a fresh checkout.

### 11.37 Shared client script (app.js)

- `SPEC-11.37.1` `window.bunyipToast(msg, kind)` must append a pill to `#bunyip-toast-root`, using the palette for
  `success`, `error` or `info` and the `info` palette for any other or missing kind, and must do nothing when the
  toast root is absent.
- `SPEC-11.37.2` Before appending, `bunyipToast` must remove the oldest pills until fewer than 5 remain, so the column
  never exceeds 5 pills.
- `SPEC-11.37.3` Every toast pill's background must be opaque (a `bg-*` token without an alpha suffix).
- `SPEC-11.37.4` A toast pill must have `role="alert"` for kind `error` and `role="status"` otherwise, and must set the
  message as text (`textContent`, in a `whitespace-pre-line` span), never as HTML.
- `SPEC-11.37.5` Every toast pill must contain a `<button type="button" aria-label="Dismiss">` that removes the pill
  through the same fade-out sequence the timer uses (opacity 0 then detach after 250 ms if still attached).
- `SPEC-11.37.6` A toast of kind `error` must have no auto-dismiss timer; any other kind must auto-dismiss after 8000 ms
  when the message has more than 2 whitespace-separated words and after 5000 ms otherwise.
- `SPEC-11.37.7` On load, when the address carries `toast_ok` and/or `toast_err`, app.js must delete both parameters
  from the address bar with `history.replaceState` (path, remaining query and hash), then show the `toast_ok` value as
  a `success` toast and the `toast_err` value as an `error` toast, in that order.
- `SPEC-11.37.8` If the location cannot be parsed, or `replaceState` throws, app.js must log a `console.warn` line
  prefixed `bunyip:` naming the lost effect, and in the `replaceState` case must still show the toast.
- `SPEC-11.37.9` An `input` event on `input[data-otp-autosubmit]` whose value matches `^[0-9]{6}$` must submit its form
  (via `requestSubmit`, else `submit`) only when the form's `data-otp-submitting` flag is unset and `checkValidity()`
  passes, and must set that flag to `1` before submitting; a value that does not match (including a dashed recovery
  code) must not submit.
- `SPEC-11.37.10` A click outside an open `details[data-menu]`, and the Escape key anywhere, must remove the `open`
  attribute from every open `details[data-menu]`.
- `SPEC-11.37.11` A submit event on a form with a non-empty `data-confirm` attribute must call `window.confirm` with
  that text in the capture phase and must call `preventDefault` when the user cancels.
- `SPEC-11.37.12` A click inside `[data-copy]` must copy the element's `data-copy` value with the Clipboard API; on
  success it must set the label to "Copied" for 1500 ms, show a `success` toast "Copied to clipboard" and unlock the
  saved gate; on rejection it must set the label to "Copy failed" for 1500 ms and show an `error` toast "Copy failed".
- `SPEC-11.37.13` When the Clipboard API is unavailable, a `[data-copy]` click must select the contents of the button's
  previous sibling element, set the label to "Press Ctrl+C" for 3000 ms and unlock the saved gate.
- `SPEC-11.37.14` A click inside `[data-download-file]` must download the attribute's text as a `text/plain;charset=utf-8`
  file named by `data-download-filename` (default `download.txt`), revoke the object URL after 500 ms, show a `success`
  toast "File downloaded" and unlock the saved gate; on a thrown error it must show an `error` toast "Download failed".
- `SPEC-11.37.15` Unlocking the saved gate must, inside the nearest `[data-saved-gate]`, set `hidden = false` and remove
  `aria-hidden` on `[data-saved-gate-link]`, and set `hidden = true` and `aria-hidden="true"` on
  `[data-saved-gate-hint]`.
- `SPEC-11.37.16` A click inside `[data-dialog-open]` must call `showModal()` on the `<dialog>` whose id is the
  attribute value when it exists, and a click inside `[data-dialog-close]` must close the enclosing `<dialog>`.
- `SPEC-11.37.17` A click on `[data-feedback-link]` must set its `href` to `/feedback?from=` + the URL-encoded current
  `pathname + search`.
- `SPEC-11.37.18` Each element with `data-redirect-to` and a `data-redirect-after` that parses to a number `>= 0` must
  navigate `location.href` to the target after that many milliseconds, and each element with `data-reload-after` that
  parses to a number `>= 0` must reload the page after that many milliseconds; an invalid delay must do nothing.
- `SPEC-11.37.19` A `change` event on `[data-submit-on-change]` must submit its enclosing form.
- `SPEC-11.37.20` app.js must set `data-scrollbars="auto"` on `<html>` and must set `data-scrollbar-active` on a scroll
  container when it scrolls, when a non-touch pointer is within 14 px of its scrollbar strip, and during a pointer drag
  that began in that strip.
- `SPEC-11.37.21` app.js must remove `data-scrollbar-active` 6000 ms after the last activity on that container, unless
  the pointer is still within its zone or dragging it, and must clear the hover state when the pointer leaves the window
  and the drag state on `pointerup`, `pointercancel` or a pointer move with no button held.
- `SPEC-11.37.22` On a page with `[data-feedback-form]`, the script must validate the email field with these exact
  messages, in this order: empty is valid; over 254 characters "Email must be 254 characters or fewer"; no `@` "Email must
  contain an @"; empty local part or domain "Email must have characters on both sides of @"; no dot in the domain "Email
  domain must contain a dot"; whitespace "Email must not contain whitespace"; and the message field with "Please enter a
  message." when blank, matching the server's messages.
- `SPEC-11.37.23` On that page the script must validate each field on `blur`, re-validate on `input` only while the
  field has `aria-invalid="true"`, set `aria-invalid` to `true` or `false` on the input, and fill or clear and
  hide/show the field's `[data-field-error]` slot.
- `SPEC-11.37.24` On that page the script must validate attachments against these limits and messages: more than 3 files
  "Up to 3 files only."; a type outside `image/png`, `image/jpeg`, `image/webp`, `image/gif`, `text/plain` "Only PNG,
  JPEG, WebP, GIF, and plain text files are allowed."; a file over 5 MiB `"NAME" is larger than 5 MB.`.
- `SPEC-11.37.25` On that page the script must label the picker "No file chosen", "1 file selected" or "N files
  selected", render one preview chip per file (image preview via object URL, or a "TXT" box for non-images) with the file
  size formatted as bytes, KB or MB, and revoke the object URLs when the previews are cleared.
- `SPEC-11.37.26` On submit the script must validate every field and attachment, mark each invalid one, call
  `preventDefault` and focus the topmost invalid control when any is invalid; otherwise it must block a second submit
  while `data-feedback-submitting` is `1`, and on the first submit set that flag, disable the submit button, reveal the
  spinner and set the label to "Sending" followed by an ellipsis.

### 11.38 Theme, live-event and list-keyboard scripts

- `SPEC-11.38.1` theme.js must read the theme choice from `localStorage` key `theme-storage` as JSON
  `{state:{theme, highContrast}, version:0}` and, before first paint, add to `<html>` the class `dark` or `light`
  (for stored `system` or no value, `dark` when `prefers-color-scheme: dark` matches, else `light`; for a stored
  `dark` or `light`, that value) and `high-contrast` when stored.
- `SPEC-11.38.2` If the stored theme cannot be read, theme.js must log a `console.warn` line prefixed `bunyip:` and fall
  back to `system`; if applying the theme throws, it must log a `console.error` line prefixed `bunyip:` and leave the
  page in the default theme.
- `SPEC-11.38.3` A click inside `[data-theme-toggle]` must switch `<html>` between `dark` and `light` and persist
  `{theme, highContrast}`; a click inside `[data-contrast-toggle]` must toggle `high-contrast` and persist it together
  with the stored theme (default `system`).
- `SPEC-11.38.4` If persisting the theme fails, theme.js must still apply the change to the current page and log a
  `console.warn` line prefixed `bunyip:`.
- `SPEC-11.38.5` sse.js must read the API origin from `data-api-origin` on its own script tag and do nothing when the
  attribute is missing or `EventSource` is unsupported.
- `SPEC-11.38.6` sse.js must open `new EventSource(origin + '/v1/events', {withCredentials: true})`; if opening throws
  it must log a `console.error` line prefixed `bunyip:` stating that the tab updates only on navigation.
- `SPEC-11.38.7` sse.js must reload the page on the events `claims_changed`, `profile_changed`,
  `applications_changed` and `resync`, and on `session_revoked` must navigate to
  `/login?toast_err=Session%20ended%20by%20an%20administrator.`.
- `SPEC-11.38.8` sse.js must close the stream on `pagehide`, and log a `console.warn` line prefixed `bunyip:` if
  closing throws.
- `SPEC-11.38.9` admin-users.js must, on `keydown` of a `role=radio` control inside `[data-segmented]`, move focus to
  and click the next radio on ArrowRight or ArrowDown and the previous on ArrowLeft or ArrowUp, wrapping at both ends and
  calling `preventDefault`.
- `SPEC-11.38.10` admin-users.js must, on a Space key press on `[data-sort-header]`, call `preventDefault` and click it.

### 11.39 Form and list scripts

- `SPEC-11.39.1` password-field.js must bind each `[data-pw-toggle]` button once, so that a click flips the target
  input (found by id) between `type=password` and `type=text` and sets `aria-pressed` to `true`/`false` and
  `aria-label` to "Hide password"/"Show password".
- `SPEC-11.39.2` password-field.js must, for each `form[data-pw-guard]` that contains `[data-pw-new]`,
  `[data-pw-confirm]` and `[data-pw-guard-msg]`, cancel the submit with `preventDefault`, fill and show the message and
  focus the failing field when the new password has fewer than 12 characters or lacks a lowercase letter, an uppercase
  letter, a digit or a non-alphanumeric character (message "Password must be at least 12 characters and include upper
  and lowercase letters, a digit and a special character.", focus on the new field), or when the confirmation differs
  (message "Passwords don't match.", focus on the confirm field); otherwise it must clear the message and allow the
  submit.
- `SPEC-11.39.3` password-field.js must clear and hide the guard message on every `input` in the new or confirm field,
  and must bind each form once.
- `SPEC-11.39.4` password.js must act only when `#password` exists and has not been initialised, and must set the rows
  `#pw-len` (length at least 12), `#pw-case` (lowercase and uppercase) and `#pw-digit` (digit and non-alphanumeric) to
  `pending` for an empty value, `pass` when the rule holds and `fail` otherwise, mirroring the server's `password_ok`.
- `SPEC-11.39.5` password.js must check the typed password against the Pwned Passwords range API by hashing it with
  SHA-1 in the browser, sending only the first 5 hexadecimal characters to
  `https://api.pwnedpasswords.com/range/{prefix}`, matching the remaining 35 case-insensitively, and never sending the
  password or the full hash; the lookup must be debounced by 500 ms and a response for a superseded value must be
  ignored.
- `SPEC-11.39.6` `#pw-breach` must be `fail` when the suffix is found, `pass` when it is not, and `pending` while the
  lookup is scheduled or in flight; `#pw-breach-help` must be visible only in the `fail` state; a row with
  `data-label-STATE` must show that label for the state.
- `SPEC-11.39.7` When the breach lookup cannot run (no WebCrypto, a non-OK response or a request error), password.js
  must log a `console.warn` line prefixed `bunyip: HaveIBeenPwned lookup unavailable`, set `#pw-breach` to `pending`
  and stop blocking the submit on it.
- `SPEC-11.39.8` password.js must disable the form's submit button unless the three local rules pass, the breach row is
  `pass` (or `pending` with the lookup known unavailable), and the confirmation is non-empty and equal to the password,
  and must refresh that state when a breach result lands.
- `SPEC-11.39.9` password.js must keep `#pw-confirm-msg` empty while the confirmation is empty and otherwise show a
  check-mark message "Passwords match" in the success colour or a cross-mark message "Passwords do not match" in the
  destructive colour, and must evaluate a value preserved across a server re-render on load.
- `SPEC-11.39.10` avatar-picker.js must initialise each `[data-avatar-picker]` once, reading `data-upload-url`,
  `data-remove-url`, `data-max-bytes` (default 2097152) and `data-max-edge` (default 512), and must do nothing on a page
  without a picker.
- `SPEC-11.39.11` For a chosen or dropped file, avatar-picker.js must reject a file larger than `data-max-bytes` with
  "That image is {size}. The limit is 2 MB." and a file whose first bytes are not a PNG, JPEG, GIF or WebP signature
  (independent of the declared MIME type) with "That file is not a PNG, JPEG, WebP, or GIF image.", showing the message
  in `[data-avatar-error]` and uploading nothing.
- `SPEC-11.39.12` For an accepted file, avatar-picker.js must preview it from a `data:` URL, centre-crop it to a square
  of at most `data-max-edge` pixels on a white background, encode it as JPEG at quality 0.85, and upload that;
  if encoding throws it must log a `console.warn` line prefixed `bunyip:`, and if encoding throws or yields an empty
  blob it must upload the original validated file instead.
- `SPEC-11.39.13` avatar-picker.js must upload with `XMLHttpRequest` `POST` to `data-upload-url` as multipart form data
  with the file under the field `avatar` (`avatar.jpg` for the re-encoded blob), header `Accept: application/json`,
  disable the change and remove buttons while busy, and publish progress in the CSS variable `--avatar-progress`; an
  empty payload must show "That image could not be read. Please try a different file." without a request.
- `SPEC-11.39.14` On a 2xx upload response avatar-picker.js must repaint every `[data-avatar-slot]` with
  `/me/avatar?v=` + the current time in milliseconds, show the remove button, clear the error and show a `success`
  toast "Profile photo updated".
- `SPEC-11.39.15` On a non-2xx upload response avatar-picker.js must show the JSON `error` member when present and
  "Upload failed. Please try again." otherwise (logging a `console.warn` line prefixed `bunyip:` when the body is not
  JSON); on a transport error it must show "Upload failed. Check your connection and try again.".
- `SPEC-11.39.16` The remove button must, only when `data-has-avatar` is `1` and `window.confirm("Remove your profile
  photo? This cannot be undone.")` is accepted, `POST` to `data-remove-url`; on 2xx it must clear every avatar slot to
  the initial, hide the remove button and show a `success` toast "Profile photo removed", and on a non-2xx status or
  transport error it must show "Could not remove the photo. Please try again.".
- `SPEC-11.39.17` While a drag is over the trigger avatar-picker.js must toggle `is-dragging` on the picker root, and
  once per page it must cancel the default action of window-level `dragover` and `drop` so a missed drop does not
  navigate away.
- `SPEC-11.39.18` app-reorder.js must act on each `[data-reorder-list]` and start a drag only from a
  `[data-reorder-handle]` (a drag that did not begin on the handle must be cancelled), moving the dragged
  `[data-reorder-item]` live during `dragover` and persisting on `dragend`.
- `SPEC-11.39.19` ArrowUp or ArrowDown on a focused `[data-reorder-handle]` must move its row one place up or down when
  a neighbour exists, call `preventDefault`, keep focus on the handle and persist.
- `SPEC-11.39.20` Persisting must `POST` `{"ordered_ids":[<data-app-id of each item in DOM order>]}` as JSON with
  `credentials: same-origin` to the list's `data-reorder-action` (doing nothing when it is absent); a 2xx response must
  show a `success` toast "Order saved".
- `SPEC-11.39.21` When persisting fails (non-2xx or a transport error) app-reorder.js must log a `console.error` line
  prefixed `bunyip:`, show an `error` toast "Could not save the new order", and after 900 ms navigate to the current URL
  with the query parameter `toast_err` set to that message (so the fresh page re-raises it), or plain-reload with a
  `console.warn` when the URL cannot be parsed.

## 12. Web handlers

### 12.1 Shared admin handler conventions

Common behavior of every module under `bunyip-web/src/handlers/admin/`.

- `SPEC-12.1.1` Every admin page and action handler in these modules must call `admin_guard` before any other work. An
  unauthenticated request must receive a 303 redirect to `/login`, and an authenticated account whose role is not Admin
  must receive a 303 redirect to `/dashboard`; both responses must relay the session cookies the guard set.
- `SPEC-12.1.2` An action handler that changes state must answer with a 303 redirect (or, for `POST
  /admin/applications/reorder`, a bare status), never with 200, and must relay `c.set_cookies` on every success and
  failure path so a refreshed session is not dropped.
- `SPEC-12.1.3` `refuse_non_super_admin` must return `None` for a super admin and otherwise a 303 redirect to
  `{back}?toast_err=Only%20the%20super%20admin%20can%20change%20this` carrying the session cookies. The handler must
  stop before calling the API. The API enforces the same gate; the redirect is the friendlier message only.
- `SPEC-12.1.4` `secret_field_note` must return, for a non-editable field, the text "Owned by the {storage} provider
  (SECRETS_STORAGE={storage}), which bunyip cannot write. Edit the file {ENV}_FILE points at (./secrets/{file}) and
  restart bunyip-api. Saving here returns a conflict.". For an editable field with a stored value it must return "A
  value is set in the {provider} provider. Leave blank to keep it, or type a new one to replace it."; with no stored
  value it must return "No value set. Saved to the {provider} provider.". `{provider}` must be `declared` when the
  storage name is empty.
- `SPEC-12.1.5` `with_attachment_hardening` must add exactly the headers `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: sandbox` and `Referrer-Policy: no-referrer` to every binary-proxy response (feedback
  attachment, feedback CSV export, account backup download).
- `SPEC-12.1.6` `title_case` must split an action name on `_`, replace a word that case-insensitively equals `api`,
  `oci`, `ip`, `smtp` or `oauth` with `API`, `OCI`, `IP`, `SMTP` or `OAuth`, upper-case the first character of every
  other word, and join the words with a single space.
- `SPEC-12.1.7` Every paginated admin list handler must treat a missing `page` as 1 and clamp any value below 1 to 1.
  `PageQuery` must carry `page` (u32) and the optional `tier` filter.
- `SPEC-12.1.8` A list page whose API fetch fails must render an error box naming the failed load and carrying the
  underlying error, and must not render the empty-state text, the pager total or a zero count in its place.

### 12.2 Admin dashboard

- `SPEC-12.2.1` `GET /admin` must fetch platform stats, system health (datasets) and the 5 newest audit-log entries
  (page 1, size 5, admin-only off, no filters) concurrently, and each fetch must fail independently: a failed fetch must
  not prevent the page from rendering.
- `SPEC-12.2.2` When the stats fetch succeeds the page must render four tiles: "Total Users", "Active Memberships",
  "Active Apps" (`{active_applications}/{total_applications}`) and "Past Due". When it fails the page must render the
  error box "Could not reach the API." with the underlying error and no tiles.
- `SPEC-12.2.3` The page must show the "This environment has no applications yet" prompt linking to `/admin/seed` only
  when the stats fetch succeeded and `total_applications` is 0. A failed stats fetch must not show the prompt.
- `SPEC-12.2.4` The Datasets card must render on every load. A failed health fetch must show the error box "Could not
  reach the API to load dataset health."; an empty list must show "No datasets are configured."; otherwise one row per
  dataset.
- `SPEC-12.2.5` A dataset row must show the badge "Not configured" when the dataset is not configured, else "Missing"
  when it is not present, else "Stale" when stale, else "Fresh", in that precedence. It must show the age as `{n} day
  old` for 1 and `{n} days old` otherwise, only when an age is known.
- `SPEC-12.2.6` The Recent Activity card must list the fetched entries with the action rendered by `title_case`, the
  actor email (or "System" when none) and the relative time. A failed fetch must show "Could not reach the API to load
  recent activity."; an empty result must show "No recent activity.".

### 12.3 Applications list, field toggles, reorder and delete

- `SPEC-12.3.1` `GET /admin/applications` must list every application with its display name, slug, an Active toggle, a
  Maintenance toggle and an Edit link to `/admin/applications/{id}/edit`. A failed fetch must show "Could not reach the
  API to load applications." with the cause; an empty list must show "No applications.". A `?error=` query value must
  render as an error box above the list.
- `SPEC-12.3.2` Each toggle must post to `/admin/applications/{id}/field` with hidden `field` (`is_active` or
  `maintenance_mode`) and hidden `value` set to the opposite of the current state (`true` when currently off).
- `SPEC-12.3.3` The surface badges of a row must be computed as: Hub when `is_active` and `is_hosted`; Binary when
  `forgejo_owner` and `pinned_release_tag` are present and, for `artifact_source` `generic_package`, a package or a repo
  is present, otherwise the repo is present; OCI when `is_active` and `oci_image_owner`, `oci_image_name` and
  `pinned_image_tag` are all present. A field is present only when it is non-empty after trimming. An absent surface
  must render the outline badge "No Hub", "No Binary" or "No OCI".
- `SPEC-12.3.4` `POST /admin/applications/{id}/field` must send the API a one-key JSON object `{field: value ==
  "true"}`. On success it must redirect to `/admin/applications`. On failure it must log a warning with `app_id`,
  `field` and the error, and redirect to `/admin/applications?error=Could%20not%20update%20application`.
- `SPEC-12.3.5` `POST /admin/applications/reorder` must accept a JSON body `{ordered_ids: [string]}` (default empty),
  answer 204 with no body on success, and answer 502 on any API failure, never a redirect, so the client script can show
  its toast and reload.
- `SPEC-12.3.6` The list page must load `app-reorder.js` itself, and the list container must carry `data-reorder-list`
  and `data-reorder-action="/admin/applications/reorder"`; every row must carry `data-reorder-item`, `data-app-id`,
  `draggable="true"` and a keyboard-focusable `data-reorder-handle` button.
- `SPEC-12.3.7` `POST /admin/applications/{id}/delete` must send the submitted `password` and `totp_code` to the API
  (both default to empty). On success it must redirect to `/admin/applications`; on failure it must redirect to
  `/admin/applications/{id}/edit?error={url-encoded API user message}`.
- `SPEC-12.3.8` Every failure of an action in `applications.rs` must be reported through the server-rendered `?error=`
  query value (shown as an error box with JavaScript disabled) and not through the client-only toast query values.

### 12.4 Application create and edit

- `SPEC-12.4.1` `GET /admin/applications/new` must render the create form with the identity fields `name`, `slug`,
  `display_name` and `container_name` (all required), the hosted checkbox on, `artifact_source` `release`, and the
  details and distribution fields empty. `POST /admin/applications` must handle the submission.
- `SPEC-12.4.2` `create_app_body` must require `name`, `display_name` and `container_name` as non-empty after trimming
  and at most 200 bytes, and `slug` valid under `validate::slug` (lowercase letters, digits and internal hyphens, at
  most 64 bytes); a violation must be returned as the form error text and the API must not be called.
- `SPEC-12.4.3` `create_app_body` must always send `is_hosted` (true for `true` or `on`), send each non-empty trimmed
  detail field (`description`, `icon_url`, `subdomain`, `version`, `source_code_url`, `release_notes_url`,
  `maintenance_message`), send `artifact_source` when non-empty, send each of `forgejo_owner`, `forgejo_repo`,
  `pinned_release_tag`, `oci_image_owner`, `oci_image_name` and `pinned_image_tag` only when non-empty and at most 200
  bytes, and send `forgejo_package` (at most 200 bytes) only when `artifact_source` is `generic_package` and it is
  non-empty.
- `SPEC-12.4.4` On a create validation error or an API error the handler must re-render the create form with the error
  box and every submitted value preserved (200 page, no redirect). On success it must redirect to `/admin/applications`.
- `SPEC-12.4.5` `GET /admin/applications/{id}/edit` must load the application list. A failed load must render an error
  box with the API user message and must not render "Application not found."; an id absent from a successful load must
  render "Application not found.". A found application must render the details and distribution form posting to
  `/admin/applications/{id}/distribution`, the surface badges, a "Manage documentation" link to
  `/admin/applications/{id}/docs`, the group assignment card and the Danger Zone, with `artifact_source` showing
  `release` when unset. A `?error=` value must render in the Danger Zone.
- `SPEC-12.4.6` The Danger Zone must be a form posting to `/admin/applications/{id}/delete` with a password field, a
  `totp_code` field and a confirmation prompt, and must ship the password-reveal script.
- `SPEC-12.4.7` `distribution_update_body` must send `artifact_source` and each trimmed non-empty distribution and
  detail field, omit blank ones so the API keeps the stored value, always send `is_hosted`, and always send
  `forgejo_package`, as the trimmed value only when `artifact_source` is `generic_package` and as the empty string
  (which clears it) otherwise.
- `SPEC-12.4.8` `POST /admin/applications/{id}/distribution` must redirect to `/admin/applications` on success and, on
  failure, re-render the edit form (200) with the API user message and the submitted values, without surface badges.
- `SPEC-12.4.9` A checkbox value must count as checked only when it is `true` or `on`; an absent checkbox must count as
  unchecked.

### 12.5 Application documentation pages

- `SPEC-12.5.1` `GET /admin/applications/{id}/docs` must load the application list and the page list. A failed
  application load must render an error box with the API user message. A failed page-list load must render "Could not
  reach the API to load documentation pages." and not "No pages yet. Add one below.". The heading must use the
  application's display name, falling back to the id when the application is not in the list. A `?error=` value must
  render as an error box.
- `SPEC-12.5.2` The docs page must render, for each documentation page, an edit form (title, slug, sort order, markdown
  body) posting to `/admin/applications/{id}/docs/{doc_id}` and a Delete form with a confirmation prompt, plus an "Add a
  page" form posting to `/admin/applications/{id}/docs`. Field ids must be unique per form through a prefix and every
  label must carry an explicit `for`.
- `SPEC-12.5.3` `POST /admin/applications/{id}/docs` and `POST /admin/applications/{id}/docs/{doc_id}` must parse
  `sort_order` with `validate::parse_i32` (blank is 0). A non-numeric or out-of-range value must redirect to
  `/admin/applications/{id}/docs?error={message}` without calling the API and must not substitute 0.
- `SPEC-12.5.4` A successful create or update must redirect to `/admin/applications/{id}/docs`. A failed create must log
  a warning with `app_id`, `slug` and the error and redirect with `?error=Could%20not%20create%20documentation%20page`;
  a failed update must log `app_id`, `doc_id` and the error and redirect with
  `?error=Could%20not%20update%20documentation%20page`.
- `SPEC-12.5.5` `POST /admin/applications/{id}/docs/{doc_id}/delete` must redirect to `/admin/applications/{id}/docs` on
  success and, on failure, log a warning with `app_id`, `doc_id` and the error and redirect with
  `?error=Could%20not%20delete%20documentation%20page`.

### 12.6 Application groups

- `SPEC-12.6.1` `GET /admin/application-groups` must list each group with its display name, slug, an Edit link to
  `/admin/application-groups/{id}/edit` and a Delete form with a confirmation prompt. A failed fetch must show "Could
  not reach the API to load application groups." with the cause; an empty list must show "No groups yet.".
- `SPEC-12.6.2` `group_body` must require `name` and `display_name` non-empty and at most 200 bytes, `slug` valid under
  `validate::slug`, `description` at most 1000 bytes (empty becomes null), `icon_url` an absolute http(s) URL of at most
  512 bytes (empty becomes null), and `sort_order` an `i32` (blank is 0; a non-numeric or out-of-range value is an
  error, never silently 0). A violation must render the form again with the message and must not call the API.
- `SPEC-12.6.3` `POST /admin/application-groups` and `POST /admin/application-groups/{id}` must redirect to
  `/admin/application-groups` on success. On an API failure they must re-render the form (200) with the API user
  message.
- `SPEC-12.6.4` `GET /admin/application-groups/{id}/edit` must show the error box "Could not reach the API to load
  application groups." when the fetch failed, "Group not found." when the fetch succeeded without that id, and otherwise
  the form headed "Edit {display_name}" prefilled with the group and posting to `/admin/application-groups/{id}`.
- `SPEC-12.6.5` `POST /admin/application-groups/{id}/delete` must redirect to `/admin/application-groups` on success
  and, on failure, log a warning with `group_id` and the error and redirect to
  `/admin/application-groups?toast_err=Could%20not%20delete%20application%20group`.
- `SPEC-12.6.6` `POST /admin/applications/{id}/group` must treat an empty or whitespace `group_id` as "ungroup" (no
  group) and otherwise send the trimmed id. On success it must redirect to
  `/admin/applications/{id}/edit?toast_ok=Application%20moved`; on failure it must log a warning with `app_id` and the
  error and redirect to `/admin/applications/{id}/edit?toast_err=Could%20not%20move%20the%20application`.
- `SPEC-12.6.7` The group assignment card must offer an "Ungrouped" option (value empty) plus one option per group with
  the current group selected, and a "Save group" button posting to `/admin/applications/{id}/group`. When the group list
  fetch failed it must instead render only the error box "Could not load application groups, so the current assignment
  can't be shown here. Reload the page to change it." with no select and no save control, so a degraded fetch can never
  clear a real assignment.

### 12.7 Entitlements and memberships

- `SPEC-12.7.1` `GET /admin/entitlements` must list every application with its display name, slug, a "Restricted" badge
  when it requires an entitlement, and a form posting hidden `value` (the opposite of the current state) to
  `/admin/applications/{slug}/restricted-toggle` with the button "Open" for a restricted application and "Restrict"
  otherwise. A failed fetch must show "Could not reach the API to load applications."; an empty list must show "No
  applications.".
- `SPEC-12.7.2` `POST /admin/applications/{slug}/restricted-toggle` must set `requires_entitlement` to `value ==
  "true"`. On success it must redirect to `/admin/entitlements?toast_ok=Entitlement%20requirement%20changed`; on failure
  it must log a warning with `slug` and the error and redirect with
  `toast_err=Could%20not%20change%20the%20entitlement%20requirement`.
- `SPEC-12.7.3` `GET /admin/users/{user_id}/entitlements` must fetch the user's granted entitlements and the application
  list independently and render each failure as its own error box ("Could not reach the API to load entitlements." /
  "...applications."), "No entitlements granted." for an empty grant list, and per application a Revoke form (when
  granted) or a Grant form (when not), each posting hidden `slug` and carrying a confirmation prompt.
- `SPEC-12.7.4` `POST /admin/users/{user_id}/entitlements/grant` and `.../revoke` must apply `verification_gate` with
  back path `/admin/users/{user_id}/entitlements` before calling the API. On success they must redirect there with
  `toast_ok` "Entitlement granted" or "Entitlement revoked"; on failure they must log a warning with `user_id`, `slug`
  and the error and redirect there with `toast_err` "Could not grant the entitlement" or "Could not revoke the
  entitlement".
- `SPEC-12.7.5` `GET /admin/memberships` must redirect (303) to `/admin/users?tier={tier}` when `tier` is exactly
  `early_adopter`, `standard`, `lifetime` or `free`, and to `/admin/users` for any other or absent value.
- `SPEC-12.7.6` `POST /admin/memberships/{user_id}/grant` and `.../revoke` must apply `verification_gate` with back path
  `/admin/users/{user_id}` before calling the API. A successful grant must redirect to
  `/admin/users/{user_id}?toast_ok=Membership%20granted` and a successful revoke to `/admin/users/{user_id}`. A failure
  must log a warning with `user_id` and the error and redirect to `/admin/users/{user_id}?toast_err=` with "Could not
  grant membership" or "Could not revoke membership".

### 12.8 Audit logs and error logs

- `SPEC-12.8.1` `GET /admin/audit-logs` must request page size 50, treat `admin_only` as set only when it equals `true`,
  and pass `user_id`, `action`, `severity`, `since` and `q` to the API only when non-empty.
- `SPEC-12.8.2` When `user_id` is set the page must show "Filtered to {email}" with a Clear link that drops only
  `user_id`. When the user lookup fails the label must fall back to the id itself and the audit rows must still render.
- `SPEC-12.8.3` The pager base URL must be `/admin/audit-logs` followed by `?` and the `&`-joined, URL-encoded
  parameters `admin_only=true`, `user_id`, `action`, `severity`, `since` and `q` that are set, so that paging never
  drops a filter. The admin-only toggle form must carry the other filters as hidden inputs.
- `SPEC-12.8.4` The filter form must offer an Action chip with the fixed options in `ACTION_OPTIONS` (all actions plus
  14 action names), a Severity chip (`info`, `warning`, `error`, `critical`), a Since chip (`1h`, `24h`, `7d`, `30d`,
  all time) and a text search `q` with `maxlength` 128. A Clear link must appear only when action, severity, since or q
  is set, and must keep `user_id` and `admin_only`.
- `SPEC-12.8.5` `audit_row` must pick the icon from the first matching rule in order: action contains `login`;
  `membership` or `payment`; `password`; `magic_link`; `register`; `admin` or `deactivate`; otherwise a user icon. It
  must show the `title_case` action, an "Admin" badge when `is_admin_action`, a "Warning" badge for severity `warning`,
  an "Error" badge for severity `error`, the actor email or "System", the actor IP when known, and the relative time.
- `SPEC-12.8.6` A failed audit fetch must show "Could not reach the API to load audit logs."; an empty result must show
  "No audit logs found."; the pager must render in both cases using page 1 total when the fetch failed.
- `SPEC-12.8.7` `GET /admin/logs` must trim `category` and treat empty as unset, request the API error log with it, and
  show "Showing {matched} of {buffered} buffered (capacity {capacity})." only when the fetch succeeded. The "All" and
  "Rate limit" (`category=rate_limit`) links must mark the current choice.
- `SPEC-12.8.8` A failed error-log fetch must show "Could not reach the API to load error logs."; an empty result must
  show "No errors captured." (with " in this category" appended when a category is set). Each entry must show the
  message, an "Error" badge, the category badge when set, the target, the route and client when set, and the structured
  fields as `key=value`.

### 12.9 Feedback list tabs and triage actions

- `SPEC-12.9.1` The feedback area must have four tabs: Active (`/admin/feedback`, API bucket `active`), Closed
  (`/admin/feedback/closed`, `closed`), Spam (`/admin/feedback/spam`, `spam`) and Archive (`/admin/feedback/archive`),
  each rendered by one shared tab bar that marks the current tab with `aria-current="page"`.
- `SPEC-12.9.2` The Active, Closed and Spam list handlers must request page size 20 and pass `tag` (trimmed, non-empty),
  `attachment` and `response` (`yes` becomes true, `no` becomes false, anything else is no filter) and `q` (trimmed,
  non-empty) to the API. The pager base URL must carry every non-empty filter, URL-encoded, on the tab's path.
- `SPEC-12.9.3` A failed list fetch must show "Could not reach the API to load feedback."; an empty list must show "No
  feedback yet." (Active), "No closed feedback." (Closed) or "No spam." (Spam). The filter form must offer the tag
  options Bug, Feature, Flow and Idea and a text search with `maxlength` 128, and a Clear link when any filter is set.
- `SPEC-12.9.4` A list row must link to `/admin/feedback/{id}?from={active|closed|spam|archive}` and show the subject
  (or "(no subject)"), the submitter name and masked email joined with a middle dot when both exist, the source page
  unless empty or `/feedback`, the message excerpt, the relative time and a status chip.
- `SPEC-12.9.5` The status chip must read New, Reviewed, Responded, Closed or Unknown for the corresponding status, and
  an unknown status must render the neutral "Unknown" chip.
- `SPEC-12.9.6` The detail action bar must offer, by tab: Active gets Reviewed (or "Un-review" when already Reviewed),
  Close, Archive, Mark as spam; Closed gets Re-open, Archive, Mark as spam; Spam gets Not spam and Archive; Archive gets
  none; every tab gets Delete with a confirmation prompt. Each form must post hidden `from` set to the tab slug.
- `SPEC-12.9.7` `from_tab_path` must map `from` `closed`, `spam` and `archive` to their tab paths and every other or
  absent value to `/admin/feedback`; `FeedbackTab::from_query` must map unknown or absent values to Active.
- `SPEC-12.9.8` `POST /admin/feedback/{id}/status` must map `status` `reviewed`, `responded` and `closed` to those
  statuses and every other value to `new`. On success it must redirect to the `from` tab path with `toast_ok` "Closed",
  "Marked reviewed", "Marked responded" or "Re-opened"; on failure it must redirect there with
  `toast_err=Could%20not%20update%20status`.
- `SPEC-12.9.9` `POST /admin/feedback/{id}/mark-spam`, `/unmark-spam`, `/archive` and `/delete` must redirect to the
  `from` tab path with `toast_ok` "Marked as spam", "Restored from spam", "Archived" or "Deleted" on success and
  `toast_err` "Could not mark spam", "Could not unmark spam", "Could not archive" or "Could not delete" on failure.
  Delete is relayed to the API without a second server-side confirmation.
- `SPEC-12.9.10` `POST /admin/feedback/archive/{archive_id}/restore` must redirect to `/admin/feedback/archive` with
  `toast_ok=Restored` on success and `toast_err=Could%20not%20restore` on failure.
- `SPEC-12.9.11` Each feedback list and the archive page must link "Export CSV" to `/admin/feedback/export`.

### 12.10 Feedback detail, response, attachments, export and archive

- `SPEC-12.10.1` `GET /admin/feedback/{id}` must load the detail for the `from` tab (unknown becomes Active) and, when
  the load fails, redirect (303) to that tab's list path.
- `SPEC-12.10.2` The detail page must show the submitter name and masked email only (never the raw address), the source
  page unless empty or `/feedback`, the tags, the message with newlines preserved, the attachments, the received time,
  the spam classifier reason when present, the submitter IP as a link to `/admin/ip-bans?ip={ip}` when present, and the
  user agent when present.
- `SPEC-12.10.3` When the submission has no email on record, the Response card must show "No email on record - the
  submitter did not provide an address. Your response will be saved but cannot be delivered.".
- `SPEC-12.10.4` The response form must prefill the textarea with the stored response (or a just-submitted draft), show
  "Sent {relative time}" when a stored response with a sent time exists, and label the button "Resend response" when a
  stored response exists and "Send response" otherwise.
- `SPEC-12.10.5` `POST /admin/feedback/{id}/respond` must apply `verification_gate` with back path
  `/admin/feedback/{id}`, trim the response, reject an empty response with "Response cannot be empty" and one longer
  than 16000 bytes with "Response must be 16000 characters or fewer" without calling the API, and otherwise send it.
- `SPEC-12.10.6` On success `POST /admin/feedback/{id}/respond` must redirect to
  `/admin/feedback/{id}?toast_ok=Response%20sent`. On any rejection or API failure it must re-render the detail page
  (200, Active tab) with the typed text still in the textarea and the error inside the form ("Could not send response"
  for an API failure), and must redirect to `/admin/feedback` if the detail reload fails.
- `SPEC-12.10.7` Attachments must render with a link to `/admin/feedback/{feedback_id}/attachments/{attachment_id}`, an
  inline thumbnail when the MIME type starts with `image/`, the filename, and the size as `{n} B` below 1024 bytes,
  `{x.x} KB` below 1 MiB and `{x.x} MB` otherwise.
- `SPEC-12.10.8` `GET /admin/feedback/{id}/attachments/{attachment_id}` and `GET /admin/feedback/export` must stream the
  API body when the API answers 2xx, with the API status, `Content-Type` (default `application/octet-stream`, and
  `text/csv` for the export), `Content-Disposition` (default `attachment`, and `attachment; filename="feedback.csv"` for
  the export), the API `Content-Length` when present and the hardening headers.
- `SPEC-12.10.9` When the API answers 401 the attachment and export proxies must redirect to `/login`; for any other
  non-2xx answer or transport failure they must redirect to `/admin/feedback/{feedback_id}` (attachment) or
  `/admin/feedback` (export), so an error body is never saved as the download.
- `SPEC-12.10.10` `GET /admin/feedback/archive` must request page size 20 and show each archived row with the subject,
  name and email, the message excerpt, "Archived {relative time}" plus " - was {original_status}" when known, and a
  Restore form posting to `/admin/feedback/archive/{id}/restore`. A failed fetch must show "Could not reach the API to
  load archived feedback."; an empty list must show "Archive is empty.".

### 12.11 Admin invites and mailer suppressions

- `SPEC-12.11.1` `GET /admin/invites` must request page size 20 with `status` and `email` (each trimmed, empty means
  unset), render a status chip (`pending`, `accepted`, `revoked`, `expired`, all) and an email text filter with
  `maxlength` 128, show "{total} total." only when the fetch succeeded, and carry both filters in the pager base URL. A
  failed fetch must show "Could not reach the API to load invites."; an empty list must show "No invites yet.".
- `SPEC-12.11.2` An invite's status must be Revoked when `revoked_at` is set, else Accepted when `accepted_at` is set,
  else Expired when `expires_at` sorts before the current RFC3339 time, else Pending. Only a Pending invite must show a
  Revoke form posting to `/admin/invites/{id}/revoke` with a confirmation prompt.
- `SPEC-12.11.3` `POST /admin/invites` must apply `verification_gate` with back path `/admin/invites`, send the trimmed
  email, and redirect to `/admin/invites` with `toast_ok=Invited {email}` on success or `toast_err={API user message}`
  on failure.
- `SPEC-12.11.4` `POST /admin/invites/{invite_id}/revoke` must apply `verification_gate` with back path `/admin/invites`
  and redirect to `/admin/invites` with `toast_ok=Invite%20revoked` on success or `toast_err={API user message}` on
  failure.
- `SPEC-12.11.5` `GET /admin/mailer-suppressions` must request page size 20, show "{total} total." only when the fetch
  succeeded, and render for each entry the address, the reason with ": {detail}" appended when a non-empty detail
  exists, the "Suppressed {relative time}" line and a Remove form posting to `/admin/mailer-suppressions/{url-encoded
  address}/delete` with a confirmation prompt. A failed fetch must show "Could not reach the API to load mailer
  suppressions."; an empty list must show "No suppressed addresses.".
- `SPEC-12.11.6` `POST /admin/mailer-suppressions/{address}/delete` must apply `verification_gate` with back path
  `/admin/mailer-suppressions` and redirect there with `toast_ok=Suppression%20removed` on success or `toast_err={API
  user message}` on failure.

### 12.12 IP bans and auto-ban settings

- `SPEC-12.12.1` `GET /admin/ip-bans` must fetch the whole ban list in one call and filter and sort it in the handler:
  `search` (trimmed) keeps bans whose IP starts with it case-insensitively; `reason` (trimmed) keeps bans whose reason
  contains it case-insensitively; `sort` is one of `strikes_desc`, `strikes_asc`, `expires_soonest`, `expires_latest`,
  `banned_oldest` or `banned_newest`, and any other or empty value sorts as `banned_newest`.
- `SPEC-12.12.2` The page must show "{n} active." (or "{n} of {total} active." when a filter or non-default sort is
  active) only when the fetch succeeded. A failed fetch must show "Could not reach the API to load IP bans."; an empty
  result must show "No active IP bans.". The search input must have `maxlength` 45 and the reason input 128.
- `SPEC-12.12.3` A ban row must show the IP, a "Banned" badge, "{strikes} strikes", the reason, the banned and expiry
  relative times and an Unban form posting hidden `ip` to `/admin/ip-bans/unban` with a confirmation prompt.
- `SPEC-12.12.4` The "Add Ban" card must render only for a super admin, with the IP field prefilled from `?ip=`, a
  required reason with `maxlength` 255, and a duration field defaulting to 86400 seconds with `min` 60 and `max`
  31536000.
- `SPEC-12.12.5` When `?ip=` is non-empty after trimming, the page must look up the address enrichment and render the
  "Address intel" panel: a "Network: {category}" badge, a badge "VPN/proxy: {vpn}" (destructive) when anonymizing, "Data
  centre" when `vpn` is `data-center`, "No proxy signal" when `vpn` is `not-proxy`, otherwise an outline "VPN/proxy"
  badge, "Threat-listed" when a threat exists, and the present fields ASN, Organization, ISP, Proxy type, VPN provider
  and Threat. With no enrichment it must state that none is available and must not imply the address is clean.
- `SPEC-12.12.6` `POST /admin/ip-bans/add` must apply `refuse_non_super_admin` with back path `/admin/ip-bans`, treat a
  blank duration as 86400, and redirect to `/admin/ip-bans?toast_err=Duration%20must%20be%20a%20whole%20number` for a
  non-integer duration without calling the API. Otherwise it must send the trimmed IP, trimmed reason and duration, and
  redirect with `toast_ok=Banned {ip}` on success or `toast_err={API user message}` on failure.
- `SPEC-12.12.7` `POST /admin/ip-bans/unban` must be available to any admin, send the submitted `ip`, and redirect to
  `/admin/ip-bans` with `toast_ok=Ban lifted for {ip}` on success or `toast_err=Could%20not%20lift%20ban` on failure.
- `SPEC-12.12.8` `GET /admin/auto-ban-settings` must show the stored `enabled` switch, strike threshold, strike window
  (seconds) and ban duration (seconds), and the config source. A failed fetch must show "Could not reach the API to load
  the auto-ban config." and no form.
- `SPEC-12.12.9` `POST /admin/auto-ban-settings` must require `threshold`, `window_secs` and `ban_duration_secs` to be
  base-10 integers in `[1, max]` with max 100000, 2592000 (30 days) and 31536000 (365 days). The first failing field in
  that order must be reported as "{label} must be a whole number.", "{label} must be at least 1." or "{label} must be at
  most {max}." with labels "Strike threshold", "Strike window" and "Ban duration", and the API must not be called.
- `SPEC-12.12.10` A valid auto-ban submission must send `enabled` (`true` only when the field equals `true`) and all
  three numbers in one update and redirect to `/admin/auto-ban-settings`. On a validation or API failure it must
  re-render the page (200) with the error and the submitted trimmed values.

### 12.13 Rate limits

- `SPEC-12.13.1` `GET /admin/rate-limits` must normalise `window` to `1h`, `6h` or `1d` (any other value becomes `1h`),
  and fetch independently the limit configs, the active throttles (page size 20), the past throttles (limit 100), the
  traffic and approaching overview (threshold 0.7, top 5 per action, for the window) and the whitelist. Each failed
  fetch must render its own error box and must not hide the other sections.
- `SPEC-12.13.2` A failed overview fetch must mark every traffic row failed, showing "Could not reach the API to load
  rate-limit traffic." when all rows failed, and must show "Could not reach the API to load subjects approaching their
  limit." for Close to the Limit instead of "No throttles are approaching right now.".
- `SPEC-12.13.3` An active-throttle row must show the subject (user email, else IP, else raw key), the `title_case`
  action, the badge `{count}/{max_requests}`, the window start and "retry in {label}", and a Reset form posting hidden
  `action`, `key` and (on the user-detail page) `return_user` to `/admin/rate-limits/reset` with a confirmation prompt.
  Empty and failed states must read "No active rate limits." and "Could not reach the API to load rate limits.".
- `SPEC-12.13.4` `fmt_retry_secs` must return "any moment" for 0, `{s}s` below one minute, `{m}m` for whole minutes and
  `{m}m {s}s` otherwise; `fmt_window_secs` must return `{h}h` for whole hours of at least 3600, `{m}m` for whole minutes
  of at least 60 and `{s}s` otherwise.
- `SPEC-12.13.5` `POST /admin/rate-limits/reset` must redirect to `/admin/users/{url-encoded return_user}` when
  `return_user` is non-empty and to `/admin/rate-limits` otherwise (never a caller-supplied URL), with
  `toast_ok=Rate%20limit%20reset` on success or `toast_err=Could%20not%20reset%20rate%20limit` on failure.
- `SPEC-12.13.6` The Limit Configuration card must show each action's cap and window, an "Overridden" or "Default"
  badge, the default values when overridden, and, only for a super admin, a Save form (requests `min` 1 `max` 1000000,
  window seconds `min` 1 `max` 604800) and a Revert form when overridden; other admins must see plain text.
- `SPEC-12.13.7` `POST /admin/rate-limits/config` must apply `refuse_non_super_admin` with back path
  `/admin/rate-limits`, parse `max_requests` as `i32` and `window_seconds` as `i64`, and redirect with
  `toast_err=Requests%20and%20window%20must%20be%20whole%20numbers` without calling the API when either fails. On
  success it must redirect with `toast_ok=Rate%20limit%20updated`; on failure with `toast_err={API user message}`.
- `SPEC-12.13.8` `POST /admin/rate-limits/config/reset` must apply `refuse_non_super_admin`, delete the override for the
  trimmed action, and redirect to `/admin/rate-limits` with `toast_ok=Reverted%20to%20the%20default%20limit` on success
  or `toast_err={API user message}` on failure.
- `SPEC-12.13.9` `POST /admin/rate-limits/whitelist/add` and `/remove` must be available to any admin and send the
  trimmed `kind`, `value` and `reason` (add) or `id` (remove). They must redirect to `/admin/rate-limits` with
  `toast_ok` "Added to whitelist" or "Removed from whitelist" on success and `toast_err` "Could not add to whitelist" or
  "Could not remove from whitelist" on failure. The add form must offer the kinds `user`, `email` and `ip`.
- `SPEC-12.13.10` The sparkline must draw one bar per bucket oldest to newest, scale to the larger of the limit and the
  largest count, give every bar a height of at least 1, tint a bar amber when its count exceeds the limit, and draw a
  dashed threshold line only when the limit is positive. The Traffic card must link the window toggle to
  `/admin/rate-limits?window={1h|6h|1d}` and mark the current one.
- `SPEC-12.13.11` The Past Throttles card must show "No rate limits have fired in the last 24 hours." for an empty
  history and "Could not reach the API to load past throttles." for a failed fetch; the whitelist card must show "No
  whitelisted principals. Use the form below to add one." for an empty list and "Could not reach the API to load the
  whitelist." for a failed fetch.

### 12.14 Email configuration

- `SPEC-12.14.1` `GET /admin/email` must show the SMTP and IMAP settings, the sender settings and the config source. A
  failed fetch must show "Could not reach the API to load the email config." and no form. The SMTP and IMAP password
  fields must never be prefilled: the placeholder must be a fixed mask when a value is stored and "Not set" otherwise;
  when the field is not editable it must render read-only and disabled with `secret_field_note`.
- `SPEC-12.14.2` `email_update_body` must always send `enabled` and `imap_enabled` (`true` only when the field equals
  `true`) and, for `smtp_port` and `imap_port`, send an integer only when non-empty. A non-integer must be rejected with
  "SMTP port must be a whole number." or "IMAP port must be a whole number." and a value outside 1 to 65535 with "SMTP
  port must be between 1 and 65535." or "IMAP port must be between 1 and 65535.".
- `SPEC-12.14.3` `email_update_body` must send `smtp_tls` only when it is `implicit` or `starttls`, must reject a
  non-empty `from_email` that has no `@` with "From email must be a valid address.", and must send each of `smtp_host`,
  `smtp_username`, `smtp_password`, `imap_host`, `imap_username`, `imap_password`, `imap_mailbox`, `from_email`,
  `from_name` and `admin_notification_emails` only when non-empty after trimming, so a blank field keeps its stored
  value.
- `SPEC-12.14.4` `POST /admin/email` must redirect to `/admin/email` on success. On a validation or API failure it must
  re-render the page (200) with the API user message and the submitted values, with the secret fields empty.
- `SPEC-12.14.5` `POST /admin/email/test` must run the connection probe against the saved settings (the form submits no
  fields) and re-render the email page (200) with a banner: the success message when `ok`; "SMTP test failed at the
  {stage} stage. {message}" when the relay reported a failed stage; the API user message when the call itself failed.
- `SPEC-12.14.6` `POST /admin/email/test-send` must send a real test message with the saved settings and re-render the
  email page (200) with a banner: the success message when `ok`; "Test email failed to send. {message}" when `ok` is
  false; the API user message when the call failed.

### 12.15 Mirzam newsletter integration

- `SPEC-12.15.1` `GET /admin/mirzam` must show the enabled switch, site address, product-updates list slug, notices list
  slug and a write-only API token field (fixed-mask placeholder when stored, "Not set" otherwise, read-only with
  `secret_field_note` when not editable). A failed fetch must show "Could not reach the API to load the Mirzam
  settings." and no form.
- `SPEC-12.15.2` The Sync block must show "The last call to Mirzam failed {relative time}." (without the time when none
  is recorded) with the stored error detail when a last error exists, and "No failed calls." otherwise.
- `SPEC-12.15.3` `mirzam_update_body` must always send `enabled` (`true` only when the field equals `true`), `base_url`,
  `updates_list` and `notices_list` trimmed (a blank value is a deliberate clear), and `api_token` only when non-empty
  after trimming.
- `SPEC-12.15.4` `POST /admin/mirzam` must redirect to `/admin/mirzam?toast_ok=Mirzam%20settings%20saved` on success. On
  failure it must re-render the page (200) with the API user message and the submitted values, with the token empty.
- `SPEC-12.15.5` `POST /admin/mirzam/check` must check the saved settings and redirect to `/admin/mirzam` with a
  `toast_ok` for lists that answered correctly and a `toast_err` for lists that did not, each a URL-encoded message of
  one line per distinct reason joined with a newline; only non-empty parameters must be present.
- `SPEC-12.15.6` A check line must read "{names}: {reason}" where `names` are "Product updates list ({slug})" and
  "Notices list ({slug})" joined with " and ", lists sharing an identical trimmed reason share one line, and a full stop
  must be appended when the line does not end in `.`, `!` or `?`.
- `SPEC-12.15.7` When the check returns no lists the toast must be the error "The connection check returned no result.
  Try again."; when the call itself fails the error toast must be the API user message.

### 12.16 Mokosh host settings

- `SPEC-12.16.1` `GET /admin/mokosh` must show the Google OAuth client id as plain text and the client secret as a
  write-only field (fixed-mask placeholder when stored, "Not set" otherwise, read-only with `secret_field_note` when not
  editable). A failed fetch must show "Could not reach the API to load the Mokosh settings." and no form.
- `SPEC-12.16.2` `mokosh_update_body` must always send `google_client_id` trimmed (blank is a deliberate clear) and
  `confirm_client_id_change` (`true` only when the hidden field equals `true`), and `google_client_secret` only when
  non-empty after trimming.
- `SPEC-12.16.3` `POST /admin/mokosh` must redirect to `/admin/mokosh?toast_ok=Mokosh%20settings%20saved` on success.
- `SPEC-12.16.4` When the API refuses with a message containing `confirm_client_id_change`, the handler must treat it as
  the changed-id warning: re-render the page (200) with the submitted id, a warning box holding the API message cut
  before " Send the same change again", a hidden `confirm_client_id_change=true` field and the button "Save anyway". Any
  other API failure must re-render the page (200) with the API user message in an error box and no confirmation field.

### 12.17 Branding

- `SPEC-12.17.1` `GET /admin/branding` must show the product name, tagline, meta description, share image URL,
  newsletter signup URL, theme CSS and the two browser-chrome colours, followed by one upload card per slot `mark`,
  `favicon` and `mascot`. A failed fetch must show "Could not reach the API to load branding." and no form.
- `SPEC-12.17.2` `branding_update_body` must send all eight text fields on every save, each trimmed, including blank
  ones, because a blank value clears the field.
- `SPEC-12.17.3` `POST /admin/branding` must redirect to `/admin/branding` on success. On failure it must re-render the
  page (200) with the API user message inside the form and the submitted trimmed values, not the stored ones.
- `SPEC-12.17.4` Each slot card must show a preview when the slot is filled and its empty-state sentence otherwise, an
  upload form (`multipart/form-data`, file input `asset`, accepting PNG, JPEG, WebP and GIF) posting to
  `/admin/branding/assets/{slot}`, and a Remove form posting to `/admin/branding/assets/{slot}/clear` only when filled.
- `SPEC-12.17.5` The upload and clear handlers must accept only the slots `mark`, `favicon` and `mascot`; any other slot
  must re-render the page (200) with the error "Unknown brand asset." and must not call the API.
- `SPEC-12.17.6` `POST /admin/branding/assets/{slot}` must read the multipart field named `asset`, draining and skipping
  other fields, and reject: no `asset` field with "No image was selected."; an empty body with "The selected file is
  empty."; a body over 2 MiB (2097152 bytes) with "The image must be 2 MB or smaller."; an unreadable field with "Could
  not read upload: {cause}" or "Could not read the image: {cause}". A rejection must re-render the page (200) with the
  message and write nothing.
- `SPEC-12.17.7` An accepted upload must be relayed with the file name (default `asset`), the declared content type
  (default `application/octet-stream`, advisory only) and the bytes; success must redirect to `/admin/branding`; an API
  rejection must re-render the page (200) with the API user message and the persisted values.
- `SPEC-12.17.8` `POST /admin/branding/assets/{slot}/clear` must redirect to `/admin/branding` on success and re-render
  the page (200) with the API user message and the persisted values on failure.

### 12.18 Account backup and restore

- `SPEC-12.18.1` `GET /integrations/backup` must be admin-guarded and render the Backup & Restore page with the "What's
  included" note naming the brand ("the account's {brand} state") or "the account's own state" when the brand name is
  empty, a Download link to `/integrations/backup/download` and a restore form.
- `SPEC-12.18.2` `GET /integrations/backup/download` must stream the API `/account/backup` body when the API answers
  2xx, with the API status, `Content-Type` (default `application/json`), `Content-Disposition` (default `attachment;
  filename="account-backup.json"`), the API `Content-Length` when present and the hardening headers.
- `SPEC-12.18.3` When the API answers 401 the download must redirect to `/login`; for any other non-2xx answer or
  transport failure it must redirect to `/integrations/backup`, so an error body is never saved as the backup file.
- `SPEC-12.18.4` The restore form must be `multipart/form-data` with a required file input `backup`, posting to
  `/integrations/backup/restore`, with a confirmation prompt.
- `SPEC-12.18.5` `POST /integrations/backup/restore` must read the multipart field `backup`, draining and skipping other
  fields, and reject: no field with "No backup file was uploaded."; an empty file with "The uploaded file is empty."; a
  file over 8 MiB (8388608 bytes) with "The backup file must be 8 MB or smaller."; a file that is not JSON with "That
  file is not a valid backup (expected JSON)."; an unreadable field with "Could not read upload: {cause}" or "Could not
  read the file: {cause}". A rejection must render the page (200) with the message and must not call the API.
- `SPEC-12.18.6` A parsed bundle must be sent to the API restore. On success the page (200) must show the "Restore
  complete" report: Profile "restored" or "unchanged", Entitlements granted (comma-joined or "none"), and per app the
  slug with "restored" or "skipped ({reason})". On an API failure it must render the page (200) with the API user
  message as an error box.

### 12.19 Feature toggles and provider status

- `SPEC-12.19.1` `GET /admin/features` must list every toggle as a block with its label, help text, and who changed it
  and when ("Last changed by {email} {time}", "Last changed {time}", or "Never changed. Off by default."). A failed
  fetch must log a warning with the endpoint, error message and error code and show "Could not reach the API to load the
  feature toggles."; an empty list must show "No feature toggles.".
- `SPEC-12.19.2` Only a super admin must see an editable form per toggle (hidden `key`, the switch `enabled`, a Save
  button posting to `/admin/features`); every other admin must see an "On" or "Off" badge and "Only the super admin can
  change this.".
- `SPEC-12.19.3` `POST /admin/features` must apply `refuse_non_super_admin` with back path `/admin/features`, send the
  trimmed `key` and `enabled` true exactly when the `enabled` field is present in the body (an unticked switch is absent
  and means off), and redirect to `/admin/features` with `toast_ok=Feature%20toggle%20saved` on success or
  `toast_err={API user message}` on failure.
- `SPEC-12.19.4` `GET /admin/providers/status` must show, on a successful fetch, a Discrepancies card ("None flagged."
  when empty) and one card per application in the report, with no application omitted whatever its state. A failed fetch
  must show "Could not reach the API to load the suite provider status." instead of any card.
- `SPEC-12.19.5` An application card must show the badge "Reachable", "Unreachable", "Unauthenticated", "Version
  mismatch" or "Unknown" for its state, a detail sentence for every non-healthy state (the reason for Unreachable), and
  for a healthy one each provider kind with "serving: {name}" or "nothing is serving" and the enabled providers in order
  with " (unreachable)" appended to an unreachable one.
- `SPEC-12.19.6` A discrepancy must render as `{app}/{kind}: "{key}" is held by no provider`, as `{app}/{kind}: "{key}"
  is present in more than one provider ({providers})` (or "more than one provider holds a value ({providers})" when the
  key is empty), as `{app}/{kind}: "{key}" is absent from {serving} (the highest-priority provider) but held by
  {holder}`, and an unrecognised one as "an unrecognised discrepancy was reported".
- `SPEC-12.19.7` The page introduction must name the brand ("{brand}'s own included") and, when the brand name is empty,
  say "including this deployment's own" instead of substituting a literal name.

### 12.20 Admin gate and redirect conventions (seed, status, system settings, pricing tiers, Stripe, users)

Applies to every handler in subsections 12.21 to 12.38. Source files are under `bunyip-web/src/handlers/admin/`.

- `SPEC-12.20.1` Every handler in 12.21 to 12.38 must call `admin_guard` before any bunyip-api call and, when it
  returns `Err`, must return that response unchanged (unauthenticated: redirect to `/login`; admin without two-factor:
  redirect to `/settings/2fa/setup`; non-admin: redirect to `/dashboard`).
- `SPEC-12.20.2` Every POST action handler in 12.21 to 12.38 must answer with a `303 See Other` redirect built by
  `redirect_cookies`, which carries the auth context's `set_cookies`; the outcome travels in the redirect query.
- `SPEC-12.20.3` Redirect outcomes must be URL-encoded with `urlenc` and carried as `toast_ok` / `toast_err` (Stripe,
  tier catalog, users) or as `ok` / `error` (seed data); an API failure message shown to the admin must be
  `ApiError::user_message`, or `user_message_with_reference` where the Stripe and catalog handlers state it.
- `SPEC-12.20.4` The user-action handlers (`user_role`, `user_delete`, `user_suspend`, `user_reactivate`,
  `user_reset_password`, `user_email`, `user_verify_email`, `user_reset_2fa`, `user_grant_lifetime`,
  `user_revoke_lifetime`, `user_set_tier`) must call `verification_gate` after `admin_guard`, and when it returns a
  response must return it without calling bunyip-api; the gate bounces to the handler's own page with a `toast_err`.
None: production gating of seed import is enforced by bunyip-api, not by these handlers.

### 12.21 Seed data (`/admin/seed`)

- `SPEC-12.21.1` `GET /admin/seed` must fetch the starter-template list from bunyip-api (`GET /admin/seed/templates`)
  forwarding the admin's cookie, and must render the page titled "Seed Data" with active nav `/admin/seed`; an `ok`
  query value must render as a success box and an `error` query value as an error box.
- `SPEC-12.21.2` When the template list cannot be fetched, the page must show the error box "Could not reach the API to
  load seed templates." with the API error, and must not show the empty state; when the list is empty it must show
  "No starter templates are available."
- `SPEC-12.21.3` Each listed template must render its name, description and the counts of users, applications, groups
  and feedback, plus a `POST /admin/seed/template` form carrying the template name in the hidden field `template`.
- `SPEC-12.21.4` The page must offer a download link to `/admin/seed/export` and an import form posting the textarea
  `seed_json` (required) to `/admin/seed/import`.
- `SPEC-12.21.5` `GET /admin/seed/export` must stream bunyip-api's `GET /admin/seed/export` body to the browser without
  buffering it, when the API status is a success, mirroring that status, with `Content-Type: application/json` and the
  API's `Content-Disposition` (default `attachment; filename="seed-export.json"` when the API sends none).
- `SPEC-12.21.6` The export response must also carry `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: sandbox` and `Referrer-Policy: no-referrer`.
- `SPEC-12.21.7` When the API call fails or answers non-success, the export must redirect to
  `/admin/seed?error=Could not export seed data.` (encoded).
- `SPEC-12.21.8` `POST /admin/seed/import` must parse `seed_json` as JSON before any API call; when it is not valid
  JSON it must redirect to `/admin/seed` with `error` = "That is not valid JSON: " followed by the parser message, and
  must not call the API.
- `SPEC-12.21.9` A valid JSON body must be forwarded to bunyip-api's seed import; on success the redirect `ok` must be
  "Imported {users} users, {applications} apps, {groups} groups, {entitlements} entitlements, {feedback} feedback."
  from the returned counts, and on failure the redirect `error` must be the API error's `user_message`.
- `SPEC-12.21.10` `POST /admin/seed/template` must trim `template`; when it is empty it must redirect with `error` =
  "No template selected." and must not call the API.
- `SPEC-12.21.11` A non-empty template name must be forwarded to bunyip-api's template import; success must redirect
  with `ok` = "Loaded template '{name}': {users} users, {applications} apps, {groups} groups, {entitlements}
  entitlements, {feedback} feedback." and failure with `error` = the API error's `user_message`.

### 12.22 System status (`GET /admin/status`)

- `SPEC-12.22.1` The handler must fetch integration status, system health and the API version concurrently, each
  failure handled independently of the others, and must send no cookie on the version fetch (the endpoint is
  unauthenticated).
- `SPEC-12.22.2` The Version card must always render. For the API side it must show the version and the first 12
  characters of the revision, each as "Unknown" when empty or when the fetch failed; on a failed fetch it must also
  show "The API's /version endpoint did not respond: " followed by the error message.
- `SPEC-12.22.3` The Version card's web side must show the compile-time package version, the first 12 characters of
  the build commit, and the build describe tag.
- `SPEC-12.22.4` The API Version card must show an upgrade hint only when the update payload is a JSON object whose
  `available` is `true`: "A newer version is available upstream: {latest_version}." or, when `latest_version` is
  empty, "A newer version is available upstream."; otherwise no hint.
- `SPEC-12.22.5` When system health loads, the page must show an API Build card (version, revision as the first 12
  characters of `git_commit`, describe tag, build date) and a Stats card (uptime and "{idle} idle / {size} open"
  database pool); when it fails, both cards must be replaced by the error box "Could not reach the API to load build +
  stats." with the API error.
- `SPEC-12.22.6` Uptime must format as `{d}d {h}h` when at least one day, else `{h}h {m}m` when at least one hour,
  else `{m}m {s}s` when at least one minute, else `{s}s`.
- `SPEC-12.22.7` The Integrations card must always render; when the fetch fails it must show the error box "Could not
  reach the API to load integration status." with the API error instead of a list.
- `SPEC-12.22.8` Each integration row must show its name and a state badge (Configured: success; Unconfigured: outline;
  Failing: destructive; an unrecognised state: outline labelled "Unknown"), then its detail line when non-empty, then
  its remedy line when non-empty.

### 12.23 System settings page (`GET /admin/system-config`)

- `SPEC-12.23.1` The handler must fetch the file-layer configuration from bunyip-api and render the page titled
  "System Settings" with active nav `/admin/system-config`; when the fetch fails it must render the error box "Could
  not reach the API to load the system config." with the API error and no form.
- `SPEC-12.23.2` When the fetch succeeds the page must show the file-layer directory path and a form posting to
  `/admin/system-config` with the controls `login_approval_enabled` and `signup_bot_guard_enabled` (toggles) and
  `country_allow` and `country_deny` (text), pre-filled from the stored values.
- `SPEC-12.23.3` Every rendered setting must carry a provenance line (`data-provenance` equal to the field name),
  matched to the API's provenance entry by case-insensitive key.
- `SPEC-12.23.4` The provenance line must read: with no entry, "This deployment's API did not report which provider
  serves this setting."; serving `environment`, that the {FIELD} environment variable serves it and saving writes the
  file layer, which overrides it from the next restart; serving `file` while `environment` also holds it, that the file
  layer serves it and the environment variable is ignored; serving `file` alone, "Served by the file layer, which this
  form writes."; any other provider P, "Served by the P provider."; serving nothing, that the built-in default applies.
  {FIELD} is the field name upper-cased.

### 12.24 System settings save (`POST /admin/system-config`)

- `SPEC-12.24.1` The save must send the full body every time: `login_approval_enabled` and `signup_bot_guard_enabled`
  as `true` when their checkbox is present in the form and `false` when absent, and `country_allow` and
  `country_deny` trimmed, so a cleared field clears the setting.
- `SPEC-12.24.2` On success the handler must redirect to `/admin/system-config` with no toast.
- `SPEC-12.24.3` On failure it must re-render the page (not redirect) with the submitted values (checkboxes as
  submitted, country fields trimmed) and the API error's `user_message` as an error box inside the form below the
  heading, re-fetching only the path and provenance from bunyip-api.

### 12.25 Pricing tiers page (`GET /admin/tier-settings`)

- `SPEC-12.25.1` The handler must fetch the tier configuration, the Stripe price list, the pricing status and the
  Stripe checkout trial length, and render the page titled "Pricing Tiers" with active nav `/admin/tier-settings`; the
  catalog form's submitted values may arrive in the query (see 12.33).
- `SPEC-12.25.2` When the tier configuration cannot be fetched the page must show the error box "Could not reach the
  API to load the tier config." with the API error, must log a warning naming the endpoint, message and code, and must
  render neither form.
- `SPEC-12.25.3` When the Stripe price list cannot be fetched the handler must log a warning naming the endpoint,
  message and code and render the catalog selects without price options.
- `SPEC-12.25.4` When the pricing status cannot be fetched the handler must log a warning and the catalog section must
  show the failure as an error box (see 12.33), never as an empty status.
- `SPEC-12.25.5` The checkout trial field must be the Stripe configuration's `trial_period_days`; when that config is
  unreadable the handler must log a warning and leave the field blank, not 0.
- `SPEC-12.25.6` The Tiers & Slots form posting to `/admin/tier-settings` must contain `lifetime_slots` and
  `early_adopter_slots` (number, 0 to 1,000,000), `early_adopter_trial_days` and `standard_trial_days` (number, 0 to
  3,650), `trial_period_days` (number, 0 to 365) and the `orgs_enabled` toggle, pre-filled from the stored values, with
  the used counts of lifetime and early-adopter slots in the block caption.

### 12.26 Pricing tiers save (`POST /admin/tier-settings`)

- `SPEC-12.26.1` Each of `lifetime_slots`, `early_adopter_slots`, `early_adopter_trial_days`, `standard_trial_days` and
  `trial_period_days` must be trimmed and parsed as a base-10 integer in `[0, max]` with max 1,000,000 for the two
  slot fields, 3,650 for the two trial-day fields and 365 for the checkout trial; the first failing field, checked in
  that order, must be named in the error: "{label} must be a whole number.", "{label} must be zero or greater." or
  "{label} must be at most {max}." with labels "Lifetime slots", "Early-adopter slots", "Early-adopter trial days",
  "Standard trial days" and "Checkout trial (days)".
- `SPEC-12.26.2` When every field parses, the handler must make exactly one bunyip-api call (`PUT
  /admin/tier-settings`) with the six keys `lifetime_slots`, `early_adopter_slots`, `early_adopter_trial_days`,
  `standard_trial_days`, `orgs_enabled` (true when the checkbox is present) and `trial_period_days`; nothing may be
  sent when any field is invalid.
- `SPEC-12.26.3` On success it must redirect to `/admin/tier-settings` with no toast.
- `SPEC-12.26.4` On a validation or API failure it must re-render the page with the error box inside the Tiers & Slots
  form, the submitted values trimmed, the `orgs_enabled` tick as submitted, and the catalog form from the stored row
  (no submitted catalog values).

### 12.27 Stripe page (`GET /admin/stripe`)

- `SPEC-12.27.1` The handler must fetch the Stripe configuration and, keeping each result separately, the product list,
  price list and webhook-endpoint list, and render the page titled "Stripe" with active nav `/admin/stripe`.
- `SPEC-12.27.2` When the Stripe configuration cannot be fetched the page must show only the error box "Could not reach
  the API to load the Stripe config." with the API error.
- `SPEC-12.27.3` When it loads, the page must show, in order: the setup guidance card, the configuration form posting
  to `/admin/stripe` (blocks "Stripe Configuration" with `secret_key`, `webhook_secret`, `app_tag`; and "Checkout"
  with `success_url`, `cancel_url`), the key and permissions card, the Products block, the Prices block and the
  Webhook endpoints block.
- `SPEC-12.27.4` The secret fields must be editable password inputs (placeholder: the masked stored value, else
  `sk_live_...` / `whsec_...`) only when the configuration reports `secrets_editable`; otherwise they must render
  read-only and disabled with a note naming the owning provider. A stored secret value must never be rendered.
- `SPEC-12.27.5` The handler must call the permission probe only when the query has `check=permissions`.
- `SPEC-12.27.6` A product, price or webhook list that cannot be read from Stripe must render a "Could not read ..."
  error box, never the empty state; its cause line must be the API's message when the status is 400 to 499 and the
  message is non-empty, else a fixed hint naming the usual missing permission, and it must include the API request id
  when present.
- `SPEC-12.27.7` The query values `webhook_error`, `webhook_url`, `webhook_events` and `webhook_ref`, each trimmed and
  ignored when blank, must restore a failed webhook create: the error box (with reference), the submitted URL and the
  submitted events text.

### 12.28 Stripe configuration save (`POST /admin/stripe`)

- `SPEC-12.28.1` `app_tag` must be trimmed and at most 200 bytes, else the error "App tag must be 200 characters or
  fewer"; a blank `app_tag` must be sent as the empty string.
- `SPEC-12.28.2` A non-blank `secret_key` (trimmed) must start with `sk_` or `rk_` and be at most 255 bytes, else the
  errors "Secret key must start with 'sk_' or 'rk_'" or "Secret key must be 255 characters or fewer"; a non-blank
  `webhook_secret` must start with `whsec_` and be at most 255 bytes, else "Webhook secret must start with 'whsec_'"
  or "Webhook secret must be 255 characters or fewer".
- `SPEC-12.28.3` The update body must always carry `app_tag` and must carry `secret_key`, `webhook_secret`,
  `success_url` and `cancel_url` only when non-blank after trimming (blank means keep the stored value); the URLs are
  not format-checked here.
- `SPEC-12.28.4` On success the handler must redirect to `/admin/stripe`.
- `SPEC-12.28.5` On a validation failure or API failure it must render a page titled "Stripe" with the error box (API
  failures use `user_message_with_reference`) and a link "Back to Stripe", without re-fetching the Stripe
  configuration.

### 12.29 Stripe key permission self-test

- `SPEC-12.29.1` When the probe call fails, the card must show the error box "Could not run the permission test." with
  the API error and request id.
- `SPEC-12.29.2` When the report says Stripe is not configured, the card must show "Save a secret key above first, then
  run the test."; when the key status is `rejected` it must show a single error box stating that Stripe rejected the
  key, not one row per permission.
- `SPEC-12.29.3` Otherwise the card must list the checks whose `when` is `admin` under "Tested now" and those whose
  `when` is `checkout` under "Also required (used at checkout)", each row showing the label, "Needs {access} access"
  and a status badge.
- `SPEC-12.29.4` The status badge must map `granted` to success "Granted", `missing` to destructive "Missing",
  `key_rejected` to destructive "Key rejected", `unknown` to warning "Could not verify", `untested` to outline "Not
  tested here", and any other value to outline "Unknown".
- `SPEC-12.29.5` The card's banner must be the error box about a missing permission when any `admin` check is
  `missing`, else the success box "The tested permissions are all present on the saved key."
- `SPEC-12.29.6` The "Test key and permissions" control must be a link to `/admin/stripe?check=permissions` anchored at
  `#permission-check`.

### 12.30 Stripe products

- `SPEC-12.30.1` `POST /admin/stripe/products` must trim `name`; when empty it must redirect with `toast_err` "Product
  name is required" without an API call; otherwise it must send `name` plus `description` only when the trimmed
  description is non-empty.
- `SPEC-12.30.2` Create must redirect to `/admin/stripe` with `toast_ok` "Product created" on success and with
  `toast_err` = `user_message_with_reference` on failure.
- `SPEC-12.30.3` `POST /admin/stripe/products/{id}` must validate the name as trimmed, required ("Product name is
  required") and at most 250 bytes ("Product name must be 250 characters or fewer"), and the trimmed description as at
  most 500 bytes ("Description must be 500 characters or fewer"), redirecting with `toast_err` and making no API call
  on failure.
- `SPEC-12.30.4` The edit body must contain exactly `name` and `description` (a blank description sent as the empty
  string so Stripe clears it) and must never contain `active` or `metadata`.
- `SPEC-12.30.5` Edit must redirect with `toast_ok` "Product updated" on success and `toast_err` =
  `user_message_with_reference` on failure.
- `SPEC-12.30.6` `POST /admin/stripe/products/{id}/archive` must redirect with `toast_ok` "Product archived" or
  `toast_err` = `user_message_with_reference`; `POST /admin/stripe/products/{id}/unarchive` must redirect with
  `toast_ok` "Product restored" or `toast_err` = `user_message`.
- `SPEC-12.30.7` The Products block must show a create form (`name` required, `description`) and, per product, name,
  an Active or Archived badge, the trimmed description when non-empty, the id, and an Edit disclosure pre-filled with
  `maxlength` 250 and 500.
- `SPEC-12.30.8` An active product must offer an Archive form, except when its `member_count` is above 0, where a
  disabled button and the text "1 member" or "{n} members" must replace it; an archived product must offer Unarchive.
- `SPEC-12.30.9` An active product must carry the warning badge "No active price" only when the price list loaded and
  holds no active price for it; when the price list failed no such claim may be made.
- `SPEC-12.30.10` An empty product list must render "No products yet. Create one to get started."

### 12.31 Stripe prices

- `SPEC-12.31.1` An amount in dollars must convert to integer cents as the rounded value of amount x 100; it must be
  rejected with "Amount must be a number of 0 or more." when it does not parse as a finite number or is negative; zero
  is valid.
- `SPEC-12.31.2` `POST /admin/stripe/prices` must redirect with `toast_err` "Select a product" when `product_id` is
  blank, and with the amount error when the amount is invalid, in both cases without an API call.
- `SPEC-12.31.3` Create must send `product_id`, `unit_amount` (cents), `currency` and `interval`, each trimmed, and
  redirect with `toast_ok` "Price created" or `toast_err` = `user_message_with_reference`.
- `SPEC-12.31.4` `POST /admin/stripe/prices/{id}/replace` must validate the amount as in create, send exactly
  `unit_amount`, `currency` and `interval`, and redirect with `toast_ok` "Price replaced" or `toast_err` =
  `user_message_with_reference`.
- `SPEC-12.31.5` `POST /admin/stripe/prices/{id}/archive` must redirect with `toast_ok` "Price archived" or `toast_err`
  = `user_message_with_reference`; `POST /admin/stripe/prices/{id}/unarchive` must redirect with `toast_ok` "Price
  restored" or `toast_err` = `user_message`.
- `SPEC-12.31.6` The create form's product dropdown must list only active products; when the product list failed, the
  Prices block must state that the dropdown is empty because the products could not be read. Currency options must be
  usd, eur, gbp and interval options month and year.
- `SPEC-12.31.7` Each price row must show the formatted amount, the recurring interval or "One-time", an Active or
  Archived badge (archived rows dimmed), the product name (falling back to the product id) and the price id.
- `SPEC-12.31.8` An active price must offer Archive (replaced by a disabled button and member count when `member_count`
  is above 0) and a Replace disclosure pre-filled with the amount in dollars (two decimals; 0 when unset), the
  lower-cased currency and the interval (default month); an archived price must offer Unarchive and no Replace.
- `SPEC-12.31.9` Two active prices must be flagged duplicates when they share product id, lower-cased currency,
  recurring interval and interval count (a recurring price with no count counts as 1; one-time prices form their own
  group); each such row must show a warning naming its conflicting sibling ids, and archived prices must not take part.
- `SPEC-12.31.10` An empty price list must render "No prices yet. Create one to get started."

### 12.32 Stripe webhook endpoints

- `SPEC-12.32.1` The webhook URL to register must be the public API origin with trailing slashes removed followed by
  `/v1/webhooks/stripe`.
- `SPEC-12.32.2` An origin must count as public only when it starts with `https://`, has a non-empty host (any port
  removed), and the host is not `localhost`, `127.0.0.1` or `[::1]`; otherwise the form must state that Stripe cannot
  reach the prefilled address.
- `SPEC-12.32.3` The block must show the success box "Webhook processing is active ..." when a webhook signing secret
  is stored and the error box "Webhook processing is not active ..." when it is not.
- `SPEC-12.32.4` `POST /admin/stripe/webhooks` must trim `url`; when empty it must redirect with `toast_err` "Endpoint
  URL is required" without an API call.
- `SPEC-12.32.5` The events text must be split on commas and whitespace, with blanks and duplicates removed keeping
  first-seen order; when no event remains the six events `checkout.session.completed`,
  `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`,
  `invoice.payment_succeeded` and `invoice.payment_failed` must be used; the form's textarea must default to that set.
- `SPEC-12.32.6` On success the handler must render (status 200, not a redirect) the page "Webhook endpoint created":
  when the API returns a signing secret it must show it and state that bunyip saved it; when it does not it must state
  that no secret was returned or saved and tell the admin to paste one on the Stripe page.
- `SPEC-12.32.7` On failure the handler must redirect to `/admin/stripe` with `webhook_error` =
  `user_message_with_reference`, `webhook_url` and `webhook_events` (the events joined by ", "), plus `webhook_ref` =
  the API request id when present.
- `SPEC-12.32.8` `POST /admin/stripe/webhooks/{id}/delete` must redirect with `toast_ok` "Webhook endpoint deleted" or
  `toast_err` = `user_message_with_reference`.
- `SPEC-12.32.9` Each listed endpoint must show its URL, an Enabled badge when its status is `enabled` (else its
  status text), the event count and list, its id and a Delete form; an empty list must render the empty state "No
  webhook endpoints yet ...".

### 12.33 Tier catalog mapping (`POST /admin/tier-settings/catalog`)

- `SPEC-12.33.1` The catalog save must send `free_price_id`, `early_adopter_price_id` and `standard_price_id` trimmed,
  an empty value meaning clear the mapping, and must always send `pricing_enabled`, `lifetime_visible`,
  `early_adopter_visible` and `standard_visible` as booleans (true when the checkbox is present).
- `SPEC-12.33.2` On success the handler must redirect to `/admin/tier-settings` with `toast_ok` "Catalog mapping
  saved"; on failure it must redirect there with `toast_err` = `user_message_with_reference` plus the submitted values:
  the three price ids trimmed and url-encoded, and the four flags as `1` or `0`.
- `SPEC-12.33.3` When the tier configuration cannot be loaded the section must show the error box "Could not load the
  tier catalog mapping." with the error message and request id; otherwise it must render the "Public pricing page"
  switch and the three tier blocks "Free / lifetime", "Early adopter" and "Standard" in one form with the button "Save
  catalog mapping".
- `SPEC-12.33.4` Each rendered control must take the submitted query value when present and the stored value
  otherwise: a price id as trimmed (empty meaning none), a flag as `1` true, `0` false, any other value the stored
  flag.
- `SPEC-12.33.5` Each price select must offer "(none)" with an empty value, every active price as "{amount} - {id}",
  and the current id as "{id} (not in the active list)" when it is not among the active prices.
- `SPEC-12.33.6` Each tier must show the product of its mapped price, or "derived from the price on save" when
  unknown, and when the stored product differs from the mapped price's product it must show the warning badge "Stored
  product differs from the price".
- `SPEC-12.33.7` Each tier must have a toggle "Show this tier on the pricing page" named `lifetime_visible`,
  `early_adopter_visible` or `standard_visible`.
- `SPEC-12.33.8` The pricing status must render as: on a fetch failure, the error box "Could not load the pricing
  status, so this page cannot say what /pricing is serving: {message}"; when published, the success box "/pricing is
  live and advertising: {tier names}."; one error box per reason; and, when unpublished with no reasons, the error
  box "/pricing returns 404 and the API gave no reason. Check the bunyip-api logs."

### 12.34 Users list (`GET /admin/users`)

- `SPEC-12.34.1` The query must normalize as: `status` one of `active`, `suspended`, `all` (anything else `active`);
  `dir` `asc` or else `desc`; `search` trimmed; `page` at least 1 (default 1); `page_size` default 20 clamped to 10
  through 100; `tier`, `verified` and `sort` passed through as given.
- `SPEC-12.34.2` `verified=verified` must filter to verified users, `verified=unverified` to unverified, any other
  value to no filter.
- `SPEC-12.34.3` The handler must fetch the page of users with the filter, sort and paging, and separately the total
  user count for the denominator; when the count fetch fails the count text must fall back to "{n} users".
- `SPEC-12.34.4` A request carrying the `HX-Request` header must receive only the `#users-panel` fragment; any other
  request must receive the full admin page including the panel, the inline loading CSS, the vendored htmx script and
  `admin-users.js`.
- `SPEC-12.34.5` The panel heading must be "Suspended accounts" for `suspended`, "All accounts" for `all`, else "Active
  users"; the result count must read "{filtered} of {all} users" when any filter or non-active status is applied and
  the total is known, else "{filtered} users", and must be absent when the fetch failed.
- `SPEC-12.34.6` When the fetch fails the list must show the error box "Could not reach the API to load users." with
  the API error; when it succeeds with no rows it must show "No users match these filters." with a "Clear all
  filters" action if any filter or non-active status applies, else "No users yet."
- `SPEC-12.34.7` Every panel link must be derived from one query state that emits only non-default parameters
  (search, status, tier, verified, sort with dir, page above 1, page_size not 20); changing search, status, tier,
  verified or page size must reset the page to 1; selecting a sort column must start ascending, and selecting the
  active column again must flip its direction.
- `SPEC-12.34.8` The panel must offer the search input (id `admin-users-search`, `hx-preserve`), Verification and Tier
  dropdowns, an Active / All / Suspended segmented control, removable filter chips with "Clear all" (which keeps sort
  and page size), sortable Email, Tier, Verification and Joined headers, and a pager with Previous / Next and a
  per-page choice of 10, 20, 50 and 100, with Previous / Next only when there is more than one page.
- `SPEC-12.34.9` Each user row must show an avatar initial (first character of the email upper-cased, else "?"), the
  display name (first and last name, either alone, else the email, with the email as a secondary line when a name
  shows), an Admin badge for admins, a Suspended badge for suspended users, the tier label, "Email verified" or "Email
  unverified", "Profile complete" (both names non-blank) or "Name missing", and "Joined {relative time}".
- `SPEC-12.34.10` An active user's row must link to `/admin/users/{id}`; a suspended user's row must not be a link and
  must carry a Reactivate form posting to `/admin/users/{id}/reactivate`.

### 12.35 User detail (`GET /admin/users/{id}`)

- `SPEC-12.35.1` When the user cannot be fetched the page must render "User not found" with the text "Could not load
  user {id}." and a link back to the users list.
- `SPEC-12.35.2` The handler must fetch the first page of 100 rate limits and show an "Active rate limits" card only
  when at least one item has this user's id.
- `SPEC-12.35.3` The handler must fetch the user's newest 25 audit entries; the "User activity" card must show them, or
  "No audit entries for this user." when none, or the error box "Could not reach the API to load this user's audit
  log." when the fetch fails, and must link to `/admin/audit-logs?user_id={id}`.
- `SPEC-12.35.4` The "Real user" classification must be true exactly when at least three of these four signals hold:
  non-blank first name, non-blank last name, verified email, at least one audit entry; the heading must show the
  success badge "Real user" when true and the outline badge "Unverified identity" otherwise.
- `SPEC-12.35.5` The heading must show the display name (else the email) with badges: Admin for admins, Lifetime for
  lifetime members, and "Email unverified" when the email is not verified.
- `SPEC-12.35.6` The Profile card must show user id, email, first and last name ("-" when blank), role, email
  verified, two-factor state, membership status, tier, lifetime flag and grace end when present.
- `SPEC-12.35.7` The Identity & security card must offer an email form (`email` required, a `verified` toggle off by
  default) posting to `/admin/users/{id}/email`, a "Force-verify email" form shown only when the email is unverified,
  and a "Clear 2FA" form shown only when two-factor is enabled.
- `SPEC-12.35.8` The Actions card must offer a Manage Entitlements link and forms for role change (to subscriber when
  the target is an admin, else to admin), password-reset email, Suspend and Delete, each with a confirmation prompt
  naming the user's email.
- `SPEC-12.35.9` The Membership tier card must offer the options lifetime, early_adopter, standard and free regardless
  of the current tier, preselect the current one, and require a `totp_code` field, posting to `/admin/users/{id}/tier`.

### 12.36 User account state actions

- `SPEC-12.36.1` `POST /admin/users/{id}/role` must accept only `admin` or `subscriber`; any other value must redirect
  to `/admin/users` without an API call.
- `SPEC-12.36.2` A valid role change must redirect to `/admin/users` on success; on failure it must log a warning with
  the user id and error and redirect to `/admin/users` with `toast_err` "Could not update user role".
- `SPEC-12.36.3` `POST /admin/users/{id}/delete` must redirect to `/admin/users` on success, and on failure log a
  warning with the user id and redirect with `toast_err` "Could not delete user".
- `SPEC-12.36.4` `POST /admin/users/{id}/suspend` must redirect to `/admin/users` on success, and on failure log a
  warning with the user id and redirect with `toast_err` "Could not suspend user".
- `SPEC-12.36.5` `POST /admin/users/{id}/reactivate` must redirect to `/admin/users?status=suspended` with `toast_ok`
  "User reactivated" on success, and on failure log a warning with the user id and redirect there with `toast_err`
  "Could not reactivate user"; its verification-gate bounce must also target `/admin/users?status=suspended`.
- `SPEC-12.36.6` `POST /admin/users/{id}/reset-password` must redirect to `/admin/users/{id}` with `toast_ok`
  "Password reset email sent" on success, and on failure log a warning with the user id and redirect there with
  `toast_err` "Could not send the password reset".

### 12.37 User identity and security actions

- `SPEC-12.37.1` `POST /admin/users/{id}/email` must trim `email`; when empty it must redirect to `/admin/users/{id}`
  with `toast_err` "Email is required" without an API call; otherwise it must send the email and `verified` (true only
  when the checkbox is present).
- `SPEC-12.37.2` The email update must redirect to `/admin/users/{id}` with `toast_ok` "Email updated" on success and
  `toast_err` "Could not update email" on failure.
- `SPEC-12.37.3` `POST /admin/users/{id}/email/verify` must redirect to `/admin/users/{id}` with `toast_ok` "Email
  verified" on success and `toast_err` "Could not verify email" on failure.
- `SPEC-12.37.4` `POST /admin/users/{id}/two-factor/reset` must redirect to `/admin/users/{id}` with `toast_ok`
  "Two-factor cleared" on success and `toast_err` "Could not clear two-factor" on failure.

### 12.38 User tier and lifetime membership actions

- `SPEC-12.38.1` `POST /admin/users/{id}/tier` must forward the trimmed `tier` and trimmed `totp_code` to bunyip-api,
  which validates both, and must make no other change on a failure.
- `SPEC-12.38.2` The tier change must redirect to `/admin/users/{id}` with `toast_ok` "Tier updated" on success and
  `toast_err` = the API error's `user_message` on failure.
- `SPEC-12.38.3` `POST /admin/users/{id}/lifetime` and `POST /admin/users/{id}/lifetime/revoke` must forward the
  trimmed `totp_code` to the grant or revoke call; they must redirect to `/admin/users/{id}` with `toast_ok`
  "Lifetime membership granted" or "Lifetime membership revoked" on success, and on failure log a warning with the user
  id and redirect with `toast_err` = the API error's `user_message`.

### 12.39 Admin handler unit tests

None: `bunyip-web/src/handlers/admin/tests.rs` and the inline `#[cfg(test)]` modules in the files above are test-only
and define no behavior.

### 12.40 Handler module helpers

Shared helpers in `bunyip-web/src/handlers/mod.rs` used by every web handler. All redirects produced through
`redirect_cookies` are HTTP 303 and relay the given `Set-Cookie` values.

- `SPEC-12.40.1` `ctx` must authenticate the request optionally from the forwarded cookie header and return the auth
  context together with its forward cookie; an anonymous request must yield a context with no user and must not be an
  error.
- `SPEC-12.40.2` `public_ctx` must read the public pricing payload through the shared TTL cache (`AppState::pricing`),
  not a direct API call, and must compute `app_links_allowed` once per render.
- `SPEC-12.40.3` `application_links_allowed` must return `false` for an anonymous visitor and, for a signed-in user,
  must return `!needs_onboarding(user)` so a rendered application link and its destination gate cannot disagree.
- `SPEC-12.40.4` `public_response` must wrap content in the public shell, must show the Pricing link only when
  `pricing.published()` is true, and must relay the context's refreshed cookies on the HTML response.
- `SPEC-12.40.5` `auth_page` must render the public shell with the feedback launcher disabled (`launcher = false`).
- `SPEC-12.40.6` `cookie_value` must return the trimmed value of the first cookie whose trimmed name equals the
  requested name exactly, and `None` when the header is absent or no cookie matches.
- `SPEC-12.40.7` `password_ok` must accept a password only when it is at least 12 bytes long and contains at least one
  ASCII lowercase letter, one ASCII uppercase letter, one ASCII digit and one non-alphanumeric character.
- `SPEC-12.40.8` `names_present` must be true only when both `first_name` and `last_name` are present and non-empty
  after trimming whitespace; the phone number must not be considered.
- `SPEC-12.40.9` `rotating_index(len)` must return `0` when `len` is `0`, otherwise the current clock sub-second
  nanoseconds modulo `len`.
- `SPEC-12.40.10` `dashboard_response`, `dashboard_response_with_avatar_picker` and `admin_response` must relay the
  context's `Set-Cookie` values; only the avatar-picker variant may load the picker stylesheet and
  `assets/js/avatar-picker.js`, and `admin_response` must render the context's feedback badge in the admin sidebar.

### 12.41 Authentication guard and onboarding gate

- `SPEC-12.41.1` `guard` must authenticate the request and, when no user results, must return a 303 redirect to
  `/login` carrying the refreshed cookies; the protected handler must not run.
- `SPEC-12.41.2` `guard` must, for an admin whose two-factor is not enabled, redirect to `/settings/2fa/setup` unless the
  guarded path is exactly `/settings/2fa/setup`, in which case it must return the user without evaluating the
  onboarding gate.
- `SPEC-12.41.3` `guard` must redirect a user to `/onboarding` when `needs_onboarding` is true and the guarded path is
  not onboarding-allowed; it must not evaluate `needs_onboarding` for an allowed path.
- `SPEC-12.41.4` A path must be onboarding-allowed only when it equals `/onboarding`, `/settings/verify-email`,
  `/settings/verify-email/resend` or `/logout`, or starts with `/assets`.
- `SPEC-12.41.5` The onboarding policy must return true when names are missing; otherwise false when the email is
  verified; otherwise false for an admin; otherwise the deployment's email-delivery flag.
- `SPEC-12.41.6` `needs_onboarding` must consult the setup-status flags (through the shared TTL cache) only for a named,
  unverified, non-admin user and must make no API call in every other case.
- `SPEC-12.41.7` When the setup-status flags cannot be read, `needs_onboarding` must treat email delivery as off and
  must log a warning naming the endpoint `/v1/auth/setup/status`.
- `SPEC-12.41.8` `admin_guard` must call `guard` with path `/admin` and must redirect a non-admin to `/dashboard`
  carrying the refreshed cookies.
- `SPEC-12.41.9` `admin_guard` must fetch the admin Feedback new-count once per call and set the badge to the count
  clamped to `0..=u32::MAX`; on fetch failure it must set an explicit unavailable badge with tooltip
  `Feedback count unavailable`, must log a warning with the error, and must not fail the page.

### 12.42 Verification gate on privileged admin actions

- `SPEC-12.42.1` `is_verified` must be true only when `names_present` holds and `email_verified` is true; it must not
  depend on whether mail delivery is configured.
- `SPEC-12.42.2` `verification_gate` must return `None` for a verified user and must return a refusal otherwise,
  admin included.
- `SPEC-12.42.3` A refusal must log a warning with the user id and the back path, and must be a 303 redirect to the
  back path with a `toast_err` query value equal to the URL-encoded `VERIFICATION_REQUIRED_MESSAGE`, joined with `&`
  when the back path already contains `?` and with `?` otherwise, carrying the context cookies.
- `SPEC-12.42.4` `VERIFICATION_REQUIRED_MESSAGE` must read exactly `Verify your email before performing this action. Use
  the resend link on your settings page.`
- `SPEC-12.42.5` Each of these admin handlers must call `verification_gate`: user_role, user_delete, user_suspend,
  user_reactivate, user_reset_password, user_email, user_verify_email, user_reset_2fa, user_grant_lifetime,
  user_revoke_lifetime, user_set_tier, membership_grant, membership_revoke, grant_user_entitlement_h,
  revoke_user_entitlement_h, feedback_respond; the build's tests must fail when one stops doing so.
- `SPEC-12.42.6` The handlers email_save, email_test, email_test_send and system_config_save must not call
  `verification_gate`, so an unverified admin can repair mail delivery; the build's tests must fail when one does.
- `SPEC-12.42.7` No admin handler source that calls `admin_api::` may contain `let _ = admin_api::`; the build's tests
  must fail when one does, so a refused action cannot become a fake success redirect.

### 12.43 Web-edge form validators

All validators return `Err(message)` for the inline error box and run before the API call. Length caps are in bytes.

- `SPEC-12.43.1` `trim_bounded` must trim the value and return `Err("<field> is required")` when empty, and
  `Err("<field> must be <max> characters or fewer")` when longer than `max` bytes.
- `SPEC-12.43.2` `trim_bounded_opt` must return `Ok(None)` for an empty or whitespace-only value, otherwise apply the
  `trim_bounded` length check and return the trimmed value.
- `SPEC-12.43.3` `slug` must trim, then reject empty, longer than 64 bytes, a leading or trailing hyphen, and any byte
  outside lowercase `a-z`, `0-9` and `-`, each with its own message naming the field.
- `SPEC-12.43.4` `url_opt` must return `Ok(None)` for an empty value; otherwise it must reject a value over `max`
  bytes, one that does not parse as a URL (`<field> must be a valid URL`), a scheme other than `http` or `https`
  (`<field> must start with http:// or https://`), and a URL without a host (`<field> must include a host`).
- `SPEC-12.43.5` `parse_i32` must return `0` for an empty or whitespace-only value and must reject any value that does
  not parse as an `i32` with `<field> must be a whole number between -2,147,483,648 and 2,147,483,647`, never
  coercing to `0` or truncating.
- `SPEC-12.43.6` `parse_i32_opt` must apply the `parse_i32` rule but return `Ok(None)` for a blank value.
- `SPEC-12.43.7` `email` must trim, then reject in this order: empty, longer than 254 bytes, no `@`, an empty local
  part or domain, a domain without a dot, and any whitespace; it must accept all other values unchanged.
- `SPEC-12.43.8` `email_opt` must return `Ok(None)` for an empty or whitespace-only value and apply `email` otherwise.

### 12.44 Health endpoint

- `SPEC-12.44.1` `GET /healthz` must answer 200 with `Content-Type: application/json` and the exact body
  `{"status":"ok"}`, require no authentication, and must not call bunyip-api or any datastore.

### 12.45 Organizations route

- `SPEC-12.45.1` `GET /organizations` must be registered regardless of the organizations feature flag and, while the
  flag is off, must answer the same branded 404 the router fallback serves, before the auth guard runs and without any
  redirect.
- `SPEC-12.45.2` While the flag is on, `GET /organizations` must pass `guard` with path `/organizations` (an anonymous
  caller gets a 303 to `/login`) and must render the Organizations page in the dashboard shell with the empty state
  `No organizations yet.`

### 12.46 Onboarding routes

- `SPEC-12.46.1` `GET /onboarding` and `POST /onboarding` must pass `guard` with path `/onboarding`.
- `SPEC-12.46.2` `GET /onboarding` must, when `needs_onboarding` is false, redirect to `/dashboard`; when the request
  carries a session cookie it must first refresh the session and append the rotated cookies to the redirect.
- `SPEC-12.46.3` `GET /onboarding` must, for an unverified user whose request lacks the cookie
  `bunyip_onboard_verify_sent`, request a verification email once and set that cookie with value `1`, `Path=/`,
  `HttpOnly`, `SameSite=Lax` and `Max-Age=3600`; a request carrying the cookie must not send another email.
- `SPEC-12.46.4` When that automatic send fails with status 429, the page must show the error text from
  `verification_message()`; the `error` query parameter must take precedence over it and `ok` must render as a success
  box.
- `SPEC-12.46.5` `POST /onboarding` must trim the first and last name and, when either is empty, redirect to
  `/onboarding?error=Enter both your first and last name.` (URL-encoded) without calling the API.
- `SPEC-12.46.6` `POST /onboarding` with both names must update the profile with the trimmed first name, trimmed last
  name and trimmed phone; on success it must refresh the session, append the rotated cookies and redirect to
  `/onboarding`; on failure it must redirect to `/onboarding?error=<user message>`.
- `SPEC-12.46.7` The onboarding page must render two step cards (name form with inputs limited to 64 characters, and
  email verification showing a resend form posting to `/settings/verify-email/resend` while unverified), a heading
  `Welcome to <brand>` or `Welcome` when the brand name is empty, and the dashboard title `Welcome`.

### 12.47 Login, logout and redirect safety

- `SPEC-12.47.1` `safe_redirect` must return the raw value when it starts with `/` but not `//`, or when it equals the
  configured OIDC issuer origin or starts with `<issuer>/` (trailing slash of the issuer ignored, empty issuer never
  matching); otherwise, and when absent, it must return `/dashboard`.
- `SPEC-12.47.2` `GET /login` must redirect a signed-in visitor to `safe_redirect(redirect)` carrying refreshed cookies,
  except when the `checked` query parameter is present, in which case it must render the login form to avoid a redirect
  loop with `/oauth2/authorize`.
- `SPEC-12.47.3` The login form must post to `/login` with a hidden `redirect` field (default `/dashboard`), a
  `remember` switch, a "Forgot password?" link to `/password-reset`, and a magic-link button that carries the URL-encoded
  redirect.
- `SPEC-12.47.4` `POST /login` must send the trimmed email, the untrimmed password and `remember` (true when the field
  is present) to the API, and on a signed-in outcome must redirect to `safe_redirect(redirect)` with the API's cookies.
- `SPEC-12.47.5` When login requires two-factor, `POST /login` must add the `bunyip_2fa` cookie holding the challenge
  token and redirect to `/login/2fa`, appending `?redirect=<URL-encoded redirect>` when a non-empty redirect was posted.
- `SPEC-12.47.6` When login requires approval, `POST /login` must add the `bunyip_approval` cookie holding the challenge
  token and redirect to `/login/approval`, appending the redirect the same way.
- `SPEC-12.47.7` The `bunyip_2fa` and `bunyip_approval` cookies must have `Path=/`, `HttpOnly`, `SameSite=Lax`,
  `Max-Age=600`, and `Secure` exactly when `Config::cookies_secure(peer ip, headers)` is true; their clearing cookies
  must carry the same attributes with empty value and `Max-Age=0`.
- `SPEC-12.47.8` A failed `POST /login` must re-render the login form (HTTP 200) with the API error's user message in
  the error box and the safe redirect target in the hidden field.
- `SPEC-12.47.9` `POST /logout` must call the API logout and must append, whether or not the API call succeeded, host-only
  clearing cookies for `access_token`, `refresh_token` and `bunyip_op_session` (`Path=/`, `HttpOnly`, `SameSite=Lax`,
  `Max-Age=0`, `Secure` per `cookies_secure`), the same three with `Domain=<app_domain>` when `app_domain` is non-empty,
  and clears for `bunyip_2fa` and `bunyip_approval`.
- `SPEC-12.47.10` `POST /logout` must redirect to `/`, except that a `redirect` query value starting with `/` but not
  `//` must redirect to `/login?redirect=<value>`.

### 12.48 Registration

- `SPEC-12.48.1` `GET /register` must redirect a signed-in visitor to `/dashboard` carrying refreshed cookies.
- `SPEC-12.48.2` `GET /register` must fetch a signup challenge token and the pricing payload concurrently, embed the
  token in a hidden `signup_token` field, and state the entry price in the subtitle only when one is published.
- `SPEC-12.48.3` The registration form must include an off-screen, non-tabbable honeypot input `contact_channel`, the
  `data-pw-guard` attribute, password and confirm inputs that are never pre-filled, a magic-link alternative, and
  password requirement rows with ids `pw-len`, `pw-case`, `pw-digit` and `pw-breach` driven by `assets/js/password.js`.
- `SPEC-12.48.4` `POST /register` must validate in the handler and report every failing rule at once, next to its input:
  an email without `@` (`Enter a valid email address.`), a password failing `password_ok` (`Password does not meet the
  requirements below.`), and, only when the password is valid, a mismatch (`Passwords don't match.`).
- `SPEC-12.48.5` A rejected `POST /register` must re-render the form (HTTP 200) preserving the trimmed email and signup
  token, leaving both password fields empty, and showing a hint to re-enter the password.
- `SPEC-12.48.6` A valid `POST /register` must call the API register with the trimmed email, password, honeypot value
  and signup token and, on success, redirect to `/onboarding` with the API's cookies.
- `SPEC-12.48.7` When the API rejects registration, the form must re-render with the API user message as the top
  banner, not attributed to a field, and the email preserved.

### 12.49 Magic-link sign-in

- `SPEC-12.49.1` `GET /magic-link` without a `token` must render the request form with an autofocused email input.
- `SPEC-12.49.2` `GET /magic-link?token=` must verify the token with the API and, on a signed-in outcome, redirect to
  `safe_redirect(redirect)` with the API's cookies.
- `SPEC-12.49.3` A magic-link verification requiring two-factor or approval must set the `bunyip_2fa` or
  `bunyip_approval` cookie and redirect to `/login/2fa` or `/login/approval`, carrying a non-empty `redirect` as
  `?redirect=<URL-encoded>`.
- `SPEC-12.49.4` A failed magic-link verification must render a `Verification Failed` card with the API user message and
  a link to `/magic-link`.
- `SPEC-12.49.5` `POST /magic-link` must request a link for the trimmed email; on success it must render the
  `Check your email` card stating the link expires in 15 minutes, and on failure the form with the API user message.

### 12.50 Password reset

- `SPEC-12.50.1` `POST /password-reset` must request a reset for the trimmed email; on success it must render the card
  `If an account exists with that email, we've sent reset instructions.` stating the link expires in 1 hour, and on
  failure the form with the API user message.
- `SPEC-12.50.2` `GET /password-reset/confirm` without a `token` must render an `Invalid Reset Link` card linking to
  `/password-reset`; with a token it must render the new-password form carrying the token in a hidden field.
- `SPEC-12.50.3` `POST /password-reset/confirm` must reject a password failing `password_ok` with `Password does not
  meet the requirements`, then a mismatch with `Passwords don't match`, re-rendering the form without calling the API.
- `SPEC-12.50.4` A valid `POST /password-reset/confirm` must call the API with the token and password and, on success,
  redirect to `/login`; on failure it must re-render the form with the API user message.

### 12.51 Two-factor and login-approval challenges

- `SPEC-12.51.1` `GET /login/2fa` and `GET /login/approval` must render a `No pending verification` card linking to
  `/login` when the `bunyip_2fa` or `bunyip_approval` cookie is absent.
- `SPEC-12.51.2` `GET /login/2fa` with the cookie must render the six-digit authenticator form, or the recovery-code
  form (maximum 19 characters) when the `recovery` query parameter is present, carrying a non-empty `redirect` as a
  hidden field.
- `SPEC-12.51.3` `POST /login/2fa` and `POST /login/approval` without their cookie must redirect to `/login`.
- `SPEC-12.51.4` `POST /login/2fa` must verify the trimmed code against the challenge cookie value and, on success,
  append the clearing `bunyip_2fa` cookie to the API's cookies and redirect to `safe_redirect(redirect)`.
- `SPEC-12.51.5` A failed `POST /login/2fa` must re-render the same variant (authenticator or recovery, per the posted
  `recovery` field) with the API user message and the redirect preserved.
- `SPEC-12.51.6` `POST /login/approval` must verify the trimmed code against the `bunyip_approval` cookie value and, on
  success, append the clearing `bunyip_approval` cookie and redirect to `safe_redirect(redirect)`; on failure it must
  re-render the approval card with the API user message.

### 12.52 Invites and emailed token links

- `SPEC-12.52.1` `GET /invite/accept` without a token must render an `Invitation Failed` card reading `No invite token
  provided.`
- `SPEC-12.52.2` `GET /invite/accept?token=` must pre-accept the invite: when the API returns an email it must render the
  password form for that email; when it returns a signed-in session it must redirect to `/dashboard` with its cookies;
  any other success must render the form for `your account`; an error must render `Invitation Failed` with the API
  user message.
- `SPEC-12.52.3` `POST /invite/accept` must reject a mismatch (`Passwords do not match`) before a password failing
  `password_ok` (`Password does not meet the requirements`) and re-render the form without calling the API.
- `SPEC-12.52.4` A valid `POST /invite/accept` must send the token and password to the API; a returned session must
  redirect to `/dashboard` with its cookies, a success without a session must re-render with `Failed to accept invite`,
  and an error must re-render with the API user message.
- `SPEC-12.52.5` `GET /settings/confirm-email` must render `Invalid Link` without a token, `Email Updated` (telling the
  user to log in with the new address) when the API confirms the change, and `Confirmation Failed` with the API user
  message otherwise.
- `SPEC-12.52.6` `GET /settings/verify-email` must render `Invalid Link` without a token and `Verification Failed` with
  the API user message on error.
- `SPEC-12.52.7` A successful verification must render `Email Verified!` with copy chosen by the returned tier:
  `lifetime`, `early_adopter` and `standard` each have their own sentence and any other tier gets `Your email address
  has been verified successfully.`; the card must link to `/dashboard`.
- `SPEC-12.52.8` After a successful verification the handler must refresh the session and relay the rotated cookies
  only when the request carried a session cookie; a refresh failure must not fail the verification page.

### 12.53 OIDC consent screen

- `SPEC-12.53.1` `GET /oauth2/consent` and `POST /oauth2/consent` must pass `guard` with path `/oauth2/consent`.
- `SPEC-12.53.2` `GET /oauth2/consent` must redirect to `/dashboard` when `missing` holds no scope after whitespace
  splitting.
- `SPEC-12.53.3` The application name and logo shown must come only from a lookup by `client_id` against bunyip-api,
  never from the query string; a failed lookup must render the generic `An application` identity.
- `SPEC-12.53.4` Each requested scope must render one line: `profile` as `Your first and last name`, `phone` as `Your
  phone number`, any other scope as `Additional account details`.
- `SPEC-12.53.5` A logo must render as an image only when its trimmed URL starts with `https://` or `/`; otherwise the
  card must show the name initial (uppercased) or, with no name, a generic application icon.
- `SPEC-12.53.6` The lead sentence must be `<name> is requesting access to your <brand> account. Approve below to
  continue.`, using `An application` when no non-blank name exists and `your account` when the brand is empty; names
  must be rendered as escaped text.
- `SPEC-12.53.7` The consent form must post hidden `client_id`, `scopes` (the `missing` value) and `continue_url`
  fields and two submit buttons named `action` with values `allow` and `deny`.
- `SPEC-12.53.8` `continue_under_issuer` must be true only when the trimmed URL equals the configured OIDC issuer origin
  (trailing slash ignored) or starts with `<origin>/`, and false when the issuer is empty.
- `SPEC-12.53.9` `POST /oauth2/consent` with any `action` other than `allow` must redirect to `continue_url` with
  `consent=denied` appended (`&` if it has a query, else `?`) when `continue_under_issuer` holds, and otherwise to
  `/dashboard?error=Authorization+declined.`
- `SPEC-12.53.10` `POST /oauth2/consent` with `allow` and an empty `client_id` must redirect to
  `/dashboard?error=Invalid+client+id.` without calling the API.
- `SPEC-12.53.11` `allow` must post `{client_id, scopes}` (scopes split on whitespace) to `/users/me/consents`; a
  transport error or a non-success answer must redirect to `/dashboard?error=Could+not+save+consent.`
- `SPEC-12.53.12` After a saved consent the handler must log at info (target `consent_post`) the client id, scopes and
  destination, and must redirect to `continue_url` when `continue_under_issuer` holds, otherwise to `/dashboard`.

### 12.54 Dashboard, applications and downloads

- `SPEC-12.54.1` `GET /dashboard` must pass `guard`, fetch the application list, the Stripe-enabled flag and the pricing
  payload concurrently, and show a rotating tagline from a fixed list of five.
- `SPEC-12.54.2` Application lists fetched for `/dashboard` and `/applications` must render three distinct states: a
  fetch failure as an error box `Could not reach the API to load applications.`, an empty catalog as `No applications
  are available yet.`, and otherwise the tiles.
- `SPEC-12.54.3` A dashboard tile must show the badge Maintenance when in maintenance, else Active when accessible,
  else Locked; an inaccessible tile must show a disabled button reading `Membership Required` for a non-member,
  `Under Maintenance` for a maintenance application and `Not Available` otherwise.
- `SPEC-12.54.4` An accessible tile or card must link to the application's launch URL in a new tab with
  `rel="noopener noreferrer"`; when no launch URL exists, including the application with slug `lets-chat` while the
  community feature is not configured, it must show a disabled `Not configured` button.
- `SPEC-12.54.5` The dashboard membership panel must show a `Manage` link to `/membership` for a member; for a non-member
  it must show `Subscribe Now` linking to `/membership` when Stripe is enabled and a disabled `Payment is not
  configured` button otherwise.
- `SPEC-12.54.6` `membership_badge` must choose the first applicable label: Admin for an admin, Lifetime for a lifetime
  member, Trial while a future trial end exists, else by membership status: Active, Grace Period, Past Due, Canceled,
  Incomplete, and `No Membership` for any other status.
- `SPEC-12.54.7` `membership_status` text must be, in order: `Lifetime member` for a lifetime member, `Trial ends in N
  day(s)` while a trial end exists, for an Active member `You have access to all applications.` plus `Price locked`
  (with ` at <price>` only when a locked amount exists) when the price is locked, else the access sentence alone.
- `SPEC-12.54.8` `GET /community` must pass `guard` and redirect a member to the configured community URL, a non-member
  to `/membership`, and a member with no configured URL to `/dashboard`.
- `SPEC-12.54.9` `GET /applications` must pass `guard` and fetch applications, groups, downloads and the Stripe flag
  concurrently; each failing auxiliary fetch must degrade only its part of the page.
- `SPEC-12.54.10` When the groups fetch fails the page must log a warning naming `/v1/application-groups` with the error
  message and code and render a flat list; when the downloads fetch fails it must log a warning naming `/v1/downloads`
  and render cards without a download affordance.
- `SPEC-12.54.11` `/applications` must render one section per non-empty group in API order, an ungrouped section
  (headed `Other` only when at least one group section exists) for applications whose group is missing, and a
  `More downloads` section for download groups matching no application slug; a non-member must see a membership banner.
- `SPEC-12.54.12` An application card must show its host only for a declared subdomain, a `Release notes` link when
  `release_notes_url` is non-empty, and a `Backup & Restore` link to `/integrations/backup` for slug `backup`.
- `SPEC-12.54.13` `GET /downloads` must answer a permanent redirect (HTTP 308) to `/applications` and `GET /billing` a
  permanent redirect (HTTP 308) to `/membership`, without authentication.
- `SPEC-12.54.14` `GET /downloads/{slug}/{asset}` must pass `guard` with path `/downloads`, request the asset from the
  API with the user's cookie, and on a 2xx answer stream the body with the upstream `Content-Type` (default
  `application/octet-stream`), upstream `Content-Disposition` (default `attachment; filename="<name>"` with backslash and
  quote escaped) and upstream `Content-Length` when present.
- `SPEC-12.54.15` A non-2xx or failed download answer must never be relayed as the file: a 401 must redirect to
  `/login` and any other failure to `/downloads`, each carrying the context cookies.
- `SPEC-12.54.16` The download affordance must render nothing when the product has neither binary assets nor an OCI
  image, an `Upgrade to access` link to `/membership` for a non-member, and otherwise a button labelled `Download`,
  `OCI` or `Download/OCI` that opens a dialog with id `dl-<slug>` through a `data-dialog-open` attribute.
- `SPEC-12.54.17` Registry host, image reference and asset names must appear only as escaped text and `data-copy`
  attributes, never as executable script.
- `SPEC-12.54.18` The container instructions must list `docker login <registry>`, `docker pull <reference>`,
  `docker run --rm <reference>` and a compose skeleton using the reference; the binary instructions must link
  `/downloads/<url-encoded slug>/<url-encoded asset>` and show `chmod +x <name> && ./<name> --help`.
- `SPEC-12.54.19` A download-only card (no matching application) must show a disabled `Requires access` button when the
  user lacks access to the product and a `Documentation` link to `/apps/<slug>/docs` only when the product has docs.
- `SPEC-12.54.20` Money and dates in these pages must format as `<CURRENCY> <amount with 2 decimals>` (cents / 100),
  `%B %-d, %Y` dates, and sizes as `<n.n> MB` at or above 1 MiB else `<n.n> KB`.

### 12.55 Membership and billing routes

- `SPEC-12.55.1` `GET /checkout/success` must pass `guard` and show the `Welcome aboard` card with the user's tier name
  only when the user is a lifetime member or the membership status is Active; otherwise it must show `Finalizing your
  membership` with a `data-reload-after="3000"` marker so the page refreshes every 3 seconds.
- `SPEC-12.55.2` `GET /membership-required` must pass `guard` and show the cheapest published monthly price only when
  one exists.
- `SPEC-12.55.3` `GET /membership` must pass `guard`, fetch membership, payment history, invoices, the Stripe flag and
  pricing concurrently, show `ok` and `error` query values as success and error boxes, and show a fetch failure of
  invoices or payment history as an error box distinct from the empty states `No invoices yet.` and `No payment history
  yet.`
- `SPEC-12.55.4` The plan card must treat a user as holding a plan only when not a lifetime member and the status is
  Active, Past Due or Grace Period; a lifetime member must see `No billing. Access never expires.` and no cancel
  controls; a user without a plan must see `No Active Membership` with a `Subscribe` form posting to
  `/membership/subscribe` when Stripe is enabled, else a disabled `Payment is not configured` button.
- `SPEC-12.55.5` A Past Due membership must show a dunning banner naming `by <grace period end date>` when a grace end
  exists and `before your grace period ends` otherwise.
- `SPEC-12.55.6` The plan price must be the member's locked amount (with the pricing currency and the tier's interval)
  when the price is locked, else the tier's published price; when none exists it must read `See pricing`. A missing
  current period end must read `End of the current billing period`.
- `SPEC-12.55.7` For a plan holder the page must show a `Manage Billing` form posting to `/membership/billing-portal`
  and either a `Reactivate Membership` form posting to `/membership/reactivate` (when cancel-at-period-end is set) or a
  cancel choice offering `/membership/cancel` and `/membership/cancel-now`, the latter requiring a
  `data-confirm` confirmation.
- `SPEC-12.55.8` `POST /membership/subscribe` must pass `guard`, create a checkout session and redirect to its URL only
  when it starts with `https://checkout.stripe.com/`; any other URL or an API error must redirect to
  `/membership?error=<message>`.
- `SPEC-12.55.9` Checkout error messages must be mapped: text containing `No active price configured`, text containing
  `Stripe is not configured`, and the generic `An unexpected error occurred. Please try again later.` each to their
  fixed operator-facing sentence, an empty message to `Could not start checkout. Please try again or contact support.`,
  and any other message unchanged.
- `SPEC-12.55.10` `POST /membership/cancel`, `/membership/cancel-now` and `/membership/reactivate` must pass `guard`,
  call the corresponding API operation, append any cookies it returns and redirect to `/membership`.
- `SPEC-12.55.11` `POST /membership/billing-portal` must pass `guard` and redirect to the portal URL the API returns;
  on an API error it must redirect to `/membership?error=<user message>`.
- `SPEC-12.55.12` `tier_name` must map Lifetime, Free, Early Adopter, Standard to those labels and an unknown tier to
  `Unknown` without failing the response.

### 12.56 Settings routes

All `POST /settings/...` actions below must pass `guard`, answer 303, and on failure redirect to
`/settings?error=<URL-encoded API user message>` unless stated otherwise.

- `SPEC-12.56.1` `GET /settings` must pass `guard`, treat `session_page` and `device_page` as 1-indexed with a floor of
  1, and use a page size of 20 for sessions and trusted devices.
- `SPEC-12.56.2` `GET /settings` must read the two-factor status from the API, falling back to the user's own
  `two_factor_enabled` when the read fails, and must fetch trusted devices only when two-factor is enabled.
- `SPEC-12.56.3` The sessions and trusted-devices cards must show a failed fetch as an error box naming the list, an
  empty list as `No active sessions found.` or `No trusted devices.`, and rows with a revoke form; the current session
  must be badged `This device` and have no revoke form.
- `SPEC-12.56.4` The sessions card must offer `Log out all other devices` (confirmed) whenever the total session count
  exceeds one, even if the others are on another page.
- `SPEC-12.56.5` The two-factor card must offer password-and-code disabling only for non-admins, state that admin
  accounts cannot disable two-factor, and offer recovery-code regeneration and authenticator reset to every
  two-factor user.
- `SPEC-12.56.6` The Danger Zone delete form must include the two-factor code input only when the user has two-factor
  enabled, and its copy must name the brand (or `this app` when the brand is empty).
- `SPEC-12.56.7` `POST /settings/sessions/{id}/revoke` and `POST /settings/sessions/revoke-others` must revoke the
  session or all other sessions and redirect to `/settings?ok=Session+revoked` or `/settings?ok=Logged+out+other+devices`.
- `SPEC-12.56.8` `POST /settings/trusted-devices/{id}/revoke` must revoke the device and redirect to
  `/settings?ok=Trusted+device+revoked`.
- `SPEC-12.56.9` `POST /settings/profile` must send first name, last name and phone exactly as submitted (an empty
  value clears the field) and redirect to `/settings?ok=Profile+saved`.
- `SPEC-12.56.10` `POST /settings/avatar` must read the multipart field `avatar` and reject, before calling the API, a
  missing file (`No image was selected.`), an empty file (`The selected file is empty.`) and a file over 2 MiB
  (`The image must be 2 MB or smaller.`); the route must accept request bodies up to 3 MiB.
- `SPEC-12.56.11` `POST /settings/avatar` and `POST /settings/avatar/remove` must answer JSON when the `Accept` header
  contains `application/json`: 200 `{"ok":true}` on success and 400 `{"error":"<message>"}` on any failure, relaying
  refreshed cookies; otherwise they must redirect to `/settings?ok=Profile+photo+updated`,
  `/settings?ok=Profile+photo+removed` or the error form.
- `SPEC-12.56.12` `GET /me/avatar` must answer 404 when `guard` fails or the API answer is not 2xx, and otherwise stream
  the avatar with the upstream `Content-Type` and `Cache-Control: private, max-age=300`.
- `SPEC-12.56.13` `POST /settings/email` must reject with the validator message when `validate::email` fails for
  `New email`, and with `Please enter your current password` when the password is empty, before calling the API.
- `SPEC-12.56.14` A successful `POST /settings/email` must append the API's cookies and redirect to `/login` when the API
  requires re-login, else to `/settings?ok=Email+change+requested`.
- `SPEC-12.56.15` `POST /settings/password` must reject a mismatch (`Passwords don't match`) before a policy failure
  (`Password does not meet the requirements`) without calling the API, and on success redirect to
  `/settings?ok=Password+updated`.
- `SPEC-12.56.16` `POST /settings/2fa/disable` must send the password and code to the API and on success redirect to
  `/settings?ok=Two-factor+disabled`.
- `SPEC-12.56.17` `POST /settings/verify-email/resend` must pass `guard` with that path and redirect the outcome to
  `/onboarding` when `needs_onboarding` holds, else to `/settings`: success as `ok=Verification email sent to <email>`,
  failure as `error=<verification_message()>`.
- `SPEC-12.56.18` `POST /settings/account/delete` must reject a blank password with `Enter your current password to
  confirm account deletion.` before calling the API, send no code when the code is empty, and on success append the
  API's cookies and redirect to `/`.

### 12.57 Two-factor settings flows

- `SPEC-12.57.1` `GET /settings/2fa/setup` must pass `guard` with that path, make no setup API call, and show the
  already-enabled page when two-factor is on, else the password step.
- `SPEC-12.57.2` `POST /settings/2fa/setup` with an empty password must re-render the password step with `Enter your
  current password.` without calling the API.
- `SPEC-12.57.3` `POST /settings/2fa/setup` with a password must start setup through the API and render the QR view with
  the returned setup token in a hidden field posting to `/settings/2fa/setup/confirm`; status 409 must render the
  already-enabled page, error code `VALIDATION_ERROR` must show the message under the password input, and any other
  error must show it above the card.
- `SPEC-12.57.4` The QR view must blur the QR code and manual key until revealed by a no-JavaScript checkbox toggle and
  must render a six-digit code input limited to 6 characters.
- `SPEC-12.57.5` `POST /settings/2fa/setup/confirm` must confirm with the trimmed code and setup token and on success
  show the recovery codes panel; on failure it must resume the same setup by token and re-render the same key with the
  error, and when resume also fails show the error with a `Start again` link to `/settings/2fa/setup`.
- `SPEC-12.57.6` The recovery codes panel must show the codes blurred until revealed, provide Copy and Download controls
  carrying the same plaintext (one code per line, trailing newline) with the file name
  `<brand-slug>-recovery-codes-<YYYY-MM-DD>.txt` (`platform` when the brand slug is empty), and keep its `Done` link to
  `/settings` hidden until a copy or download has happened.
- `SPEC-12.57.7` `GET /settings/2fa/recovery-codes` must pass `guard` and render the password form; `POST` must
  regenerate codes with the password and show the new codes once, or re-render the form with the API user message.
- `SPEC-12.57.8` `GET /settings/2fa/rekey` must pass `guard` and render the password-and-current-code form; `POST` must
  begin the re-key with the password and trimmed code and render the QR view posting to
  `/settings/2fa/rekey/confirm`, or re-render the form with the API user message.
- `SPEC-12.57.9` `POST /settings/2fa/rekey/confirm` must confirm the re-key with the trimmed code and show the new
  recovery codes on success, or the code-only form with the API user message and a restart link on failure.

## 13. Shared web UI crate

### 13.1 Crate scope

- `SPEC-13.1.1` The web-kit crate must stay branding-free: no function, constant or markup in it may name a product, read
  the branding record, reference an application route or depend on API types; consumers must pass those in.
- `SPEC-13.1.2` The crate must expose exactly the modules `avatar`, `client_ip`, `common`, `csrf`, `shell` and `ui`.
- `SPEC-13.1.3` The crate must not own the content-security-policy layer or the browser scripts (`app.js`, `password.js`,
  `theme.js`); the consumer must supply the policy and serve the scripts from its own `/assets` directory.
- `SPEC-13.1.4` The crate's manifest must allow `dead_code` so public helpers that a given consumer does not use do not
  fail the build.

### 13.2 CSRF: origin check scope

- `SPEC-13.2.1` `csrf::enforce_origin_with` must pass `GET`, `HEAD` and `OPTIONS` requests through without any check.
- `SPEC-13.2.2` The middleware must pass through, unchecked, a request whose URI path equals an entry of the exemption
  list given as state; matching must be exact-path equality, never a prefix.
- `SPEC-13.2.3` The exemption list must be a `&'static [&'static str]` supplied by the consumer, and a consumer that
  mounts no protocol-authenticated endpoint must pass an empty list.

### 13.3 CSRF: origin decision

- `SPEC-13.3.1` For every other method the middleware must pass the request through only when the `Host` header equals
  the host (and port, when present) parsed from the `Origin` header.
- `SPEC-13.3.2` When `Origin` is absent, the middleware must apply the same comparison to the `Referer` header.
- `SPEC-13.3.3` When `Origin` is present, the middleware must not fall back to `Referer`, whatever its value.
- `SPEC-13.3.4` The middleware must refuse the request when `Host` is absent, when both `Origin` and `Referer` are
  absent, when the compared header is not valid UTF-8, or when it does not parse as a URL with a host (including the
  literal `null`).
- `SPEC-13.3.5` A refused request must be answered HTTP 403 with the body `Cross-origin request refused (CSRF). Open the
  page directly and try again.` and the handler must not run.
- `SPEC-13.3.6` A refusal must be logged at `warn` with the method, path, `Host`, `Origin` and `Referer` values.
- `SPEC-13.3.7` The host extracted from a URL must be `host`, or `host:port` when the URL carries a non-default port (the
  URL parser drops a scheme-default port); the path, query and fragment must be ignored.

### 13.4 Client IP forwarding: resolution

- `SPEC-13.4.1` `resolve_forwarded_ip` must return `None` unless the socket peer address is known and falls inside one
  of the trusted-proxy CIDRs; an empty CIDR list or an unknown peer must always yield `None`.
- `SPEC-13.4.2` For a trusted peer it must return the first comma-separated `X-Forwarded-For` entry (trimmed) when that
  entry parses as an IP address.
- `SPEC-13.4.3` For a trusted peer whose `X-Forwarded-For` is absent or whose first entry does not parse, it must fall
  back to `X-Real-IP` (trimmed), and return `None` when that is absent or unparseable.
- `SPEC-13.4.4` The resolver must never fabricate an address: for an untrusted peer it must forward nothing, so the
  backend attributes the request to the front end itself.

### 13.5 Client IP forwarding: request scope

- `SPEC-13.5.1` `forward_client_ip` must resolve the IP once per request from `ConnectInfo<SocketAddr>`,
  `X-Forwarded-For` and `X-Real-IP`, using the trusted CIDRs given as state.
- `SPEC-13.5.2` The middleware must run the rest of the stack inside a task-local scope holding the resolved IP, so
  `client_ip::current()` returns it to outbound API calls made by the handler.
- `SPEC-13.5.3` `current()` and `current_ua()` must return `None` outside a request scope and must never panic.
- `SPEC-13.5.4` The middleware must also capture the request `User-Agent` (truncated to its first 512 characters) in a
  task-local read by `current_ua()`; the user agent must be forwarded regardless of whether the peer is trusted.

### 13.6 Asset versioning and process-wide installs

- `SPEC-13.6.1` `asset(path)` must return `<path>?v=<asset version>`; every `/assets/*` reference in markup must go
  through it so a deploy defeats the immutable cache.
- `SPEC-13.6.2` `asset_version()` must return the version installed by `install_asset_version`, or `dev` when none was
  installed.
- `SPEC-13.6.3` `install_asset_version`, `install_sse_api_origin`, `install_community_enabled` and
  `install_default_share_image` must set a process-wide value once from `main`; a later call must not replace it.
- `SPEC-13.6.4` `install_sse_api_origin` must strip trailing `/` characters from the origin; `sse_api_origin` must
  return `http://localhost:4401` when none was installed.
- `SPEC-13.6.5` `community_enabled()` must be `false` until installed; `default_share_image()` must be `None` until
  installed with a value.

### 13.7 Feature flags

- `SPEC-13.7.1` `orgs_enabled()` must be `false` until `install_orgs_enabled` is called, and every later call must
  replace the value without a restart.
- `SPEC-13.7.2` `install_features` must replace the entire feature map with the given key/boolean pairs.
- `SPEC-13.7.3` `feature_enabled(key)` must return the installed boolean, and `false` for a key that is absent.
- `SPEC-13.7.4` Reading or replacing the feature map after a panicking writer poisoned its lock must still succeed,
  using the poisoned guard's inner value.

### 13.8 Theme and palette

- `SPEC-13.8.1` `palette_value(record)` must return `None` for an empty string and `Some(record)` otherwise, with no
  compiled-in colour fallback, so an unbranded deployment omits the markup.
- `SPEC-13.8.2` `theme_controls(icon_class)` must render two ghost icon buttons: `Toggle theme` (attribute
  `data-theme-toggle`, sun and moon icons) and `Toggle high contrast` (attribute `data-contrast-toggle`, contrast
  icon), with no inline script handlers.
- `SPEC-13.8.3` `sse_subscriber_script()` must render a deferred `<script>` for the versioned `/assets/js/sse.js` that
  passes the API origin only as the `data-api-origin` attribute.

### 13.9 Navigation rows

- `SPEC-13.9.1` `nav_links(sections, active)` must render the sections in order, separated by a divider element before
  every section after the first.
- `SPEC-13.9.2` A row whose `href` equals `active` must carry `aria-current="page"` and the active class set; every
  other row must carry the inactive class set and no `aria-current`.
- `SPEC-13.9.3` A row marked `external` must open in a new tab (`target="_blank"`, `rel="noopener noreferrer"`) and end
  with an external-link icon; non-external rows must carry neither attribute.
- `SPEC-13.9.4` Each row must render its icon, then its title, then its optional badge, then the external-link icon.

### 13.10 Navigation badges

- `SPEC-13.10.1` `NavBadge::Count(0)` must render no element, identical to an item with no badge.
- `SPEC-13.10.2` `NavBadge::Count(n)` with `n` between 1 and 99 must render a pill showing `n` with
  `aria-label="<n> new"`.
- `SPEC-13.10.3` `NavBadge::Count(n)` with `n` above 99 must show the text `99+` while the `aria-label` keeps the true
  count.
- `SPEC-13.10.4` `NavBadge::Unavailable { tooltip }` must render a destructive-styled pill showing `!` whose `title` and
  `aria-label` are the tooltip text, so a failed count fetch never reads as zero.

### 13.11 Shell layout and admin blocks

- `SPEC-13.11.1` The crate must export the shell class constants `APP_SHELL_CLASS`, `APP_COLUMN_CLASS` and
  `APP_MAIN_CLASS`, which pin the authenticated shell to the viewport from the `md` breakpoint up so the sidebar and
  `<main>` scroll independently, and leave natural document scroll below `md`.
- `SPEC-13.11.2` `admin_block(title, subtitle, body)` must render a card with an `h3` title, an optional subtitle
  paragraph (omitted for `None`) and the body.
- `SPEC-13.11.3` `admin_block_grid(blocks)` must render the blocks in input order in a grid with one column below the
  `lg` breakpoint and two columns from `lg`, top-aligned.

### 13.12 Auth card

- `SPEC-13.12.1` `auth_card(icon, icon_class, title, subtitle, body)` must render a centered card with a round icon
  bubble, an `h3` title, a subtitle paragraph and the body.
- `SPEC-13.12.2` `auth_card_plain` must render the same card without the icon bubble.
- `SPEC-13.12.3` Both cards must omit the subtitle paragraph when the subtitle is the empty string.

### 13.13 Icons

- `SPEC-13.13.1` `icon(name, class)` must render an inline 24x24 `<svg>` (`viewBox="0 0 24 24"`, no fill,
  `stroke="currentColor"`, stroke width 2, round caps and joins) carrying `class` and the SVG body for `name`.
- `SPEC-13.13.2` The icon set must contain exactly these names: sun, moon, contrast, user, log-out, alert-circle,
  loader, arrow-right, arrow-left, external-link, credit-card, app-window, layout-dashboard, banknote, download, upload,
  chevron-down, menu, chevron-right, chevron-up, chevrons-up-down, grip-vertical, receipt, settings, users, file-text,
  shield, shield-check, shield-off, shield-alert, message-square-quote, smile-plus, check-circle, check, x, mail, copy,
  trash, key, lock, alert-triangle, trending-up, activity, log-in, user-plus, user-cog, link-2, save, layers, package,
  gauge, history, sliders-horizontal, globe, briefcase, help-circle, circle, circle-check, circle-x, eye, eye-off.
- `SPEC-13.13.3` `icon_is_known(name)` must return `true` exactly when `name` is in the icon set, so a consuming crate's
  guard can fail a build on an unknown name.
- `SPEC-13.13.4` `icon` with a name outside the set must render an empty `<svg>`; callers must not pass such a name, and
  the consuming crate's icon guard must fail on it.

### 13.14 Buttons

- `SPEC-13.14.1` `button_class(variant, size, extra)` must return `<base> <variant classes> <size classes> <extra>`,
  where the base carries inline-flex centering, focus ring and disabled styling that removes pointer events.
- `SPEC-13.14.2` The button variants must be `default` (primary fill), `destructive`, `outline`, `secondary`, `ghost`,
  `brand` (skinnable brand fill), `inverse` (white fill, darkest brand label) and `link`; any other name must resolve
  to the `default` variant.
- `SPEC-13.14.3` The button sizes must be `xs` (h-8), `sm` (h-9), `lg` (h-11), `icon` (h-10 w-10) and the default
  (h-10 with padding); any other name must resolve to the default size.
- `SPEC-13.14.4` A color or size that a variant does not provide must be added as a new variant or size, never as an
  `extra` that fights the variant's utility for the same CSS property.
- `SPEC-13.14.5` `disabled_button` must render a `<button type="button" disabled>` whose visible label is the stated
  reason, with no `title` tooltip carrying the reason.

### 13.15 Links, pager, badges

- `SPEC-13.15.1` `back_link(href, label)` must render an anchor with an `arrow-left` icon and the label, styled as a
  link, not as a button.
- `SPEC-13.15.2` `pager(base, param, page, total_pages)` must render nothing when `total_pages` is 1 or less.
- `SPEC-13.15.3` The pager must render `Page <page> of <total_pages>`, a `Previous` link when `page > 1` and a `Next`
  link when `page < total_pages`, as plain anchors (no htmx).
- `SPEC-13.15.4` Pager links must be `<base>?<param>=<n>`, or `<base>&<param>=<n>` when `base` already contains `?`, so
  independent pagers on one page do not share a parameter.
- `SPEC-13.15.5` `badge(variant, text)` must render a rounded pill whose colors come from the variant `secondary`,
  `destructive`, `outline`, `success` (teal) or `warning` (amber, step 800 on light and 300 on dark), with the primary
  style for any other name.

### 13.16 Toggle switches

- `SPEC-13.16.1` `toggle_switch(on, label)` must render a `<button type="submit" role="switch">` with
  `aria-checked="true"` or `"false"` per `on` and `aria-label` set to `label`, a primary track and right knob when on,
  and a muted track and left knob when off.
- `SPEC-13.16.2` `toggle_switch_field(id, name, checked, label)` must render a visually hidden
  `<input type="checkbox" role="switch">` with the given `id` and `name`, value `true`, `checked` only when `checked`,
  and `aria-label` set to `label`, plus a track and knob that follow the checked state; unchecked, the field must be
  absent from the form POST.

### 13.17 Banners and empty state

- `SPEC-13.17.1` `error_box`, `success_box` and `warning_box` must render the message after truncating it to at most
  256 bytes, cutting on a UTF-8 character boundary; messages of 256 bytes or fewer must be rendered unchanged.
- `SPEC-13.17.2` The message must be rendered through Maud escaping; truncation must not be relied on as an XSS guard.
- `SPEC-13.17.3` `error_box_detailed(headline, cause, reference)` must render the headline, then the optional cause,
  then the optional `Reference: <reference>` in a monospace line, each clamped to 256 bytes independently.
- `SPEC-13.17.4` `error_box` and `error_box_detailed` must use the destructive style with an `alert-circle` icon;
  `success_box` must use a `check` icon; `warning_box` must use the amber pair and an `alert-triangle` icon.
- `SPEC-13.17.5` `empty_state(icon, message, cta)` must render a centered column with a large muted icon and a muted
  message, and render the call to action in a wrapper only when `cta` is `Some`.

### 13.18 Avatar picker

- `SPEC-13.18.1` The `Avatar` trait must give the picker the current avatar URL (`None` when unset) and a single-letter
  fallback initial.
- `SPEC-13.18.2` `avatar_picker(user, upload_action, remove_action)` must render a container with the attributes
  `data-avatar-picker`, `data-upload-url`, `data-remove-url`, `data-max-bytes="2097152"` and `data-max-edge="512"`.
- `SPEC-13.18.3` The picker must work without JavaScript: a `multipart/form-data` `POST` form to `upload_action` with a
  file input named `avatar` accepting `image/png`, `image/jpeg`, `image/webp` and `image/gif`, plus an `Upload` submit
  button.
- `SPEC-13.18.4` The picker must render a no-JavaScript remove form posting to `remove_action` only when an avatar is
  set, and a remove button with `data-has-avatar="1"` or `"0"` matching the state.
- `SPEC-13.18.5` When an avatar is set the picker must render the image and hide the letter fallback with
  `display:none`; when unset it must show the initial.
- `SPEC-13.18.6` The picker must expose an error paragraph (`role="status"`, `aria-live="polite"`) and a help line
  `PNG, JPEG, WebP, or GIF up to 2 MB.`, and the file input must have an accessible label stating the types and size.
- `SPEC-13.18.7` The component styles must be shipped inline in the page head, not in the built stylesheet:
  `AVATAR_SLOT_CSS` on every page that shows the topbar avatar, and `AVATAR_PICKER_CSS` only on the page that renders
  the picker, so a stale cached stylesheet cannot break the layout.

## 14. Workspace build, packaging and deployment

### 14.1 Workspace manifest

- `SPEC-14.1.1` The root `Cargo.toml` must be a virtual workspace manifest (no `[package]` table) with `resolver = "2"`
  and exactly the members `bunyip-api`, `bunyip-web`, `crates/bunyip-domain`, `crates/bunyip-oci`,
  `crates/bunyip-oidc`, and `crates/web-kit`, in that order (`SPEC-2.1.1`).
- `SPEC-14.1.2` `[workspace.package]` must define `version`, `edition = "2021"`, `authors`, `license = "MIT"`, and
  `repository` once; each member must inherit them with `*.workspace = true`, and the single `version` there is the
  only place a release bump writes the product version (`release_layout := "virtual-workspace"` in the justfile).
- `SPEC-14.1.3` `[workspace.lints.clippy]` must contain exactly one entry, `too_many_arguments = "allow"`; no other
  lint may be relaxed at workspace level (`SPEC-2.1.2`).
- `SPEC-14.1.4` `[workspace.dependencies]` must pin these shared versions: `parking_lot` 0.12, `serde_json` 1,
  `tracing` 0.1, `thiserror` 1, `anyhow` 1, `rand` 0.8, `sha2` 0.10, `tokio` 1 with feature `full`, `serde` 1 with
  feature `derive`, `uuid` 1.11 with features `v4` and `serde`, `chrono` 0.4 with feature `serde`, and
  `tracing-subscriber` 0.3 with feature `env-filter`, so members cannot drift onto different point releases.

### 14.2 Rust toolchain pin

- `SPEC-14.2.1` `rust-toolchain.toml` must pin `[toolchain] channel` to one exact patch version (currently `1.98.1`,
  never a partial version such as `1.98`) with the components `clippy` and `rustfmt`, so rustup resolves the
  toolchain preinstalled in the builder images without a download (`SPEC-2.1.5`).
- `SPEC-14.2.2` The pinned channel must equal the Rust version in the tag of every builder image the repo references
  (both production Dockerfiles, both dev Dockerfiles, and the `check-container` recipe); a toolchain bump must change
  all of them and fix any newly promoted clippy or rustfmt lint in the same change.

### 14.3 Cargo configuration

- `SPEC-14.3.1` `.cargo/config.toml` must set `[net] git-fetch-with-cli = true` so cargo fetches git dependencies
  through the system git CLI and honours its credential configuration.
- `SPEC-14.3.2` `.cargo/config.toml` must set `SQLX_OFFLINE = "true"` under `[env]` (without `force`, so an explicit
  environment value wins), so the compile-time `sqlx::query!` macros resolve against the committed `.sqlx/` cache and
  no database is needed to compile.

### 14.4 `bunyip-web` manifest

- `SPEC-14.4.1` `bunyip-web/Cargo.toml` must inherit version, edition, authors, license, and repository from the
  workspace and declare exactly one `[[bin]]` target, `bunyip-web` at `src/main.rs` (`SPEC-2.1.4`).
- `SPEC-14.4.2` `bunyip-web/Cargo.toml` must declare a path dependency on `crates/bunyip-domain` (shared response
  DTOs and CIDR types only) and on `crates/web-kit`, and must declare no database driver or `sqlx` dependency, so
  `bunyip-web` cannot open a database connection (`SPEC-1.5`, `SPEC-2.1.2`).
- `SPEC-14.4.3` `bunyip-web/Cargo.toml` must build `reqwest` with `default-features = false` and the features `json`,
  `rustls-tls`, `multipart`, `stream`, and `gzip` (no native TLS library; `gzip` so the client advertises
  `Accept-Encoding` to `bunyip-api`).
- `SPEC-14.4.4` `bunyip-web/Cargo.toml` must build `tower-http` with the features `fs`, `compression-gzip`,
  `compression-br`, `set-header`, and `trace`, and `pulldown-cmark` with only the `html` feature.
- `SPEC-14.4.5` `bunyip-web/Cargo.toml` must set `[lints.rust] dead_code = "allow"` and
  `[lints.clippy] too_many_arguments = "allow"` for this crate only.

### 14.5 `bunyip-web` build metadata

- `SPEC-14.5.1` `bunyip-web/build.rs` must resolve each of `GIT_COMMIT`, `GIT_TAG`, and `BUILD_DATE` from the
  environment variable of that name when it is set, non-empty, and not the literal `unknown`; otherwise from
  `git rev-parse --short HEAD`, `git describe --tags --always --dirty`, and `date -u +%Y-%m-%dT%H:%M:%SZ`
  respectively.
- `SPEC-14.5.2` When the fallback command is missing, exits non-zero, prints non-UTF-8, or prints nothing,
  `build.rs` must resolve the value to the literal `unknown` and must not fail the build.
- `SPEC-14.5.3` `build.rs` must emit `cargo:rustc-env` lines for `GIT_COMMIT`, `GIT_TAG`, `BUILD_DATE`, and
  `ASSET_VERSION`, so the crate can read each with `env!` at compile time.

### 14.6 `ASSET_VERSION`

- `SPEC-14.6.1` When the resolved commit is not `unknown`, `build.rs` must set `ASSET_VERSION` to the commit string.
- `SPEC-14.6.2` When the resolved commit is `unknown`, `build.rs` must set `ASSET_VERSION` to the resolved build date
  with every `:` and `-` removed, and must emit a `cargo:warning` line stating that `GIT_COMMIT` is unresolved and
  every rebuild will invalidate the `/assets` cache.

### 14.7 Build script rerun triggers

- `SPEC-14.7.1` `build.rs` must emit `rerun-if-changed=build.rs` and `rerun-if-env-changed` for `GIT_COMMIT`,
  `GIT_TAG`, and `BUILD_DATE`.
- `SPEC-14.7.2` `build.rs` must obtain the paths of `HEAD`, `refs/heads`, `refs/tags`, and `packed-refs` from
  `git rev-parse --git-path` and emit `rerun-if-changed` only for those that exist on disk, so a linked worktree, a
  submodule checkout, or a context without `.git` never names a missing path (which cargo would treat as permanently
  stale). It must not watch remote-tracking refs.
- `SPEC-14.7.3` When `git` is missing, is not run in a repository, or prints non-UTF-8, `build.rs` must emit no git
  rerun triggers and continue; the `unknown` resolution in `SPEC-14.5.2` applies.

### 14.8 CSS and JS build inputs

- `SPEC-14.8.1` `bunyip-web/package.json` must be private and define `build:css` as
  `tailwindcss --input input.css --output assets/styles.css --minify` and `watch:css` as the same command with
  `--watch` in place of `--minify`; its only dependencies are `tailwindcss` and `@tailwindcss/cli`, both `^4.0.0`.
- `SPEC-14.8.2` Every JS dependency install in a Dockerfile, dev container command, or build step must use
  `bun install --frozen-lockfile` against the committed `bunyip-web/bun.lock`, so two builds of one commit use the same
  Tailwind release.
- `SPEC-14.8.3` The Tailwind output `bunyip-web/assets/styles.css` must be committed and must equal a fresh
  `bun run build:css`; it is excluded from the Docker build context and rebuilt inside the web image.
- `SPEC-14.8.4` `bunyip-web/input.css` must start with `@import "tailwindcss"` and declare
  `@source "../crates/web-kit/src"`, because automatic source detection stops at `bunyip-web/`; any other crate that
  emits markup classes must be named by its own `@source` line.
- `SPEC-14.8.5` `input.css` must declare the `dark` variant as `@custom-variant dark (&:where(.dark, .dark *))`, so
  dark styles apply to any descendant of an element with class `dark`.

### 14.9 Theme tokens

- `SPEC-14.9.1` `input.css` must define the same 21 semantic color tokens (`--background`, `--foreground`, `--card`,
  `--card-foreground`, `--popover`, `--popover-foreground`, `--primary`, `--primary-text`, `--primary-foreground`,
  `--secondary`, `--secondary-foreground`, `--muted`, `--muted-foreground`, `--accent`, `--accent-foreground`,
  `--destructive`, `--destructive-text`, `--destructive-foreground`, `--border`, `--input`, `--ring`) as `H S% L%`
  triples in each of four blocks: `:root`, `.dark`, `.high-contrast`, and `.dark.high-contrast`; `:root` additionally
  defines `--radius: 0.5rem`.
- `SPEC-14.9.2` The `@theme inline` block must map each semantic token through `hsl(var(--token))` so toggling a
  class on `<html>` reskins every utility at runtime, and must define the `--color-brand-primary-*` scale (steps 50
  to 900) and `--color-brand-accent-*` scale (steps 50, 100, 300, 500, 700, 900) as `var(--skin-primary-N, <hex>)`
  and `var(--skin-accent-N, <hex>)`, so a stored skin overrides the default palette and an absent skin leaves the
  default hex values.
- `SPEC-14.9.3` Under `.high-contrast`, every class matching `[class*="border-border/"]` must render with
  `border-color: hsl(var(--border)) !important` (full opacity), and body font weight must be 500.
- `SPEC-14.9.4` `html` must paint `background-color: hsl(var(--background))` with `color-scheme: light`, and `.dark`
  must set `color-scheme: dark`, so a transparent scrollbar track never shows the browser canvas.
- `SPEC-14.9.5` `input.css` must define `@utility container` as full width, `max-width: none`, centered, with `2rem`
  inline padding, and a `max-width: 1400px` cap only at `width >= 1400px`.

### 14.10 Self-hosted web fonts

- `SPEC-14.10.1` `input.css` must declare four `@font-face` rules, all `font-display: swap` and `font-style: normal`:
  `Inter` (weight `400 700`) from `/assets/vendor/fonts/inter-v20-latin.woff2` and `inter-v20-latin-ext.woff2`, and
  `JetBrains Mono` (weight `400 500`) from `/assets/vendor/fonts/jetbrains-mono-v24-latin.woff2` and
  `jetbrains-mono-v24-latin-ext.woff2`, each with a disjoint `unicode-range` so latin-ext files load only on demand.
- `SPEC-14.10.2` The font file name must carry its version, because `/assets` is served immutable for a year and the
  stylesheet URL carries no `?v=`; replacing a font file requires a new file name.
- `SPEC-14.10.3` Pages must not load fonts from a third-party origin; the `--font-sans` and `--font-mono` stacks must
  start with `Inter` and `JetBrains Mono` and fall back to system fonts.

### 14.11 Scrollbar styling

- `SPEC-14.11.1` `input.css` must register `--sb-alpha` with `@property` (`<number>`, inherits, initial `1`), and must
  set `--sb-alpha: 0` at rest only under `html[data-scrollbars="auto"]` (on `html` and on scroll containers) and `1`
  under `[data-scrollbar-active]`, so a page whose script never tags `<html>` keeps visible scrollbars.
- `SPEC-14.11.2` The `--sb-alpha` transitions (400ms ease-in-out to hide, 150ms ease-out to show) must apply only under
  `prefers-reduced-motion: no-preference`.
- `SPEC-14.11.3` The WebKit scrollbar must be `14px` by `14px` with a transparent track and corner, and the thumb must
  be a pill with a transparent `4px 5px 5px 4px` border, `background-clip: padding-box`, and a color of
  `hsl(var(--muted-foreground) / var(--sb-alpha))` (hover and active: `3px` border and `--foreground`).
- `SPEC-14.11.4` `scrollbar-width` and `scrollbar-color` may appear only inside
  `@supports not selector(::-webkit-scrollbar)` (`scrollbar-width: thin`), because Chromium drops the WebKit rules
  when it sees either property; `scrollbar-width: none` must never appear.

### 14.12 Other shared styles

- `SPEC-14.12.1` `.scroll-fade-up` and `.scroll-fade-up-child > *` must start at `opacity: 0` and become visible only
  when the element or parent has class `in-view`; children `1` to `6` get transition delays `0s` to `0.5s` in `0.1s`
  steps, and every child from the seventh on (`nth-child(n + 7)`) must become visible with a `0.5s` delay so no row
  stays blank.
- `SPEC-14.12.2` The password indicator CSS must hide `[data-pw-icon="eye-off"]` and the `pass` and `fail` states by
  default, show `eye-off` and hide `eye` when `[data-pw-toggle][aria-pressed="true"]`, and show `pass` or `fail`
  only under `.pw-pass` or `.pw-fail`, so a row with no state class still shows the pending glyph.
- `SPEC-14.12.3` `*:focus-visible` must show a `2px` solid outline of `--color-brand-primary-600` with `2px` offset, and
  `::selection` must use the brand-primary 200 and 900 steps (700 and 50 under `.dark`).

### 14.13 Task runner configuration

- `SPEC-14.13.1` The root `justfile` must import `common/common.just` and configure the shared recipes only through
  variables: `app := "bunyip"`, `compose_service := "api"`,
  `dev_bind_sources := "secrets/oidc target bunyip-web/node_modules"`, `pre_commit_prepare := "ensure-oidc-keys"`,
  `clippy_args := "--workspace --all-targets -- -D warnings"`, `compile_args := "--workspace --all-targets --locked"`,
  `test_args := "--workspace --all-targets"`, `migrations_dir := "bunyip-api/migrations"`,
  `migration_version_width := "14"`, and `release_layout := "virtual-workspace"`; it must not redefine a recipe the
  shared file owns, and a fresh clone without the `common` submodule fails to parse.
- `SPEC-14.13.2` `pre_commit_extra_paths` must list every non-Rust path a Rust test reads with `include_str!`:
  `bunyip-web/assets/`, `bunyip-web/input.css`, `bunyip-web/src/skin/docs/`, `crates/bunyip-domain/templates/`, and
  `bunyip-api/seed/`, so a commit touching only those still runs the cargo checks.
- `SPEC-14.13.3` The first recipe in the justfile must be `default`, which runs `just --list`.

### 14.14 Check recipes

- `SPEC-14.14.1` The `check` umbrella recipe must depend, in order, on: `check-justfile`, `check-migrations`,
  `check-migration-immutability`, `check-workflows`, `check-workflow-shell`, `check-serde-compat`, `check-runners`,
  `check-security`, `check-stripe-env`, `check-key-env`, `check-env-parity`, `check-compose-env-parity`,
  `check-argon2-offload`, `check-no-bash`, `check-scrollbars`, `check-css-current`, `check-ui-copy`,
  `check-price-literals`, `check-brand-literals`, `check-theme-colors`, `check-em-dash`, `check-doc-surface`,
  `check-config-docs`, `check-claude-md`, `check-cache-mounts`, `check-cache-keys`, `check-publish-triggers`,
  `check-dependency-audit`, `check-build`, `check-clippy`, `check-fmt`, and `check-docker`.
- `SPEC-14.14.2` Each guard recipe that has a self-test (`check-workflow-shell`, `check-serde-compat`,
  `check-env-parity`, `check-compose-env-parity`, `check-argon2-offload`, `check-scrollbars`, `check-css-current`,
  `check-ui-copy`, `check-price-literals`, `check-brand-literals`, `check-em-dash`, `check-theme-colors`,
  `check-doc-surface`, `check-claude-md`, `check-cache-mounts`, `check-cache-keys`, `check-publish-triggers`,
  `check-dependency-audit`) must run the guard script with `--self-test` before the real run, and a failing
  self-test must fail the recipe before the real run starts; `check-config-docs` does the same with
  `nu scripts/config-docs.nu self-test` then `check`.
- `SPEC-14.14.3` `check-workflows` must first require `scripts/check-workflow-secrets.nu` to FAIL against the fixture
  directory `scripts/fixtures/workflow-secrets-bad` (the leading `!` inverts the exit code) and then require it to
  pass on the real workflows.
- `SPEC-14.14.4` `check-runners`, `check-security`, `check-stripe-env`, `check-key-env`, and `check-no-bash` must run
  their `scripts/check-*.nu` script and fail the recipe on a non-zero exit.
- `SPEC-14.14.5` `check-build` must run `cargo build --workspace --all-targets`, `check-clippy` must run
  `cargo clippy --workspace --all-targets -- -D warnings`, `check-fmt` must run `cargo fmt --all --check`, and
  `check-docker` must build only the `builder` stage of `bunyip-api/oci-build/Dockerfile` with
  `--output type=cacheonly --provenance=false`.
- `SPEC-14.14.6` `check-migrations` must be only an alias of the shared `check-migration-versions` recipe, so
  migration filenames are unique and have a 14-digit prefix.

### 14.15 Cargo and container convenience recipes

- `SPEC-14.15.1` `check-container` must run, inside the pinned builder image and with the repo mounted at `/work`,
  `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
  --all-targets` with `CARGO_TARGET_DIR=/cargo-target` and `SQLX_OFFLINE=true`; the build cache must be a named
  volume mounted outside `/work`, because a volume nested under the bind mount makes Docker create the mountpoint
  root-owned on the host.
- `SPEC-14.15.2` `typecheck` must run `cargo check --workspace`, `lint` must run the clippy command of
  `SPEC-14.14.5`, `fmt` must run `cargo fmt --all`, and `test` must run `cargo test --workspace --all-targets`
  (not `--lib`, because `bunyip-web` is bin-only).
- `SPEC-14.15.3` `run` must run `cargo run -p bunyip-api`, `run-web` must run `cargo run -p bunyip-web` from inside
  `bunyip-web/` so the relative `assets` directory resolves, and `build` must run `cargo build --workspace`.

### 14.16 Recipe environment and compose commands

- `SPEC-14.16.1` The justfile must export `HOST_UID` and `HOST_GID` from `id -u` and `id -g` (the compose files
  interpolate exactly these names; a fallback of 1000 leaves a container unable to read a host-owned 0700 repo) and
  must export `SQLX_OFFLINE=true`.
- `SPEC-14.16.2` The justfile must export `WORKTREE_SUFFIX` as the empty string when `.git` is a directory and as
  `-` plus the first 7 hex characters of the SHA-1 of the absolute top-level path when `.git` is a file (a linked
  worktree), so concurrent worktrees get distinct `cargo-target` volumes.
- `SPEC-14.16.3` The dev stack must be driven through `docker compose -f compose.dev.yml`, and the SSO stack through
  `docker compose -f compose.dev.yml -f compose.dev-sso.yml`.

### 14.17 Dev `.env` bootstrap

- `SPEC-14.17.1` The private `ensure-env` recipe must ensure the per-developer external network
  `dev-bunyip-private-<whoami>` exists, creating it with `docker network create` only when `docker network inspect`
  exits non-zero, because `compose.dev.yml` declares that network `external`.
- `SPEC-14.17.2` When `.env` does not exist, `ensure-env` must build it from `.env.example` by dropping comment and
  blank lines, parsing `NAME=VALUE`, replacing `APP_ENCRYPTION_KEY` and `JWT_SECRET` with fresh 32-byte
  lowercase-hex values, and writing the result with a trailing newline; it must not overwrite an existing `.env`.
- `SPEC-14.17.3` `ensure-env` must fail (non-zero exit from `update`) when `.env.example` has no active
  `APP_ENCRYPTION_KEY` or `JWT_SECRET` line, so those two keys must stay uncommented in `.env.example`.

### 14.18 Dev signing keys and production secrets

- `SPEC-14.18.1` The private `ensure-oidc-keys` recipe must run `ensure-bind-sources` first, then move a legacy
  `secrets/dev-2026.pem` or `secrets/dev-2026.pub.pem` into `secrets/oidc/` only when the destination is absent.
- `SPEC-14.18.2` `ensure-oidc-keys` must return without changes when both `secrets/oidc/dev-2026.pem` and
  `secrets/oidc/dev-2026.pub.pem` exist; otherwise it must generate an Ed25519 private key with `openssl genpkey` and
  derive the public key from it, and a failing `openssl` call must fail the recipe.
- `SPEC-14.18.3` `init-secrets` must run `./scripts/init-secrets.nu`, the idempotent creator of the production secret
  files.

### 14.19 Dev stack lifecycle recipes

- `SPEC-14.19.1` `dev` and `dev-detach` must depend on `ensure-env` and `ensure-oidc-keys` and run
  `up --build` (`dev-detach` adds `--detach` and prints the web URL `http://localhost:4400` and the api URL
  `http://localhost:4401`).
- `SPEC-14.19.2` `dev-sso` must depend on `ensure-env` and `ensure-oidc-keys`, ensure the per-developer network as in
  `SPEC-14.17.1`, run the SSO compose stack with `up --build --detach`, and print the per-developer hub and registry
  URLs.
- `SPEC-14.19.3` `dev-stop` must run `down` on the dev stack and `dev-stop-sso` must run `down --remove-orphans` on
  the SSO stack.
- `SPEC-14.19.4` `dev-logs`, `logs-api`, and `logs-web` must follow logs of all services, `api`, and `web`
  respectively; `db-shell` must open `psql` as user `bunyip` on database `bunyip` in the `postgres` service.
- `SPEC-14.19.5` `migrate` and `migrate-revert` must run `cargo sqlx migrate run` and `cargo sqlx migrate revert` with
  `--source bunyip-api/migrations` inside the `api` service; `e2e-bootstrap` must run the `bunyip-e2e-bootstrap`
  binary inside the `api` service and forward its arguments; `e2e` must run `npx playwright test` in `e2e/` on the
  host and forward its arguments.

### 14.20 Per-developer client registration

- `SPEC-14.20.1` `register-dev-clients` must fail with exit 1 and a `FAIL:` line naming the container when the
  per-developer postgres container `dev-bunyip-postgres-<whoami>` is not running.
- `SPEC-14.20.2` `register-dev-clients` must upsert one public OAuth client row (fixed client id, scopes `openid`,
  `email`, `profile`, `offline_access`, grants `authorization_code` and `refresh_token`, auth method `none`, PKCE
  required, access token TTL 600 seconds) into `oauth_clients` with `ON CONFLICT (client_id) DO UPDATE` that
  refreshes redirect URIs, post-logout URIs, scopes, and audience, and must print the client id.

### 14.21 OCI registry verification recipe

- `SPEC-14.21.1` `verify-oci` must exit 1 with a `FAIL:` line when `SETUP_DEFAULT_ADMIN` is missing from `.env`, or
  when the api container `dev-bunyip-api-<whoami>` is not running.
- `SPEC-14.21.2` `verify-oci` must read the registry port from `BUNYIP_OCI_PORT` in `.env`, using `18081` when the
  key is absent, and must never print credentials.
- `SPEC-14.21.3` `verify-oci` must check in order and exit 1 on the first failure: an unauthenticated `GET /v2/`
  returns 401 with a `WWW-Authenticate` header; `docker login` succeeds; an entitled pull of the pinned tag succeeds;
  a pull of a non-pinned tag fails; a second pull after `docker rmi` succeeds.
- `SPEC-14.21.4` `verify-oci` must upsert the `applications` row for its `slug`, `owner`, `image`, and `tag`
  parameters (defaults `bunyip-api`, the private image owner, `bunyip-api`, `v0.1.1`) before the checks, and must
  remove the test image and log out of the registry at the end.

### 14.22 Image build recipes

- `SPEC-14.22.1` `build-docker` must depend on `build-api-image` and `build-web-image`.
- `SPEC-14.22.2` `build-api-image` and `build-web-image` (parameter `tag`, default `latest`) must build with the
  repository root as context, `--file` set to the matching `oci-build/Dockerfile`, `--build-arg GIT_COMMIT` from
  `git rev-parse --short HEAD`, `--build-arg GIT_TAG` from `git describe --tags --always --dirty`, and tag
  `bunyip-api:<tag>` or `bunyip-web:<tag>`; the api recipe must also pass the optional buildkit secret
  `dunite_token` from `DUNITE_GIT_TOKEN`.
- `SPEC-14.22.3` `build-docker-export` must build the api Dockerfile with `--target export --output
  type=local,dest=dist` so the static binary is written to `./dist`.

### 14.23 Dev cleanup recipes

- `SPEC-14.23.1` `dev-clean` must stop the dev stack with `down --remove-orphans`, remove only existing volumes among
  `dev-bunyip-postgres-<USER>`, `dev-bunyip-web-node-modules-<USER>`, `dev-bunyip-download-cache-<USER>`,
  `dev-bunyip-oci-cache-<USER>`, `bunyip-check-target`, and every `dev-bunyip-cargo-target-<USER>` volume with or
  without a worktree suffix, then remove `target`, `bunyip-web/node_modules`, and `.env` when present and print each
  removed path; it must not prune host-global Docker state.
- `SPEC-14.23.2` `dev-clean-all` must run `dev-clean`, remove the local images `bunyip-api:latest` and
  `bunyip-web:latest` when present, and prune the buildx cache.

### 14.24 Production compose secrets

- `SPEC-14.24.1` `compose.yml` must declare exactly eleven file-backed secrets under the project name `bunyip`, each
  from `./secrets/<name>`: `postgres_password`, `database_url`, `bunyip_app_password`, `app_database_url`,
  `jwt_secret`, `webhook_signing_secret`, `app_encryption_key`, `setup_default_admin`, `forgejo_api_token`,
  `update_check_token`, and `mailer_webhook_secret`; a missing secret file must abort `docker compose up`.
- `SPEC-14.24.2` Of those, `postgres_password`, `database_url`, `jwt_secret`, `app_encryption_key`, and
  `webhook_signing_secret` must be non-empty; an empty file for any other secret means the feature is not configured.
- `SPEC-14.24.3` The `api` service must receive each secret through its `{NAME}_FILE` variable pointing under
  `/run/secrets/` (`DATABASE_URL_FILE`, `BUNYIP_APP_PASSWORD_FILE`, `APP_DATABASE_URL_FILE`, `JWT_SECRET_FILE`,
  `BUNYIP_WEBHOOK_SIGNING_SECRET_FILE`, `APP_ENCRYPTION_KEY_FILE`, `SETUP_DEFAULT_ADMIN_FILE`,
  `MAILER_WEBHOOK_SECRET_FILE`, `FORGEJO_API_TOKEN_FILE`, `BUNYIP_UPDATE_CHECK_TOKEN_FILE`), and the `postgres`
  service through `POSTGRES_PASSWORD_FILE`; no secret value may appear in an `environment` value.

### 14.25 Production compose postgres

- `SPEC-14.25.1` The `postgres` service must run image `postgres:18.2-alpine3.23` as user `postgres`, with
  `no-new-privileges`, all capabilities dropped, a read-only root filesystem, tmpfs on `/tmp` and
  `/var/run/postgresql`, `restart: unless-stopped`, and only `expose: 5432` (no published port).
- `SPEC-14.25.2` The `postgres` data must live in the named volume `bunyip-postgres-data` mounted at
  `/var/lib/postgresql` (the parent of the major-version directory, so data persists across major layouts).
- `SPEC-14.25.3` The `postgres` health check must be `pg_isready` for `POSTGRES_USER` (default `bunyip`) and
  `POSTGRES_DB` (default `bunyip`) every 10s, timeout 5s, 5 retries, start period 5s.

### 14.26 Production compose api environment

- `SPEC-14.26.1` `docker compose up` must abort, printing the variable-specific message, when any of
  `BUNYIP_API_IMAGE`, `BUNYIP_WEB_IMAGE`, `SECRETS_STORAGE`, `APP_URL`, `BUNYIP_WEB_ORIGIN`,
  `OIDC_JWT_PRIVATE_KEY_PATH`, `OIDC_JWT_ACTIVE_KID`, or `BUNYIP_API_PUBLIC_ORIGIN` is unset or empty; none has a
  default (images are pinned tags, never `latest`; no development key path or kid is substituted).
- `SPEC-14.26.2` The `api` service must set `HOST_IP=0.0.0.0` and `APP_PORT=4401` as the in-container bind, default
  `ENVIRONMENT` to `production` and `RUST_LOG` to `info`, set `OIDC_JWT_PUBLIC_KEYS_DIR=/run/secrets/oidc`, and
  default `TRUSTED_PROXY_CIDR` to `172.16.0.0/12,10.0.0.0/8,192.168.0.0/16` and `CORS_ORIGIN` to
  `http://localhost:4400`.
- `SPEC-14.26.3` The `api` service must default `INFISICAL_ENABLED` to `false`, `INFISICAL_SECRET_PATH` to `/runtime`,
  `EMAIL_ENABLED` to `false`, `SMTP_PORT` to `465`, `SMTP_TLS` to `implicit`, `SUPPORT_IMAP_POLL_SECS` to `60`, and
  `OCI_REGISTRY_ENABLED` to `false`, and pass through (empty by default) the Infisical address, project, environment
  and client variables, `APP_ENCRYPTION_KEY_PREV`, `COOKIE_DOMAIN`, `BOOTSTRAP_ADMIN_EMAIL`, `OIDC_ISSUER`, and the
  SMTP, support-inbox, and notification variables.
- `SPEC-14.26.4` The `api` service must set `DOWNLOAD_CACHE_DIR=/var/cache/bunyip-downloads`,
  `OCI_BLOB_CACHE_DIR=/var/cache/bunyip-oci`, and `OCI_REGISTRY_PORT=18081`, and default
  `DOWNLOAD_CACHE_MAX_BYTES=10737418240`, `OCI_BLOB_CACHE_MAX_BYTES=53687091200`, `OCI_PULLS_PER_USER_PER_DAY=50`,
  `DOWNLOAD_DAILY_LIMIT_PER_USER=50`, `DOWNLOAD_CONCURRENCY_PER_USER=2`, `FORGEJO_RELEASE_CACHE_TTL_SECS=300`,
  `OCI_CONCURRENT_MANIFESTS_PER_USER=2`, `OCI_MANIFEST_CACHE_TTL_SECS=300`, and `OCI_TOKEN_TTL_SECS=900`.
- `SPEC-14.26.5` The `api` service must publish `4401` and `18081` on `${HOST_IP:-127.0.0.1}` (host-side interface,
  default loopback; `BUNYIP_API_PORT` default `4401`, `BUNYIP_OCI_PORT` default `18081`) and also `expose` both ports.

### 14.27 Production compose api hardening

- `SPEC-14.27.1` The `api` service must set `no-new-privileges`, drop all capabilities and add back only `SETUID`,
  `SETGID`, `CHOWN`, and `DAC_OVERRIDE` (the privilege-drop entrypoint needs them), run with a read-only root
  filesystem, and mount tmpfs on `/tmp` and `/etc`.
- `SPEC-14.27.2` The `api` service must mount only `./secrets/oidc` read-only at `/run/secrets/oidc` (never the whole
  secrets directory) and the named volumes `bunyip-config-layer` at `/app/config`, `bunyip-oci-cache` at
  `/var/cache/bunyip-oci`, and `bunyip-download-cache` at `/var/cache/bunyip-downloads`; the caches must be named
  volumes, not host bind mounts.
- `SPEC-14.27.3` The `api` service must wait for the `postgres` service to be healthy before starting, and both must
  join the bridge network `bunyip-private`.

### 14.28 Production compose web

- `SPEC-14.28.1` The `web` service must run image `BUNYIP_WEB_IMAGE` with `BUNYIP_BIND_ADDR=0.0.0.0:4400`,
  `BUNYIP_API_URL` defaulting to `http://api:4401`, `RUST_LOG` defaulting to `info`, and `TRUSTED_PROXY_CIDR` taken from
  `WEB_TRUSTED_PROXY_CIDR` with the same RFC 1918 default as `SPEC-14.26.2`; it must receive no secret.
- `SPEC-14.28.2` The `web` service must publish `4400` on `${HOST_IP:-127.0.0.1}` (`BUNYIP_WEB_PORT` default `4400`),
  start after `api` (no health condition), join `bunyip-private`, run with `no-new-privileges`, the same four added
  capabilities as `SPEC-14.27.1`, a read-only root filesystem, and tmpfs only on `/etc`.
- `SPEC-14.28.3` The `web` service must pass `BUNYIP_APP_DOMAIN`, `BUNYIP_OIDC_ISSUER`, and `BUNYIP_COMMUNITY_URL`,
  each empty by default (an empty community URL hides the community button).
- `SPEC-14.28.4` The compose file must name the volumes `bunyip-postgres-data`, `bunyip-config-layer`,
  `bunyip-oci-cache`, and `bunyip-download-cache` and the network `bunyip-private` (bridge), and the containers
  `bunyip-postgres`, `bunyip-api`, and `bunyip-web` (no `dev-` prefix in production).

### 14.29 Development compose: database and api

- `SPEC-14.29.1` `compose.dev.yml` must set the project name `bunyip-${USER}` and abort with the message
  `USER missing - run via just dev` when `USER` is unset; containers must be named `dev-bunyip-<service>-${USER}`.
- `SPEC-14.29.2` The dev `postgres` service must use image `postgres:18.2-alpine3.23`, default `POSTGRES_USER` and
  `POSTGRES_DB` to `bunyip` and `POSTGRES_PASSWORD` to `devpassword`, expose only `5432`, mount the named volume
  `dev-bunyip-postgres-${USER}` at `/var/lib/postgresql`, and use a `pg_isready` health check every 5s, timeout 5s,
  5 retries, start period 5s.
- `SPEC-14.29.3` The dev `api` service must build from `bunyip-api/Dockerfile` with context `.`, run as
  `${HOST_UID:-1000}:${HOST_GID:-1000}`, bind-mount the repo at `/app`, mount the volume `cargo-target` at
  `/app/target` and `./secrets/oidc` read-only at `/run/secrets/oidc`, set `SQLX_OFFLINE=true`, and wait for a healthy
  `postgres`.
- `SPEC-14.29.4` The dev `api` service must default `ENVIRONMENT` to `development`, `SECRETS_STORAGE` to `database`,
  `OIDC_ISSUER` to `http://localhost:4401`, the signing key to `/run/secrets/oidc/dev-2026.pem` and the active kid to
  `dev-2026`, `APP_URL` and `BUNYIP_WEB_ORIGIN` to `http://localhost:4400`, `CORS_ORIGIN` to `http://localhost:4400`,
  `RUST_LOG` to `info,bunyip_api=debug,bunyip_core=info`, and `TRUSTED_PROXY_CIDR` to the RFC 1918 list; an empty value
  in `.env` yields the default because the compose file uses the `:-` form.
- `SPEC-14.29.5` The dev `api` service must derive `BUNYIP_APP_PASSWORD` and the password inside `APP_DATABASE_URL` from
  `POSTGRES_PASSWORD` by default, so the per-user RLS role is provisioned and used with no extra configuration, and the
  two values must agree.
- `SPEC-14.29.6` The dev `api` service must fix `OCI_REGISTRY_PORT=18081` inside the container and derive
  `OCI_REGISTRY_SERVICE` and `OCI_REGISTRY_REALM` defaults from the published port `BUNYIP_OCI_PORT` (default `18081`)
  so `docker login` works after overriding the host port; it must publish `${BUNYIP_API_PORT:-4401}:4401` and
  `${BUNYIP_OCI_PORT:-18081}:18081` on all host interfaces.

### 14.30 Development compose: web, volumes, network

- `SPEC-14.30.1` The dev `web` service must build from `bunyip-web/Dockerfile`, run as `${HOST_UID:-1000}:${HOST_GID:-1000}`,
  bind-mount the repo at `/app`, mount `cargo-target` at `/app/target` and the volume `web-node-modules` at
  `/app/bunyip-web/node_modules`, publish `${BUNYIP_WEB_PORT:-4400}:4400`, and start after `api`.
- `SPEC-14.30.2` The dev `web` service must default `BUNYIP_API_URL` to `http://api:4401`, `BUNYIP_API_PUBLIC_ORIGIN`
  to `http://localhost:4401`, `BUNYIP_APP_DOMAIN` to `localhost`, `RUST_LOG` to `info`, and `TRUSTED_PROXY_CIDR` from
  `WEB_TRUSTED_PROXY_CIDR` with the RFC 1918 default.
- `SPEC-14.30.3` The dev compose file must name the volumes `dev-bunyip-postgres-${USER}`,
  `dev-bunyip-cargo-target-${USER}${WORKTREE_SUFFIX}`, `dev-bunyip-web-node-modules-${USER}`,
  `dev-bunyip-download-cache-${USER}`, and `dev-bunyip-oci-cache-${USER}`.
- `SPEC-14.30.4` The dev compose file must declare the network `private` as `external: true` with the name
  `dev-bunyip-private-${USER}`, so the network must be created before `up` (`SPEC-14.17.1`).

### 14.31 Development SSO overlay

- `SPEC-14.31.1` `compose.dev-sso.yml` must be an overlay on `compose.dev.yml`: it must reset the `web` published
  ports to none, require `BUNYIP_OIDC_ISSUER` (abort with `BUNYIP_OIDC_ISSUER missing - copy .env.example to .env and
  fill in` when unset), and set the `web` `BUNYIP_API_PUBLIC_ORIGIN` to the per-developer HTTPS api hostname.
- `SPEC-14.31.2` The overlay must override on `api`: `OIDC_ISSUER` to the per-developer HTTPS api hostname,
  `BUNYIP_WEB_ORIGIN` and `APP_URL` to the per-developer HTTPS web hostname, `OCI_REGISTRY_SERVICE` to the
  per-developer registry hostname (aborting when `USER` is unset), `OCI_REGISTRY_REALM` to the empty string (so the
  code default `https://<service>/auth/token` applies), `COOKIE_DOMAIN` to the shared parent domain, `CORS_ORIGIN` to
  the web hostname plus the per-developer first-party SPA hostname, and pass `MOKOSH_BACKUP_API_URL` through
  (empty by default) and `SECRETS_STORAGE` (default `database`).
- `SPEC-14.31.3` The overlay must attach both `web` and `api` to the `private` network and to the external shared
  reverse-proxy network, and label them with the Traefik list-syntax form `key=value` (required because compose does
  not interpolate `${USER}` inside map keys).
- `SPEC-14.31.4` Every Traefik router must be bound to both secure entrypoints the dev hosts map to port 443, use the
  configured certificate resolver, and set the Docker network label to the shared proxy network; the `web` router must
  target service port `4400`.
- `SPEC-14.31.5` Because the `api` container exposes two services, the registry router (host
  `<USER>-bunyip-registry`, port `18081`) and the identity-provider router (host `<USER>-bunyip-api`, port `4401`) must
  each name their service explicitly, or the proxy refuses to link them and both hosts return 404.

### 14.32 Production `bunyip-api` image build

- `SPEC-14.32.1` `bunyip-api/oci-build/Dockerfile` must build with the repository root as context in a three-stage
  cargo-chef shape: `chef` (toolchain plus `cargo install cargo-chef --locked`), `planner` (`cargo chef prepare
  --recipe-path recipe.json`), and `builder` (cook, then build).
- `SPEC-14.32.2` The base images of the `chef` stage and the runtime stage must be referenced by tag and immutable
  `sha256` digest, and the builder tag's Rust version must equal the pin in `rust-toolchain.toml` (`SPEC-14.2.2`).
- `SPEC-14.32.3` The `chef` stage must set `RUSTFLAGS` to `-C link-arg=-fuse-ld=lld`, `CARGO_NET_GIT_FETCH_WITH_CLI=true`,
  and `SQLX_OFFLINE=true`.
- `SPEC-14.32.4` Every buildkit cache mount in the Dockerfile must carry a per-image `id` (`bunyip-api-cargo-registry`
  or `bunyip-api-cargo-git`) and `sharing=locked`, so concurrent builds cannot unpack crates into one directory.
- `SPEC-14.32.5` The `builder` stage must cook only `--bin bunyip-api --bin bunyip-e2e-bootstrap` in release mode from
  `recipe.json`, and the final build must run `cargo build --locked --release --bin bunyip-api --bin
  bunyip-e2e-bootstrap`; the `--locked` flag must fail the build when `Cargo.lock` is out of date.
- `SPEC-14.32.6` The per-build arguments `GIT_COMMIT`, `GIT_TAG`, and `BUILD_DATE` (default `unknown`) and their
  environment must be declared after the cook step, so a per-build value never invalidates the dependency layer.
- `SPEC-14.32.7` When the buildkit secret `dunite_token` is non-empty, the cook and build steps must configure git to
  rewrite the forge URL with that token in the same `RUN` that touches the network; with no secret, the anonymous
  clone must work.
- `SPEC-14.32.8` The `export` stage must be `FROM scratch` containing only `/bunyip-api` copied from the builder.

### 14.33 Production `bunyip-api` runtime image

- `SPEC-14.33.1` The runtime stage must install `ca-certificates`, `tzdata`, `curl`, `gosu`, and `shadow` and create
  group and user `appuser` with id 1001.
- `SPEC-14.33.2` The runtime stage must copy `/etc` to `/etc.dist` after every step that edits `/etc`, because a
  read-only container mounts an empty tmpfs over `/etc` and the entrypoint restores from the copy.
- `SPEC-14.33.3` The runtime image must contain `/usr/local/bin/gosu-entrypoint.sh` (mode 0755), `/app/bunyip-api`,
  `/app/bunyip-e2e-bootstrap`, `/app/migrations` (from `bunyip-api/migrations`), and `/app/templates` (from
  `crates/bunyip-domain/templates`).
- `SPEC-14.33.4` The runtime image must create `/app/config`, `/var/cache/bunyip-oci`, and `/var/cache/bunyip-downloads`
  owned by `appuser`, so named volumes mounted there inherit that ownership on first use.
- `SPEC-14.33.5` The runtime image must set `HOST_IP=0.0.0.0`, `APP_PORT=4401`, `APP_USER=appuser`, and `DATA_DIRS` to
  the three directories of `SPEC-14.33.4` with `/app/config` first, expose `4401`, and use the entrypoint
  `["/usr/local/bin/gosu-entrypoint.sh", "/app/bunyip-api"]`, starting as root.
- `SPEC-14.33.6` The runtime image must declare a health check running
  `curl --silent --fail http://localhost:4401/v1/health` every 30s with timeout 3s, start period 5s, and 3 retries.
- `SPEC-14.33.7` The runtime image must label `org.opencontainers.image.source`, `.description`, `.revision` (from
  `GIT_COMMIT`), `.version` (from `GIT_TAG`), and `.created` (from `BUILD_DATE`).
- `SPEC-14.33.8` The image must ship `bunyip-e2e-bootstrap` as a separate binary and must not make it the
  `ENTRYPOINT`; it runs only when an operator overrides the entrypoint.

### 14.34 Production `bunyip-web` image

- `SPEC-14.34.1` `bunyip-web/oci-build/Dockerfile` must build with the repository root as context in the same
  `chef`, `planner`, `build` shape on the glibc builder image pinned by tag and `sha256` digest, with cache mount ids
  `bunyip-web-cargo-registry` and `bunyip-web-cargo-git` and `sharing=locked`.
- `SPEC-14.34.2` The `build` stage must copy `bunyip-web/package.json` and `bunyip-web/bun.lock`, run
  `bun install --frozen-lockfile` before the cook, cook only `--bin bunyip-web`, then declare `GIT_COMMIT`, `GIT_TAG`,
  and `BUILD_DATE` (default `unknown`) after the cook and the install (`SPEC-14.32.6`).
- `SPEC-14.34.3` The final build step must copy the full source, run `bun run build:css` in `bunyip-web/` (after the
  copy, because Tailwind scans the Rust sources), and then `cargo build --locked --release --bin bunyip-web`.
- `SPEC-14.34.4` The runtime stage (Debian slim, pinned by digest) must install `ca-certificates` and `gosu`, create
  `appuser` with uid and gid 1001, create `/etc.dist` (`SPEC-14.33.2`), install the entrypoint at mode 0755, and copy
  the binary to `/app/bunyip-web` and the built `assets` directory to `/app/assets`, all owned by `appuser`.
- `SPEC-14.34.5` The runtime stage must set `WORKDIR /app` (so the relative `assets` directory resolves to
  `/app/assets`), `BUNYIP_BIND_ADDR=0.0.0.0:4400`, `APP_USER=appuser`, `DATA_DIRS=""` (the process writes nothing),
  expose `4400`, use `ENTRYPOINT ["/usr/local/bin/gosu-entrypoint.sh"]` with `CMD ["/app/bunyip-web"]`, and carry the
  five image labels of `SPEC-14.33.7`; it declares no health check.

### 14.35 Development images

- `SPEC-14.35.1` The dev `bunyip-web/Dockerfile` must install JS dependencies with `bun install --frozen-lockfile` at
  image build time and again in the container command, because the repo bind mount and the `web-node-modules` volume
  shadow the build-time install.
- `SPEC-14.35.2` The dev `bunyip-web/Dockerfile` must create user `app` with `HOST_UID` and `HOST_GID` (default 1000),
  own `/app` and `/home/app`, set `CARGO_HOME=/home/app/.cargo`, expose `4400` with `BUNYIP_BIND_ADDR=0.0.0.0:4400`,
  and run as that uid and gid.
- `SPEC-14.35.3` The dev `bunyip-web/Dockerfile` command must, from `/app/bunyip-web`, install JS dependencies, build
  the CSS once, start `watch:css` in the background, and run `cargo watch -w . -x 'run -p bunyip-web'`, so the
  server's relative `assets` directory resolves to the crate directory.
- `SPEC-14.35.4` Both dev Dockerfiles must accept `CARGO_BUILD_JOBS` (default `default`) and use the same builder
  image Rust version as the pin (`SPEC-14.2.2`).

### 14.36 Container entrypoint

- `SPEC-14.36.1` `gosu-entrypoint.sh` (identical bytes in `bunyip-api/oci-build/` and `bunyip-web/oci-build/`) must
  run under `set -eu`, abort when `APP_USER` is unset or empty, abort when `DATA_DIRS` is unset (an empty value is
  allowed), and exit 1 with `entrypoint: no command to run` on standard error when given no arguments.
- `SPEC-14.36.2` When started as a non-root user, the entrypoint must skip the remap, hooks, and chown; exit 1 when
  `PUID` or `PGID` is set and differs from the actual id; exit 1 naming the directory and its owner when any
  `DATA_DIRS` entry is not a writable directory; and otherwise `exec` the command directly.
- `SPEC-14.36.3` When started as root and `/etc.dist` exists, the entrypoint must copy every entry of `/etc.dist` into
  `/etc` except `hosts`, `hostname`, and `resolv.conf`.
- `SPEC-14.36.4` As root, the entrypoint must reject a non-numeric or zero `PUID` or `PGID` with exit 1 and a message
  naming the variable; unset ids must resolve to the owner of the first `DATA_DIRS` entry when that owner is not
  root, else to 1001; and it must log the resolved `uid:gid` and the source of each.
- `SPEC-14.36.5` As root, the entrypoint must run `groupmod -o` and `usermod -o` to give `APP_USER` the resolved ids,
  run each `/etc/entrypoint.d/*.sh` hook with `sh` (exit with the hook's exit status and a message naming the hook
  when it fails), `chown` to `uid:gid` only the entries under each `DATA_DIRS` directory whose owner or group differs,
  and finally `exec gosu "$APP_USER" "$@"` so supplementary groups come from `/etc/group`.

### 14.37 Environment files

- `SPEC-14.37.1` `.env.example` is the development file `just dev` copies; every variable it defines must appear once
  and its active (uncommented) values must be safe only for local development. It must keep active lines for
  `ENVIRONMENT=development`, `SECRETS_STORAGE=database`, `JWT_SECRET`, `APP_ENCRYPTION_KEY` (empty), `OIDC_ISSUER`,
  `OIDC_JWT_PRIVATE_KEY_PATH`, `OIDC_JWT_ACTIVE_KID`, and `OIDC_JWT_PUBLIC_KEYS_DIR`, and must not be used for a
  deployment.
- `SPEC-14.37.2` `.env.example` must document, for the host-side publish settings, that `HOST_IP` (default
  `127.0.0.1`), `BUNYIP_API_PORT` (`4401`), `BUNYIP_WEB_PORT` (`4400`), and `BUNYIP_OCI_PORT` (`18081`) are the host side
  of the compose port mappings and that `HOST_IP` there is not the in-container bind address.
- `SPEC-14.37.3` `.env.example` must document that `SECRETS_STORAGE` takes `environment`, `database`, or
  `infisical`, that production has no default for it, that governed secrets (SMTP password, Stripe secret key and
  webhook secret) come only from the declared store, and that under the `environment` store the Stripe secrets are read
  only as `STRIPE_SECRET_KEY_FILE` and `STRIPE_WEBHOOK_SECRET_FILE`.
- `SPEC-14.37.4` `.env.production.example` must set `ENVIRONMENT=production`, `BUNYIP_API_IMAGE` and
  `BUNYIP_WEB_IMAGE` to pinned tags, and example values for `BUNYIP_API_PUBLIC_ORIGIN`, `CORS_ORIGIN`, `APP_URL`,
  `BUNYIP_WEB_ORIGIN`, `OIDC_ISSUER`, `OIDC_JWT_PRIVATE_KEY_PATH`, and `OIDC_JWT_ACTIVE_KID` using only reserved
  example domains; it must leave `SECRETS_STORAGE` commented out so `docker compose up` aborts until the operator
  chooses a store, and its kid must not start with `dev-`.
- `SPEC-14.37.5` `bunyip-web/.env.example` must define `BUNYIP_BIND_ADDR=0.0.0.0:4400`,
  `BUNYIP_API_URL=http://localhost:4401`, `BUNYIP_APP_DOMAIN=localhost`, and `RUST_LOG=info`, and document as optional
  `BUNYIP_API_PUBLIC_ORIGIN` (defaults to `BUNYIP_API_URL`), `BUNYIP_OIDC_ISSUER` (defaults to `BUNYIP_API_URL`),
  `TRUSTED_PROXY_CIDR` (empty trusts no forwarding headers), `BUNYIP_COMMUNITY_URL` (empty hides the button), and
  `CSP_CONNECT_SRC` and `CSP_FORM_ACTION` (extra hosts only; script, default, and frame-ancestors sources are never
  extended).
- `SPEC-14.37.6` Every environment variable `bunyip-web/src/config.rs` reads must have an entry (active or
  commented, at the start of a line) in the root `.env.example`, so a deployer can discover it.

### 14.38 Ignore files and secrets handling

- `SPEC-14.38.1` `.gitignore` must ignore `.env*` except `.env.example`, and `.env.production.example` must be
  tracked in spite of that pattern; it must ignore `target/`, `node_modules/`, and the rooted
  `/config/config.yaml`, `/config/config.yaml.migrated`, `/config/LOGIN_APPROVAL_ENABLED`,
  `/config/SIGNUP_BOT_GUARD_ENABLED`, `/config/COUNTRY_ALLOW`, and `/config/COUNTRY_DENY` (file configuration layer
  state), and must not ignore `bunyip-web/assets/styles.css`.
- `SPEC-14.38.2` `secrets/.gitignore` must ignore everything under `secrets/` except itself, so key material and
  secret value files are never committed.
- `SPEC-14.38.3` The root `.dockerignore` must exclude from the build context `target/`, `.git/`, `secrets/`, `.env`,
  `.env.*`, `**/.env`, `docs/`, `node_modules/`, `*.log`, editor directories, and `bunyip-web/assets/styles.css`
  (rebuilt inside the web image), so no secret or host-only file enters an image layer.
- `SPEC-14.38.4` `.noseyparker-ignore.txt` must list, as repo-root-relative paths in gitignore syntax, the files
  excluded from secret scanning.
- `SPEC-14.38.5` `bunyip-web/.dockerignore` must exclude `target`, `dist`, `node_modules`, `.git`, `.env`, and
  `assets/styles.css` for a build whose context is `bunyip-web/`.

### 14.39 Release, dependency updates, and submodule

- `SPEC-14.39.1` `.gitmodules` must declare exactly one submodule, `common`, at path `common`, whose recipes the root `justfile`
  imports; a clone without it must fail to parse the justfile.
- `SPEC-14.39.2` `renovate.json` must extend the shared default preset, enable only the managers `cargo`, `npm`,
  `docker-compose`, `dockerfile`, and `github-actions`, restrict `npm` to `bunyip-web/package.json`, enable OSV
  vulnerability alerts, and group the packages `rust` and `rustc` under the group name `rust toolchain` so a toolchain
  bump is a separate update.
- `SPEC-14.39.3` The release version must live only at `[workspace.package] version` in the root `Cargo.toml`
  (`SPEC-14.1.2`), and a release must be cut with `just create-release <major|minor|hotfix>` from a host with a Rust
  toolchain, because the recipe runs `cargo` on the host.
