# Bunyip-on-dunite rebuild: scaffold + fill plan

Snapshot date: 2026-05-30. Tracking issue: **BUNYIP-26**.

## Goal

Replace `bunyip-api` (today an axum in-memory mock: `crates/bunyip-mocks` +
`seeds/*.json`, stubbed OIDC) with a real actix-web SaaS backend that **is the
OIDC provider** (mokosh-server and other relying parties are clients), built on
the generic `dunite-core` kernel, mirroring the `menkent` reference consumer.
v1 is single-tenant / per-user (matches the kernel); the old org-centric model
is deferred to future multi-tenant work.

## Why this is a scaffold, not the full build

Both sibling repos were **actively mid-refactor** when this landed, changing
between individual edits:

- **dunite** - on step 2/4 of a "library-only" refactor:
  - `step 1/4`: removed the `a8n-api` binary; workspace is library-only.
  - `step 2/4`: `dunite-oci` made a generic, storage-agnostic registry engine
    (consumer provides `BlobStore`/`PullCounter` traits + HTTP wiring).
  - steps 3/4 (pending): `dunite-core` still ships the full fat domain layer
    (config/models/repositories/services incl. application/stripe/totp/user);
    that domain code is slated for removal. `dunite-oidc` not yet generic-ized.
- **menkent** - uncommitted working-tree rewrite: renaming `menkent-domain` ->
  `menkent-core` and, per `menkent-core`'s own manifest, **dropping the dunite
  dependency entirely** ("Owned wholesale by menkent (no dunite dependency)").

### Unresolved contradiction (decide before filling)

The directive for Bunyip is to **consume `dunite/crates/*`** ("dunite is 100%
generic; all domain-specific logic lives in bunyip"). But the reference example
(`menkent`) is currently moving the **opposite** way - forking everything into
`menkent-core` and cutting dunite loose. So the consumption boundary is
genuinely undecided:

- **Consume dunite** (the stated directive): `bunyip-domain` re-exports the
  generic `dunite-core` kernel and owns only Bunyip's domain specifics. Robust
  to dunite's domain-code removal *iff* we depend only on the slimmed kernel.
- **Own wholesale** (menkent's current trajectory): `bunyip-domain` forks the
  layers, no dunite dependency. More code, zero coupling.

Resolve this once dunite finishes steps 3/4 and menkent commits `menkent-core`.

## What the scaffold sets up (this PR)

- `crates/bunyip-domain` - empty domain-layer skeleton (mirrors `menkent-core`).
- `crates/bunyip-oci` - empty OCI vertical skeleton (mirrors `menkent-oci`).
- `crates/bunyip-oidc` - empty OIDC provider skeleton (mirrors `menkent-oidc`).
- All three added to the workspace `members`.
- `dunite-*` wired as **optional path deps** behind a `dunite` feature
  (off by default) so the workspace compiles independently of upstream churn.
  `cargo check -p bunyip-domain -p bunyip-oci -p bunyip-oidc` is green.
- `bunyip-api/migrations/` - the 53 SQL migrations vendored from
  `menkent/api/migrations` (dunite no longer ships migrations). Unpruned.
- `compose.dev.yml` - added an idle `postgres:16-alpine` service
  (`dev-bunyip-postgres-${USER}`), ready for the actix backend.

The existing axum mock (`bunyip-api`, `crates/bunyip-mocks`, `seeds/`),
`bunyip-web`, `README.md`, and `.env.example` are **left untouched** - the app
still builds and runs as before.

## Fill steps (once upstream stabilizes)

1. Decide the consumption boundary (above). Flip on the `dunite` feature or
   commit to wholesale ownership.
2. Fill `bunyip-domain` (config/models/repositories/services), then `bunyip-oci`
   and `bunyip-oidc` verticals, porting from menkent and stripping a8n.tools
   branding.
3. Convert `bunyip-api` from the axum mock to a thin actix binary: `lib.rs`
   re-exports, `main.rs` app assembly (dual HttpServer: primary + OCI port),
   local `handlers/*` + `routes/*`, plus a ported `/version` update-check.
4. Prune migrations: delete the 6 domain seeds -
   `20241230000008_seed_applications.sql` and the five
   `*_register_*_oidc_client.sql` files; strip the hardcoded a8n client
   `INSERT`s from `*_create_oidc_clients.sql` (keep the DDL); add Bunyip's own
   `oauth_clients` seed (mokosh-server + bunyip-web RP) and `applications` seed.
5. Generate a dev OIDC Ed25519 keypair into a gitignored `secrets/`.
6. Finish dev/prod infra: wire `bunyip-api` to Postgres + the side-by-side
   `../dunite` mount (dev) / parent-dir build context (prod), `SQLX_OFFLINE`,
   OIDC key mount; dev + prod Dockerfiles; justfile `migrate`/build recipes.
7. Retire the mock: remove `crates/bunyip-mocks`, `seeds/`, and the mock env.
8. Follow-ups (out of this work): realign the Dioxus `bunyip-web` SPA + fix the
   reversed OIDC wiring in `.env.example` (bunyip-web is currently a client of
   mokosh; it should consume Bunyip's own issuer).

## Reference

`menkent/api/src/{main.rs,routes/mod.rs,lib.rs}`, `menkent/crates/menkent-{core,oci,oidc}`,
`menkent/compose.dev.yml`, `menkent/api/oci-build/api/Dockerfile`.
