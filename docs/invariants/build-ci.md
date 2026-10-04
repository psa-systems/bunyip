# Build, CI and repo tooling

Full text of the build, CI and repo tooling conventions indexed in [`CLAUDE.md`](../../CLAUDE.md#critical-conventions), moved here verbatim (BUNYIP-854).

## sqlx

**sqlx**: only `bunyip-oidc` uses compile-time `sqlx::query!` macros. They resolve against the workspace-root `.sqlx/` offline cache; build with `SQLX_OFFLINE=true` (the justfile/Dockerfiles set it). After changing those queries, regenerate `.sqlx/` and commit it.

## Migrations (BUNYIP-293)

**Migrations** live in `bunyip-api/migrations/` and run on api startup. **Committed migrations are immutable.** sqlx checksums every applied migration in `_sqlx_migrations` and a deployed database refuses to boot once a migration's on-disk content disagrees with the recorded checksum (`migration <version> was previously applied but has been modified`). Never edit, rename, or delete a migration already on `main`: fix forward with a NEW migration file. CI and `just check` enforce this via common's shared `check-migration-immutability` recipe (PC-82), which replaced bunyip's own `scripts/check-migration-immutability.nu` (BUNYIP-293); it guards only `.sql` paths, so the migrations `README.md` can be edited (BUNYIP-458); `scripts/reconcile-sqlx-checksums.md` covers recovering a DB that was broken by an in-place edit.

## Images (BUNYIP-389, BUNYIP-558, BUNYIP-426, BUNYIP-534)

**Images**: bunyip-api is a musl-static build (`rust-builder-musl` base, governance `Dockerfile.oci-musl` pattern); bunyip-web is glibc (`rust-builder-glibc` base, needs bun + tailwind), governance `Dockerfile.oci-glibc` pattern. Both pass `GIT_COMMIT` / `GIT_TAG` / `BUILD_DATE` build args; tags come from `oci-build/get-tags.nu`. Both `oci-build/Dockerfile`s stage dependencies with cargo-chef (`chef` / `planner` / builder), each cook scoped to its own binaries (`--bin bunyip-web`; `--bin bunyip-api --bin bunyip-e2e-bootstrap`) so neither image compiles the other's dependency set: BUNYIP-389 for the api, BUNYIP-558 for the web, where a one-line source edit had been recompiling all 153 crates because the cargo cache mounts hold downloads, not artifacts. In the web image `bun run build:css` stays AFTER the source copy, since Tailwind scans the Rust sources for class names. Every external `FROM` in both Dockerfiles carries `tag@sha256:<digest>` (BUNYIP-426 F10); the api runtime tracks the same Alpine release `compose.yml` pins for postgres. Re-resolve a digest with `docker buildx imagetools inspect <ref> --raw | sha256sum` when bumping a tag, and change both halves together. Every buildkit cargo cache mount carries a per-image `id=` (`bunyip-{api,web}-cargo-{registry,git}`) and `sharing=locked` (BUNYIP-534): the publish workflows share one buildkit instance and a release commit fires both a `main` push and a `v*` tag push, so an unnamed shared mount (keyed by target path alone) let concurrent builds unpack crates into one directory and fail with `.cargo-ok: File exists`. Cargo's `.package-cache` lock sits at `$CARGO_HOME/.package-cache`, outside the mount, so it cannot serialise them. `scripts/check-cache-mount-sharing.nu` gates every Dockerfile in `check.yml`. Build metadata (`GIT_COMMIT` / `GIT_TAG` / `BUILD_DATE`) is declared BELOW the cook in both Dockerfiles, never above it: a RUN's buildkit cache key includes its exec environment and CI passes a fresh `BUILD_DATE` every build, so an `ENV` up in the stage header left the cook `DONE` rather than `CACHED` on 20 of 20 measured API runs - 68% of an 11-minute build (BUNYIP-519); `scripts/check-build-cache-keys.nu` gates the ordering. Both publish workflows declare ONE shared `paths:` filter, which `e2e/scripts/wait-for-deploy.mjs` replays, so either both images build for a merge or neither does and `bunyip-api:latest` / `bunyip-web:latest` can never name different commits (they did on 63% of merges before); `scripts/check-publish-triggers.nu` gates the three lists against each other. `--cache-to ...,ignore-error=true` stays, so a cache hiccup cannot fail a publish, but the workflows now assert the gha cache credentials exist BEFORE building (fatal, since without them every build is silently cold) and report evicted blobs, a missing manifest, or a cook that rebuilt despite an unchanged recipe AFTER building (warnings, since none of those make the published image wrong) via `scripts/check-build-cache-health.nu`.

## Workflow shell (BUNYIP-489)

**Workflow shell**: every `run:` step in `.forgejo/workflows/` executes under Nushell. Each job declares it once (`defaults.run.shell: nu {0}`) instead of per step, so a new step cannot inherit Bash; `scripts/check-workflow-shell.nu` gates both halves in `check.yml` (BUNYIP-489). Nushell has no backslash line continuation, so multi-line commands stay on one line.

## Scripts are Nushell (BUNYIP-490)

**Scripts are Nushell**: every script under `scripts/` (the CI guards plus the operator scripts) is a `#!/usr/bin/env nu` script, not Bash (BUNYIP-490). Nushell `0.112.2` is a documented prerequisite (`docs/getting-started.md`) and is present on the runners. `scripts/check-no-bash.nu` fails the build on any `.sh` file or POSIX-shell shebang under `scripts/`.

## Conformance

**Conformance**: this repo follows the governance standard at `../governance/` (CHECKLIST.md, BUILD.md, CI.md), mirroring `menkent`. Keep the version metadata as `version + hash + date` (`GIT_COMMIT` / `GIT_TAG` / `BUILD_DATE`).

## Forgejo org

**Forgejo org**: this repo lives in `psa-systems`; images publish to `psa-systems-private`.

## No em-dashes

**No em-dashes** in any output or artifact; use a hyphen, colon, parentheses, or a new sentence.
