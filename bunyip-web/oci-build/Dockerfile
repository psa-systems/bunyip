# syntax=docker/dockerfile:1.6
#
# Production image for bunyip-web: build the release binary + minified CSS, then
# run the Axum SSR server. This ships a running process (not static files), so
# there is no Caddy/entrypoint - the server serves its own pages and the
# /assets/ directory, and reads config from env.
#
# BUILD CONTEXT: the bunyip repo root. Unlike menkent's web crate, bunyip-web
# inherits `[workspace.package]` + workspace dependencies from the root
# Cargo.toml, so it is built as part of the workspace. The build uses the glibc
# builder image because bun + tailwind are needed for the CSS step. Build it:
#
#   docker build -f bunyip-web/oci-build/Dockerfile -t bunyip-web:latest .

# ---- Stage 1: build (cargo-chef) --------------------------------------------
# Dependency caching via cargo-chef (BUNYIP-558), the same three-stage shape
# bunyip-api uses (BUNYIP-389): `chef` carries the toolchain + cargo-chef;
# `planner` distils the dependency recipe from the manifests; `build` cooks the
# dependencies (a layer cached unless the recipe changes) then compiles the real
# workspace. Without it a one-line source edit recompiled axum, tower-http,
# reqwest, rustls and their transitive set from scratch, because the cargo cache
# mounts below hold downloads, not compiled artifacts.
#
# bun + cargo ship in the builder image; only cargo-chef is installed.
# Base images carry both the human-readable tag and the immutable digest
# (BUNYIP-426 F10), so two builds of the same commit cannot pick up different
# layers and a bump is a deliberate, reviewable edit. Re-resolve a digest with
# `docker buildx imagetools inspect <ref> --raw | sha256sum` when bumping a tag.
FROM ghcr.io/niceguyit/rust-builder-glibc:v1.0.1-rust1.94-trixie@sha256:f075f2433e3ba90ad9210794786d6e9b6e3dcc5c647061a468dc773c1a2789f2 AS chef
WORKDIR /app
# The cargo cache mounts here and below carry a per-image `id` and
# `sharing=locked` (BUNYIP-534): an unnamed, shared mount is keyed by target path
# alone, so concurrent builds (a release fires both a main push and a tag push
# onto one buildkit) unpack crates into the same directory and die with
# `.cargo-ok: File exists`. Cargo's own `.package-cache` lock lives outside the
# mount and cannot serialise them. The web ids differ from bunyip-api's, so the
# two images still build in parallel.
RUN --mount=type=cache,id=bunyip-web-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    cargo install cargo-chef --locked

# ---- Planner: distil the dependency recipe from the manifests ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Builder: cook dependencies, then build the web binary + its CSS ----
FROM chef AS build

# nproc/2 concurrency cap (per governance CI.md).
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# Cache JS deps (tailwindcss). The lockfile is copied with the manifest and the
# install is frozen (BUNYIP-566): without it bun re-resolved `^4.0.0` against the
# registry on every build, so two builds of the same commit could ship CSS from
# different Tailwind patch releases with no diff anywhere in the repo.
COPY bunyip-web/package.json bunyip-web/bun.lock /app/bunyip-web/
RUN cd bunyip-web && bun install --frozen-lockfile

# Cook dependencies only, from the recipe. Scoped to `--bin bunyip-web` so it
# builds exactly the dependency set the final build below needs, not the api
# verticals' as well. The dunite git dependency is anonymously readable, so this
# needs no token even though the recipe reaches it through bunyip-domain.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,id=bunyip-web-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=bunyip-web-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json --bin bunyip-web

# BUNYIP-554: build.rs turns these into the `?v=` every /assets reference
# carries, which is what invalidates the immutable one-year Cache-Control on
# that directory. .dockerignore excludes .git, so the build stage cannot derive
# them itself and they MUST be passed in or every deploy reuses one version.
# They stay in this stage (cargo build below consumes them) but BELOW the cook
# and the bun install: a RUN's cache key includes its exec env and CI passes a
# fresh BUILD_DATE every build, so an ENV above them made both layers
# uncacheable (BUNYIP-519). scripts/check-build-cache-keys.nu gates the ordering.
ARG GIT_COMMIT=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
ENV GIT_COMMIT=${GIT_COMMIT} GIT_TAG=${GIT_TAG} BUILD_DATE=${BUILD_DATE}

# Real sources + real build: cargo-chef already compiled every dependency above,
# so this only builds bunyip-web itself. build:css stays AFTER the source copy
# because Tailwind scans the Rust sources for class names.
COPY . /app
RUN --mount=type=cache,id=bunyip-web-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=bunyip-web-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cd bunyip-web && bun run build:css \
    && cd /app && cargo build --locked --release --bin bunyip-web

# ---- Stage 2: run -----------------------------------------------------------
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ARG GIT_COMMIT=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown

# ca-certificates so reqwest (rustls) can validate the API's TLS cert.
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user (UID 1001), mirroring bunyip-api/oci-build/Dockerfile.
RUN groupadd --gid 1001 appuser \
 && useradd --uid 1001 --gid 1001 --no-create-home appuser

WORKDIR /app
COPY --from=build /app/target/release/bunyip-web /app/bunyip-web
COPY --from=build /app/bunyip-web/assets /app/assets
RUN chown -R appuser:appuser /app
USER appuser

LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/bunyip \
      org.opencontainers.image.description="Bunyip Web (PSA Systems)" \
      org.opencontainers.image.revision=${GIT_COMMIT} \
      org.opencontainers.image.version=${GIT_TAG} \
      org.opencontainers.image.created=${BUILD_DATE}

ENV BUNYIP_BIND_ADDR=0.0.0.0:4400
EXPOSE 4400

# WORKDIR is /app so the server's ServeDir("assets") resolves to /app/assets.
CMD ["/app/bunyip-web"]
