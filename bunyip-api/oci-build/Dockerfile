# syntax=docker/dockerfile:1.6
#
# Production image for bunyip-api (actix-web backend).
#
# BUILD CONTEXT: the bunyip repo root. bunyip owns the domain (bunyip-domain) +
# the oci/oidc verticals; the generic dunite-core kernel is a git dependency
# (https://dev.a8n.run/psa-systems/dunite). The repo is anonymously readable,
# so the builder only needs network access to dev.a8n.run to fetch it - no
# credentials required. An optional buildkit secret `dunite_token` is honoured
# if a mirror needs auth. Build it like:
#
#   docker buildx build \
#     -f bunyip-api/oci-build/Dockerfile \
#     --secret id=dunite_token,env=DUNITE_GIT_TOKEN \
#     --build-arg GIT_COMMIT="$(git rev-parse --short HEAD)" \
#     --build-arg GIT_TAG="$(git describe --tags --always --dirty)" \
#     -t bunyip-api:latest \
#     .
#
# The binary embeds the SQL migrations (sqlx::migrate!) and email templates
# (include_str!) at compile time, so the runtime image is just the static binary.

# ---- Stage 1: build (cargo-chef) --------------------------------------------
# Dependency caching via cargo-chef (BUNYIP-389): deterministic, with no source
# stubbing, no artifact-deleting globs, no mtime touching, and no stub-leak
# guard. `chef` carries the toolchain + cargo-chef; `planner` distils the
# dependency recipe; `builder` cooks the deps (cached unless the recipe changes)
# then compiles the real workspace.
#
# musl-dev, pkgconfig, openssl-dev/-static, git and lld already ship in
# rust-builder-musl. Use lld for faster linking. Fetch the dunite git dep with
# the git CLI so the optional injected token is honoured. bunyip-oidc uses
# compile-time sqlx::query! macros; resolve them against the committed .sqlx
# offline cache instead of a live database.
# Base images carry both the human-readable tag and the immutable digest
# (BUNYIP-426 F10), so two builds of the same commit cannot pick up different
# layers and a bump is a deliberate, reviewable edit. Re-resolve a digest with
# `docker buildx imagetools inspect <ref> --raw | sha256sum` when bumping a tag.
FROM ghcr.io/niceguyit/rust-builder-musl:v1.0.0-rust1.94-alpine@sha256:6836365513bd46d47b43d014a800f5ae8f429717544fef209b1a0c5730dd5460 AS chef
WORKDIR /build
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    SQLX_OFFLINE=true
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-chef --locked

# ---- Planner: distil the dependency recipe from the manifests ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Builder: cook dependencies, then build the workspace ----
FROM chef AS builder
# Build metadata (passed from CI; build.rs reads these env vars instead of git).
ARG GIT_COMMIT=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
ENV GIT_COMMIT=${GIT_COMMIT} \
    GIT_TAG=${GIT_TAG} \
    BUILD_DATE=${BUILD_DATE}

# nproc/2 concurrency cap (per governance CI.md); CI passes the real value.
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# Cook dependencies only, from the recipe. This layer is cached unless the
# dependency graph changes, regardless of application-code edits. Scoped to the
# two api binaries so it builds exactly the dependency set the final build below
# needs - not the whole workspace (bunyip-web's deps, and resolver-2 duplicate
# feature builds of shared crates), which would roughly double the cook. The
# dunite git dep is anonymously readable; the optional `dunite_token` secret
# configures an authed mirror when present, in the SAME RUN that touches the
# network.
COPY --from=planner /build/recipe.json recipe.json
RUN --mount=type=secret,id=dunite_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    sh -c 'if [ -s /run/secrets/dunite_token ]; then \
              git config --global url."https://oauth2:$(cat /run/secrets/dunite_token)@dev.a8n.run/".insteadOf "https://dev.a8n.run/"; \
           fi' \
    && cargo chef cook --release --recipe-path recipe.json \
        --bin bunyip-api --bin bunyip-e2e-bootstrap

# Real sources + real build. cargo-chef already compiled every dependency above,
# so this only builds the workspace crates and links the binaries. No stub can
# leak, so no size guard is needed.
COPY . .
RUN --mount=type=secret,id=dunite_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    sh -c 'if [ -s /run/secrets/dunite_token ]; then \
              git config --global url."https://oauth2:$(cat /run/secrets/dunite_token)@dev.a8n.run/".insteadOf "https://dev.a8n.run/"; \
           fi' \
    && cargo build --locked --release --bin bunyip-api --bin bunyip-e2e-bootstrap

# ---- Export stage -----------------------------------------------------------
# `docker buildx build --target export --output type=local,dest=<dir>` extracts
# just the static binary for release-artifact tarballs.
FROM scratch AS export
COPY --from=builder /build/target/release/bunyip-api /bunyip-api

# ---- Stage 2: runtime -------------------------------------------------------
# alpine 3.23 matches the `postgres:18.2-alpine3.23` pin in compose.yml, so the
# repo validates one Alpine release rather than three (BUNYIP-426 F10).
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS runtime

ARG GIT_COMMIT=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl
RUN adduser -D -u 1001 appuser

# Binary, migrations (run on startup), and the email templates.
COPY --from=builder /build/target/release/bunyip-api /app/bunyip-api
# One-off staging seeder (BUNYIP-156). Shipped in the image so c-01 can run it
# via `docker compose run --entrypoint /app/bunyip-e2e-bootstrap`. Inert on
# production: it refuses to run unless BUNYIP_E2E_BOOTSTRAP_ALLOW=true AND
# ENVIRONMENT is non-production. ENTRYPOINT below is unchanged.
COPY --from=builder /build/target/release/bunyip-e2e-bootstrap /app/bunyip-e2e-bootstrap
COPY --from=builder /build/bunyip-api/migrations /app/migrations
COPY --from=builder /build/crates/bunyip-domain/templates /app/templates

# Distribution cache dirs: pre-created WITH ownership so named volumes mounted
# here inherit it on first use; root-owned mounts would fail every blob/asset
# write with Permission denied (found during BUNYIP-31 verification).
RUN mkdir -p /var/cache/bunyip-oci /var/cache/bunyip-downloads \
 && chown -R appuser:appuser /app /var/cache/bunyip-oci /var/cache/bunyip-downloads
USER appuser

LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/bunyip \
      org.opencontainers.image.description="Bunyip API (PSA Systems)" \
      org.opencontainers.image.revision=${GIT_COMMIT} \
      org.opencontainers.image.version=${GIT_TAG} \
      org.opencontainers.image.created=${BUILD_DATE}

ENV HOST_IP=0.0.0.0 APP_PORT=4401
EXPOSE 4401

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl --silent --fail http://localhost:4401/v1/health || exit 1

ENTRYPOINT ["/app/bunyip-api"]
