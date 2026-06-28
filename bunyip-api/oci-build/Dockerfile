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

# ---- Stage 1: build ---------------------------------------------------------
FROM ghcr.io/niceguyit/rust-builder-musl:v1.0.0-rust1.94-alpine AS builder
WORKDIR /build

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

# musl-dev, pkgconfig, openssl-dev/-static, git and lld already ship in
# rust-builder-musl. Use lld for faster linking. Fetch the dunite git dep with
# the git CLI so the optional injected token is honoured. bunyip-oidc uses
# compile-time sqlx::query! macros; resolve them against the committed .sqlx
# offline cache instead of a live database.
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    SQLX_OFFLINE=true

# ---- Dependency cache layer ----
# Copy every workspace manifest and stub their sources so the full dependency
# graph compiles and caches before the real sources are copied. Editing
# application code then reuses this layer. The dunite git config (from the
# optional secret) has to be set in the SAME RUN that touches the network.
COPY Cargo.toml Cargo.lock ./
COPY .sqlx .sqlx
COPY bunyip-api/Cargo.toml bunyip-api/build.rs bunyip-api/
COPY bunyip-web/Cargo.toml bunyip-web/
COPY crates/bunyip-domain/Cargo.toml crates/bunyip-domain/
COPY crates/bunyip-oci/Cargo.toml crates/bunyip-oci/
COPY crates/bunyip-oidc/Cargo.toml crates/bunyip-oidc/
# bunyip-domain include_str!'s its email templates at compile time.
COPY crates/bunyip-domain/templates crates/bunyip-domain/templates
RUN mkdir -p \
        bunyip-api/src bunyip-web/src \
        crates/bunyip-domain/src crates/bunyip-oci/src crates/bunyip-oidc/src \
    && echo "fn main() {}" > bunyip-api/src/main.rs \
    && echo "fn main() {}" > bunyip-web/src/main.rs \
    && : > crates/bunyip-domain/src/lib.rs \
    && : > crates/bunyip-oci/src/lib.rs \
    && : > crates/bunyip-oidc/src/lib.rs

# Build the api binary's dependency graph only (cached unless a manifest changes).
#
# After the stub build, every workspace-crate artifact AND its cargo
# fingerprint must be removed. Removing only the deps/ files is not enough:
# `COPY . .` preserves host mtimes (older than the stub build), so cargo would
# consider the stub-built empty libs fresh and link the real bunyip-api against
# them, failing with unresolved imports.
RUN --mount=type=secret,id=dunite_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    sh -c 'if [ -s /run/secrets/dunite_token ]; then \
              git config --global url."https://oauth2:$(cat /run/secrets/dunite_token)@dev.a8n.run/".insteadOf "https://dev.a8n.run/"; \
           fi' \
    && cargo build --locked --release --bin bunyip-api \
    && rm -rf bunyip-api/src bunyip-web/src \
        crates/bunyip-domain/src crates/bunyip-oci/src crates/bunyip-oidc/src \
        target/release/deps/*bunyip* \
        target/release/.fingerprint/bunyip-* \
        target/release/bunyip-api*

# ---- Real sources ----
COPY . .

# `COPY . .` restores host mtimes that are OLDER than the stub-built artifacts
# above, so cargo can judge the workspace up-to-date and ship the stub instead
# of the real binary (this is exactly how v0.2.0 shipped a 557 KB `fn main() {}`
# stub - BUNYIP-58). Touch every source so it is newer than any cached artifact,
# forcing a real recompile regardless of host mtimes.
RUN --mount=type=secret,id=dunite_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    sh -c 'if [ -s /run/secrets/dunite_token ]; then \
              git config --global url."https://oauth2:$(cat /run/secrets/dunite_token)@dev.a8n.run/".insteadOf "https://dev.a8n.run/"; \
           fi' \
    && find . -name '*.rs' -exec touch {} + \
    && cargo build --locked --release --bin bunyip-api --bin bunyip-e2e-bootstrap

# Belt-and-suspenders: a stub bunyip-api is ~0.5 MB, the real server is tens of
# MB. Fail the build loudly here rather than let a stub reach the registry and
# silently restart-loop in production (BUNYIP-58).
RUN sz="$(stat -c%s target/release/bunyip-api)"; \
    echo "bunyip-api release binary: $sz bytes"; \
    if [ "$sz" -lt 5000000 ]; then \
        echo "FATAL: bunyip-api binary is $sz bytes (< 5 MB) - stub build leaked; aborting." >&2; \
        exit 1; \
    fi

# ---- Export stage -----------------------------------------------------------
# `docker buildx build --target export --output type=local,dest=<dir>` extracts
# just the static binary for release-artifact tarballs.
FROM scratch AS export
COPY --from=builder /build/target/release/bunyip-api /bunyip-api

# ---- Stage 2: runtime -------------------------------------------------------
FROM alpine:3.21 AS runtime

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
