# syntax=docker/dockerfile:1
#
# Bunyip API - production OCI image (actix-web backend on the dunite crates).
#
# Build context is the repo root. The dunite crates are a PRIVATE git dependency
# (https://dev.a8n.run/psa-systems/dunite), so the build needs a Forgejo token
# passed as a buildkit secret named `dunite_token`:
#
#   docker buildx build \
#     --secret id=dunite_token,env=DUNITE_GIT_TOKEN \
#     --build-arg GIT_SHA="$(git rev-parse --short HEAD)" \
#     --tag bunyip-api:local --file bunyip-api/oci-build/Dockerfile .
#
# The binary embeds the SQL migrations (sqlx::migrate!) and email templates
# (include_str!) at compile time, so the runtime image is just the static binary.

FROM rust:1-alpine AS builder
WORKDIR /build

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static lld git

# musl-static link via lld; fetch the private git dep with the git CLI (so the
# injected token is honoured); resolve sqlx::query! macros against .sqlx offline.
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    SQLX_OFFLINE=true

ARG GIT_SHA=""
ARG GIT_TAG=""
ENV GIT_COMMIT=${GIT_SHA} GIT_TAG=${GIT_TAG}

# Whole workspace (a .dockerignore keeps target/, .git, secrets out of context).
COPY . .

# Configure git auth from the buildkit secret, then build the release binary.
RUN --mount=type=secret,id=dunite_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    sh -c 'if [ -s /run/secrets/dunite_token ]; then \
              git config --global url."https://oauth2:$(cat /run/secrets/dunite_token)@dev.a8n.run/".insteadOf "https://dev.a8n.run/"; \
           fi' \
    && cargo build --release --bin bunyip-api

# Export stage: `docker buildx build --target export --output type=local,dest=<dir>`
# extracts just the static binary for release-artifact tarballs.
FROM scratch AS export
COPY --from=builder /build/target/release/bunyip-api /bunyip-api

# Runtime stage
FROM alpine:3.21
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl \
    && adduser --disabled-password --uid 1001 appuser

COPY --from=builder /build/target/release/bunyip-api /app/bunyip-api
RUN chown --recursive appuser:appuser /app
USER appuser

ARG GIT_SHA=""
LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/bunyip \
      org.opencontainers.image.description="Bunyip API (PSA Systems)" \
      org.opencontainers.image.revision="${GIT_SHA}"

# Listen address comes from HOST_IP/APP_PORT; everything else is injected at run.
ENV HOST_IP=0.0.0.0 APP_PORT=4401
EXPOSE 4401

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl --silent --fail http://localhost:4401/v1/health || exit 1

ENTRYPOINT ["/app/bunyip-api"]
