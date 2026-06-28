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

# ---- Stage 1: build ---------------------------------------------------------
# bun + cargo ship in the builder image; nothing to install.
FROM ghcr.io/niceguyit/rust-builder-glibc:v1.0.1-rust1.94-trixie AS build

# nproc/2 concurrency cap (per governance CI.md).
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

WORKDIR /app

# Cache JS deps (tailwindcss). bunyip-web/package.json declares the tailwind CLI.
COPY bunyip-web/package.json /app/bunyip-web/package.json
RUN cd bunyip-web && bun install

# Copy the whole workspace and build only the web binary + its CSS.
COPY . /app
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cd bunyip-web && bun run build:css \
    && cd /app && cargo build --locked --release --bin bunyip-web

# ---- Stage 2: run -----------------------------------------------------------
FROM debian:trixie-slim

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
