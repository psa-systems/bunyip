# Bunyip Web - production OCI image (Dioxus WASM bundle served by Caddy)
#
# Build context is the repo root. Compose / CI invocation:
#   docker buildx build --tag bunyip-web:local --file bunyip-web/oci-build/Dockerfile .

# Build stage (trixie for glibc 2.41, required by pre-built dioxus-cli binary)
FROM rust:1-slim-trixie AS builder

WORKDIR /build

RUN apt-get update && apt-get install --yes --no-install-recommends \
        curl pkg-config libssl-dev unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Bun (Tailwind v4 CSS build)
RUN curl --location --silent --show-error --fail https://bun.sh/install \
    | env BUN_INSTALL=/usr/local bash

# Install cargo-binstall, then use it to fetch the pre-built dioxus-cli.
# TARGETARCH is provided automatically by buildx; map it to the binstall
# release naming so the image builds for both amd64 and arm64.
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) binstall_arch=x86_64 ;; \
      arm64) binstall_arch=aarch64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --location --silent --show-error \
      "https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-${binstall_arch}-unknown-linux-gnu.tgz" \
      | tar --extract --gzip --directory /usr/local/cargo/bin
RUN cargo binstall dioxus-cli --no-confirm

# Install WASM target for client build
RUN rustup target add wasm32-unknown-unknown

# --- Dependency caching (no source) ---
# Copy every workspace manifest so cargo can resolve the workspace.
COPY Cargo.toml Cargo.lock* ./
COPY bunyip-api/Cargo.toml ./bunyip-api/
COPY bunyip-web/Cargo.toml ./bunyip-web/
COPY crates/bunyip-mocks/Cargo.toml ./crates/bunyip-mocks/

RUN mkdir -p bunyip-api/src bunyip-web/src crates/bunyip-mocks/src \
    && echo 'fn main() {}' > bunyip-api/src/main.rs \
    && echo '' > bunyip-api/src/lib.rs \
    && echo 'fn main() {}' > bunyip-web/src/main.rs \
    && echo '' > crates/bunyip-mocks/src/lib.rs \
    && cargo build --release --target wasm32-unknown-unknown --package bunyip-web 2>/dev/null || true \
    && rm -rf bunyip-api/src bunyip-web/src crates/bunyip-mocks/src

# --- Tailwind / Bun deps ---
COPY bunyip-web/package.json bunyip-web/bun.lock* ./bunyip-web/
RUN cd bunyip-web && bun install --frozen-lockfile

# --- Full source ---
COPY . .

RUN cd bunyip-web && bun run build:css

# Build the WASM bundle + static assets.
RUN cd bunyip-web && dx build --release

# Runtime stage - serve static assets via Caddy
FROM alpine:3.21

# Copy Caddy from the official image.
COPY --from=caddy:alpine /usr/bin/caddy /usr/bin/caddy

# Copy static bundle. Adjust the source path if Dioxus changes its output layout.
COPY --from=builder /build/target/dx/bunyip-web/release/web/public /usr/share/caddy

COPY bunyip-web/oci-build/Caddyfile /etc/caddy/Caddyfile

RUN adduser --disabled-password --uid 1001 appuser \
    && chown --recursive appuser:appuser /usr/share/caddy
USER appuser

ENV PORT=8080
EXPOSE 8080

ARG GIT_SHA=""
LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/bunyip
LABEL org.opencontainers.image.description="Bunyip Dioxus client"
LABEL org.opencontainers.image.revision="${GIT_SHA}"

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
