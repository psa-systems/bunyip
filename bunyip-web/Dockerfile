# syntax=docker/dockerfile:1
#
# Development Dockerfile for bunyip-web - dx serve with hot reload + Tailwind v4 watcher.
# Mirrors the mokosh-clients pattern.

FROM rust:1-slim-trixie

ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install --yes --no-install-recommends \
        pkg-config libssl-dev curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# WASM target
RUN rustup target add wasm32-unknown-unknown

# Install Bun (Tailwind v4 CSS)
RUN curl --location --silent --show-error --fail https://bun.sh/install \
    | env BUN_INSTALL=/usr/local bash

# Install dioxus-cli via cargo-binstall (pre-built binary - much faster than building from source)
RUN curl --location --silent --show-error \
    https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-gnu.tgz \
    | tar --extract --gzip --directory /usr/local/cargo/bin
RUN cargo binstall dioxus-cli --no-confirm

RUN groupadd --gid ${GID} dev \
    && useradd --uid ${UID} --gid ${GID} --create-home --shell /bin/bash dev \
    && mkdir --parents /app/bunyip-web /app/target \
    && chown --recursive ${UID}:${GID} /app /usr/local/cargo \
    && chmod --recursive 777 /app/target

USER dev
WORKDIR /app

# Install JS deps (tailwindcss) so `dx serve` can resolve them via node_modules.
# bun.lock is generated on first run; subsequent rebuilds reuse it if present.
COPY --chown=${UID}:${GID} bunyip-web/package.json /app/bunyip-web/package.json
RUN cd /app/bunyip-web && bun install

EXPOSE 4400

# Build CSS once at boot, then start dx serve with a watch on input.css.
CMD ["sh", "-c", "cd bunyip-web && bun run build:css && (bun run watch:css &) && dx serve --port 4400 --addr 0.0.0.0"]
