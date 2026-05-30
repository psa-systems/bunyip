# syntax=docker/dockerfile:1
#
# Development Dockerfile for bunyip-api (actix-web backend on the dunite crates).
# Source is bind-mounted at runtime; cargo-watch hot-reloads. The dunite crates
# are a private git dependency, fetched with the system git CLI using
# DUNITE_GIT_TOKEN (passed through by compose.dev.yml).

FROM rust:1-slim-trixie

ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install --yes --no-install-recommends \
        pkg-config libssl-dev curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-watch

# Build the dunite git dep with the git CLI (honours the injected token) and
# resolve the bunyip-oidc sqlx::query! macros against the committed .sqlx cache.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    SQLX_OFFLINE=true

# Non-root user matching host UID/GID so bind-mounted files stay host-owned.
RUN groupadd --gid ${GID} dev \
    && useradd --uid ${UID} --gid ${GID} --create-home --shell /bin/bash dev \
    && mkdir --parents /app/target \
    && chown --recursive ${UID}:${GID} /app /usr/local/cargo \
    && chmod --recursive 777 /app/target

USER dev
WORKDIR /app

EXPOSE 4401

# Configure git to authenticate to the private dunite repo with the token (when
# provided), then hot-reload the backend. Watches local code only; the dunite
# git dep is pinned in Cargo.lock.
CMD ["sh", "-c", "if [ -n \"$DUNITE_GIT_TOKEN\" ]; then git config --global url.\"https://oauth2:${DUNITE_GIT_TOKEN}@dev.a8n.run/\".insteadOf \"https://dev.a8n.run/\"; fi; exec cargo watch -w bunyip-api -w crates -x 'run -p bunyip-api'"]
