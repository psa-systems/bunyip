# syntax=docker/dockerfile:1
#
# Development Dockerfile for bunyip-api.
# Source is bind-mounted at runtime; cargo-watch hot-reloads.

FROM rust:1-slim-trixie

ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install --yes --no-install-recommends \
        pkg-config libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-watch

# Non-root user matching host UID/GID so bind-mounted files stay host-owned.
RUN groupadd --gid ${GID} dev \
    && useradd --uid ${UID} --gid ${GID} --create-home --shell /bin/bash dev \
    && mkdir --parents /app/target \
    && chown --recursive ${UID}:${GID} /app /usr/local/cargo \
    && chmod --recursive 777 /app/target

USER dev
WORKDIR /app

# Source code is mounted via the compose volume.
EXPOSE 8080

CMD ["cargo", "watch", "-x", "run --bin bunyip-api"]
