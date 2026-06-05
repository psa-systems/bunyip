# syntax=docker/dockerfile:1.6
#
# Development image for bunyip-web: the Axum SSR server with hot reload
# (cargo-watch) + a Tailwind v4 watcher. The whole workspace is bind-mounted at
# /app (see compose.dev.yml). bun and cargo-watch ship in the builder image, so
# there is nothing to install beyond the JS deps.

FROM ghcr.io/niceguyit/rust-builder-glibc:v1.0.0-rust1.94-trixie

# nproc/2 concurrency cap (per governance CI.md).
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# In this base-image tag, /usr/local/bin/bun is a symlink into /root/.bun/bin/bun
# and bunx is missing entirely. /root is mode 0700, so the unprivileged host user
# (see USER below) cannot traverse it: the exec fails with "bun: Permission
# denied", and `bunx` (used by the package.json css scripts) is not found at all.
# Both are a regression of BUNYIP-37. While still root, materialize the real bun
# binary into a world-readable path outside /root and recreate bunx as a symlink
# to it (bun runs `bun x` when invoked as argv0 `bunx`), so the host user can run
# both. (Canonical fix belongs in the rust-builder base image; tracked by BUNYIP-54.)
RUN cp -L /usr/local/bin/bun /usr/local/bin/bun.bin \
 && rm /usr/local/bin/bun \
 && mv /usr/local/bin/bun.bin /usr/local/bin/bun \
 && chmod 0755 /usr/local/bin/bun \
 && ln -s /usr/local/bin/bun /usr/local/bin/bunx

WORKDIR /app

# Cache JS deps (tailwindcss). bun ships in the builder image. bunyip-web is a
# workspace member, so the package.json lives under bunyip-web/.
COPY bunyip-web/package.json /app/bunyip-web/package.json
RUN cd /app/bunyip-web && bun install

# Run as the host user (per governance CHECKLIST) so bind-mounted source and the
# target volume stay writable. CARGO_HOME moves to the user's home for writes.
ARG HOST_UID=1000
ARG HOST_GID=1000
ENV CARGO_HOME=/home/app/.cargo
RUN groupadd --gid ${HOST_GID} app 2>/dev/null || true \
 && useradd --uid ${HOST_UID} --gid ${HOST_GID} --create-home app 2>/dev/null || true \
 && mkdir -p /app/target \
 && chown -R ${HOST_UID}:${HOST_GID} /app /home/app
USER ${HOST_UID}:${HOST_GID}

ENV BUNYIP_BIND_ADDR=0.0.0.0:4400
EXPOSE 4400

# Build CSS once, watch it in the background, and run the web binary with reload.
# Stay in /app/bunyip-web so the server's CWD-relative ServeDir("assets") resolves
# to the crate's assets/ (where build:css writes styles.css). cargo finds the
# workspace by walking up to /app.
CMD ["sh", "-c", "cd /app/bunyip-web && bun run build:css && (bun run watch:css &) && cargo watch -w . -x 'run -p bunyip-web'"]
