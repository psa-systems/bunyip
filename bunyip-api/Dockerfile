# syntax=docker/dockerfile:1.6
#
# Development image for bunyip-api: the actix-web backend with hot reload
# (cargo-watch, bundled in the builder image). Source is bind-mounted at runtime
# (see compose.dev.yml); the dunite-core kernel is a git dependency
# (https://dev.a8n.run/psa-systems/dunite). The repo is anonymously readable so
# the build needs no credentials, but an optional DUNITE_GIT_TOKEN (passed
# through by compose.dev.yml) is honoured for mirrors that require auth.

FROM ghcr.io/niceguyit/rust-builder-glibc:v1.0.0-rust1.94-trixie

# nproc/2 concurrency cap (per governance CI.md); default keeps small hosts sane.
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# Fetch the dunite git dep with the git CLI (honours the optional injected
# token) and resolve the bunyip-oidc sqlx::query! macros against the committed
# .sqlx cache instead of a live DB.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    SQLX_OFFLINE=true

# Run as the host user (per governance CHECKLIST) so bind-mounted source and the
# target volume stay writable. CARGO_HOME moves to the user's home so the
# registry cache is writable without chowning the whole base image.
ARG HOST_UID=1000
ARG HOST_GID=1000
ENV CARGO_HOME=/home/app/.cargo
# The distribution cache dirs are pre-created WITH ownership so the named
# volumes compose mounts there inherit it on first use (a fresh named volume
# copies the image path's ownership); otherwise they mount root-owned and every
# blob/asset write fails with Permission denied.
RUN groupadd --gid ${HOST_GID} app 2>/dev/null || true \
 && useradd --uid ${HOST_UID} --gid ${HOST_GID} --create-home app 2>/dev/null || true \
 && mkdir -p /app/target /var/cache/bunyip-oci /var/cache/bunyip-downloads \
 && chown -R ${HOST_UID}:${HOST_GID} /app /home/app /var/cache/bunyip-oci /var/cache/bunyip-downloads
WORKDIR /app
USER ${HOST_UID}:${HOST_GID}

EXPOSE 4401

# working_dir is /app (the workspace root) in compose. Configure git auth to the
# dunite repo when a token is provided, then rebuild on changes to the api crate
# and the library crates. cargo-watch ships in the builder image.
CMD ["sh", "-c", "if [ -n \"$DUNITE_GIT_TOKEN\" ]; then git config --global url.\"https://oauth2:${DUNITE_GIT_TOKEN}@dev.a8n.run/\".insteadOf \"https://dev.a8n.run/\"; fi; exec cargo watch -w bunyip-api -w crates -x 'run -p bunyip-api'"]
