# Bunyip API - production OCI image
#
# Build context is the repo root. Compose / CI invocation:
#   docker buildx build --tag bunyip-api:local --file bunyip-api/oci-build/Dockerfile .

FROM rust:1-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static lld

ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# Copy workspace manifests + every member's manifest, then create stub source
# files to let cargo cache the dependency build before copying real sources.
COPY Cargo.toml Cargo.lock* ./
COPY bunyip-api/Cargo.toml ./bunyip-api/
COPY bunyip-web/Cargo.toml ./bunyip-web/
COPY crates/bunyip-mocks/Cargo.toml ./crates/bunyip-mocks/

RUN mkdir -p bunyip-api/src bunyip-web/src crates/bunyip-mocks/src \
    && echo 'fn main() {}' > bunyip-api/src/main.rs \
    && echo '' > bunyip-api/src/lib.rs \
    && echo 'fn main() {}' > bunyip-web/src/main.rs \
    && echo '' > crates/bunyip-mocks/src/lib.rs \
    && cargo build --release --bin bunyip-api 2>/dev/null || true \
    && rm -rf bunyip-api/src bunyip-web/src crates/bunyip-mocks/src

# Copy real sources and build.
COPY bunyip-api ./bunyip-api
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bin bunyip-api

# Runtime stage
FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl \
    && adduser --disabled-password --uid 1001 appuser

COPY --from=builder /build/target/release/bunyip-api /app/bunyip-api
COPY seeds /app/seeds

RUN chown --recursive appuser:appuser /app

USER appuser

ARG GIT_SHA=""
LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/bunyip
LABEL org.opencontainers.image.description="Bunyip API"
LABEL org.opencontainers.image.revision="${GIT_SHA}"

ENV BUNYIP_API_BIND=0.0.0.0:8080
ENV BUNYIP_SEEDS_DIR=/app/seeds

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl --silent --fail http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/bunyip-api"]
