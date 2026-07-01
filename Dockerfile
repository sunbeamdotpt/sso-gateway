# syntax=docker/dockerfile:1
# Multi-stage, multi-architecture build for the SSO gateway.
#
# Build for a single platform:
#   docker buildx build --platform linux/amd64 -f Dockerfile -t ghcr.io/sunbeamdotpt/sso-gateway:v0.1.0 .
#
# Build for both platforms:
#   docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile -t ghcr.io/sunbeamdotpt/sso-gateway:v0.1.0 .

ARG VERSION=0.1.0

FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM rust:1.95-bookworm AS builder

# Bring in xx cross-compilation helpers.
COPY --from=xx / /

# Install host build dependencies. protobuf-compiler is needed by connectrpc-build;
# clang + lld are used by xx-cargo for cross-compilation.
RUN apt-get update \
    && apt-get install -y protobuf-compiler clang lld \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the full workspace so path dependencies, proto/, and migrations/ are available.
COPY . .

# Fetch dependencies once, before TARGETPLATFORM is exposed, so the registry
# cache is shared across target architectures.
RUN --mount=type=cache,target=/root/.cargo/git/db \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/registry/index \
    cargo fetch --locked

ARG TARGETPLATFORM

# Install the target C library headers and build the release binary.
# xx-cargo selects the correct Rust target triple from TARGETPLATFORM.
RUN --mount=type=cache,target=/root/.cargo/git/db \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/registry/index \
    xx-apt-get install -y gcc libc6-dev \
    && xx-cargo build --release --locked --bin sso-gateway -p sso-gateway \
    && cp /app/target/$(xx-cargo --print-target-triple)/release/sso-gateway /app/sso-gateway \
    && xx-verify /app/sso-gateway

# Runtime image: distroless with root CA certs and a non-root user.
FROM gcr.io/distroless/cc-debian12:nonroot

ARG VERSION

# OCI annotations so GHCR autolinks the image to the repository.
LABEL org.opencontainers.image.title="sso-gateway" \
      org.opencontainers.image.description="Sunbeam Studios Unified IAM gateway" \
      org.opencontainers.image.url="https://github.com/sunbeamdotpt/sso-gateway" \
      org.opencontainers.image.source="https://github.com/sunbeamdotpt/sso-gateway" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.documentation="https://github.com/sunbeamdotpt/sso-gateway/tree/mainline/docs"

COPY --from=builder /app/sso-gateway /usr/local/bin/sso-gateway

EXPOSE 8080
USER 65532
CMD ["/usr/local/bin/sso-gateway"]
