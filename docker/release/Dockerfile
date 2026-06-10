FROM --platform=arm64 rust:1.89-trixie AS builder

# Create a build dir and add local dependencies
WORKDIR /build

# Build the rust toolchain before adding any dependencies; this is the slowest
# step and we would like to cache it before anything else
COPY ./rust-toolchain ./rust-toolchain
RUN cat rust-toolchain | xargs rustup toolchain install

# Install protoc, openssl, and pkg-config
RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y libssl-dev && \
    apt-get install -y libclang-dev && \
    apt-get install -y ca-certificates

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

ARG CARGO_FEATURES="default"

# Copy the source code
# We don't use cargo chef here because the dependencies are too complex to be effectively cached.
# In particular, the contracts abi relies recursively on the circuits, darkpool-types, etc
# `cargo chef cook` will overwrite these dependencies locally, so imports from them in the contracts will fail.
# We should write a simple Renegade-specific version of `cargo chef` instead.
COPY . .

# Build all binaries in a single layer so the target/ cache mount is live
# for the copy-out step. BuildKit cache mounts persist across builds but are
# NOT part of the image filesystem, so we cp the artifacts to /build/bin
# before the RUN ends; otherwise the later COPY --from=builder finds nothing.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    mkdir -p /build/bin && \
    # The sidecars and bootloader are off the matching hot path, so they use
    # release-fast: skipping their fat-LTO codegen-units=1 links saves ~13min
    # per image build. The relayer keeps the fully optimized release profile.
    cargo build --locked --profile release-fast --package bootloader && \
    cargo build --locked --profile release-fast --package snapshot-sidecar && \
    cargo build --locked --profile release-fast --package event-export-sidecar && \
    cargo build --locked --profile release-fast --package indexer-message-sidecar && \
    cargo build --locked --release --bin renegade-relayer --features "$CARGO_FEATURES" && \
    cp target/release-fast/bootloader \
       target/release-fast/snapshot-sidecar \
       target/release-fast/event-export-sidecar \
       target/release-fast/indexer-message-sidecar \
       target/release/renegade-relayer \
       /build/bin/

# Release stage
FROM --platform=arm64 debian:trixie-slim

RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get install -y ca-certificates && \
    apt-get install -y awscli

# Copy the binaries from the build stage
COPY --from=builder /build/bin/bootloader /bin/bootloader
COPY --from=builder /build/bin/snapshot-sidecar /bin/snapshot-sidecar
COPY --from=builder /build/bin/event-export-sidecar /bin/event-export-sidecar
COPY --from=builder /build/bin/indexer-message-sidecar /bin/indexer-message-sidecar
COPY --from=builder /build/bin/renegade-relayer /bin/renegade-relayer

# Set the bootloader as the entrypoint
ENTRYPOINT ["/bin/bootloader"]
