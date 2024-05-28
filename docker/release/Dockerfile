# Used for running integration tests on a simulated MPC network

FROM --platform=arm64 rust:latest AS chef

# Create a build dir and add local dependencies
WORKDIR /build

# Build the rust toolchain before adding any dependencies; this is the slowest
# step and we would like to cache it before anything else
COPY ./rust-toolchain ./rust-toolchain
RUN cat rust-toolchain | xargs rustup toolchain install

# Install cargo-chef
RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json

# Install protoc, openssl, and pkg-config
RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y libssl-dev && \
    apt-get install -y libclang-dev

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

ARG CARGO_FEATURES="default"

# Build only the dependencies to cache them in this layer
RUN cargo chef cook --release --recipe-path recipe.json --features "$CARGO_FEATURES"

# Build the bootloader
COPY . .
RUN cargo build --release --package bootloader

# Build the snapshot sidecar
RUN cargo build --release --package snapshot-sidecar

# Build the relayer
RUN cargo build --release --bin renegade-relayer --features "$CARGO_FEATURES"

# Release stage
FROM --platform=arm64 debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get install -y ca-certificates && \
    apt-get install -y awscli

# Copy the binaries from the build stage
COPY --from=builder /build/target/release/bootloader /bin/bootloader
COPY --from=builder /build/target/release/snapshot-sidecar /bin/snapshot-sidecar
COPY --from=builder /build/target/release/renegade-relayer /bin/renegade-relayer

# Copy the bootloader script & make it executable
COPY ./docker/release/bootloader.sh /bootloader.sh
RUN chmod +x /bootloader.sh

# Set the bootloader as the entrypoint
ENTRYPOINT ["/bin/bootloader"]
