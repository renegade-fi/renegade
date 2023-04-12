# Used for running integration tests on a simulated MPC network
FROM rust:latest AS builder

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
    apt-get install -y libssl-dev

COPY Cargo.toml Cargo.lock ./
COPY ./core/Cargo.toml ./core/Cargo.toml
COPY ./circuits ./circuits
COPY ./crypto ./crypto
COPY ./circuit-macros ./circuit-macros
COPY ./integration-helpers ./integration-helpers

# Create a dummy entrypoint to build the dependencies
RUN mkdir core/src
RUN echo 'fn main() { println!("dummy main!") }' >> core/src/main.rs

# Build the dependencies
RUN cargo build --release

# Copy the real sources into the build directory and rebuild without the dummy main
COPY ./core ./core

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

# Build the target
RUN cargo build --release

# Release stage
FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get install -y ca-certificates

# Copy the binary from the build stage
COPY --from=builder /build/target/release/renegade-relayer /bin/renegade-relayer
COPY ./core/resources/no_commit/release.toml /resources/release.toml

ENTRYPOINT [ "/bin/renegade-relayer", "--config-file", "/resources/release.toml" ]