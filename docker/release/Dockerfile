# Used for running integration tests on a simulated MPC network
FROM --platform=arm64 rust:latest AS builder

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
    apt-get install -y libclang-dev

COPY ./ ./

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

# Build the target
RUN cargo build --release

# Release stage
FROM --platform=arm64 debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get install -y ca-certificates

# Copy the binary from the build stage
COPY --from=builder /build/target/release/renegade-relayer /bin/renegade-relayer

ENTRYPOINT [ "/bin/renegade-relayer", "--config-file", "/config.toml" ]