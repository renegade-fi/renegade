# --- SOURCES STAGE --- #
# A stage that only caches the build sources so that we may
FROM debian:latest as sources

# Copy all sources, remove those that are not rust files or a Cargo.toml
WORKDIR /build
COPY . .
RUN find . -type f -print | grep -v -E '\.rs$|**/Cargo.toml$' | xargs rm

# --- BUILD STAGE --- #
FROM rust:latest AS builder
WORKDIR /build

# Build the rust toolchain before adding any dependencies
COPY ./rust-toolchain ./rust-toolchain
RUN cat rust-toolchain | xargs rustup toolchain install

# Install protoc, openssl, and pkg-config
RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y libclang-dev && \
    apt-get install -y libssl-dev

# Copy the entire workspace and remove all source files, except for dummy lib entrypoints
COPY  --from=sources /build .
RUN find . -path '*/src/*' ! -name 'lib.rs' -type f -delete
RUN find . -path '*/src/*' -name 'lib.rs' -type f -exec sh -c ': > {}' \;

# Build with a dummy main entrypoint, so that we can cache external dependencies
RUN echo "fn main() {}" >> core/src/main.rs
RUN cargo build --release

# Copy the real sources into the build directory and rebuild without the dummy entrypoints
COPY --from=sources /build .

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

# Build the target
RUN cargo build --release

# --- EXECUTABLE STAGE --- #
FROM debian:latest
RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get install -y ca-certificates

# Copy the binary from the build stage
COPY --from=builder /build/target/debug/renegade-relayer /bin/renegade-relayer

ARG CONFIG_FILE=./docker/frontend-test-stack/config.toml
COPY ${CONFIG_FILE} /config.toml

ENTRYPOINT [ "/bin/renegade-relayer", "--config-file", "/config.toml" ]