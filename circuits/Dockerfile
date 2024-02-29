FROM rust:latest AS builder

# Install the rust toolchain
WORKDIR /build
COPY ./rust-toolchain ./rust-toolchain
RUN cat rust-toolchain | xargs rustup toolchain install

# Install lib dependencies
RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y libssl-dev && \
    apt-get install -y libclang-dev

# Install cargo chef to cache dependencies
RUN cargo install cargo-chef

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

# Build only the deps for the integration test
RUN cargo chef cook --tests --features "test_helpers" --recipe-path recipe.json

WORKDIR /build
COPY . .

# Place a set of dummy sources in the path, build the dummy executable
# to cache built dependencies, then bulid the full executable
WORKDIR /build/circuits
RUN cargo build --quiet --test integration --all-features
