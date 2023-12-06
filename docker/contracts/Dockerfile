# Builds and deploys the contracts to the (assumed to be running) local devnet

FROM rust:1.70-slim-buster AS builder

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y libssl-dev && \
    apt-get install -y build-essential && \
    apt-get install -y git && \
    apt-get install -y curl && \
    apt-get install -y jq

# Build the rust toolchain to cache it before adding any dependencies
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly
RUN rustup target add wasm32-unknown-unknown

# Install `cargo-stylus`
RUN RUSTFLAGS="-C link-args=-rdynamic" cargo install --force cargo-stylus

# Install `wasm-opt`
RUN cargo install wasm-opt --locked

# Clone the contracts repo
WORKDIR /sources
RUN git clone \
    https://github.com/renegade-fi/renegade-contracts.git

WORKDIR /sources/renegade-contracts

# Build the `scripts` crate to cache it
RUN cargo build -p scripts

# Build the darkpool contract with the same flags as the deploy scripts
# to cache the dependencies.
# The actual deploy script will rebuild & deploy this contract, along with
# the others.
RUN cargo \
    +nightly \
    build \
    -r \
    -p contracts-stylus \
    --features darkpool \
    --target wasm32-unknown-unknown \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort

# Copy the deploy script
COPY ./deploy_contracts.sh /deploy_contracts.sh

ENTRYPOINT /deploy_contracts.sh
