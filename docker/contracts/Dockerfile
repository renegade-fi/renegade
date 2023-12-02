# This Dockerfile deploys the Renegade contracts to a local devnet,
# assuming that it is already running.
FROM rust:1.63-buster AS sources

# Clone the contracts source
WORKDIR /sources
RUN git clone \
    https://github.com/renegade-fi/renegade-contracts.git

WORKDIR /sources/renegade-contracts

# Build the rust toolchain before adding any dependencies; this is the slowest
# step and we would like to cache it before anything else
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly
RUN rustup target add wasm32-unknown-unknown

# Install `cargo-stylus`
RUN RUSTFLAGS="-C link-args=-rdynamic" cargo install --force cargo-stylus

# Install `wasm-opt`
RUN cargo install wasm-opt --locked

# Build the `scripts` crate
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

# Copy the healthcheck script
COPY ./check_file_exists.sh /check_file_exists.sh

ARG SIGNAL_FILE
ENV SIGNAL_FILE=$SIGNAL_FILE

# Deploy the contracts
ENTRYPOINT /deploy_contracts.sh $SIGNAL_FILE
