FROM offchainlabs/stylus-node:v0.1.0-f47fec1-dev

# Need to run as root to install dependencies
# (Stylus node base image sets user to `user`)
USER root

RUN apt-get update && apt-get install -y \
    ca-certificates \
    pkg-config \
    libssl-dev \
    build-essential \
    git \
    curl \
    jq

# Install the rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH=/root/.cargo/bin:$PATH
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly
RUN rustup target add wasm32-unknown-unknown

# Install `cargo-stylus`
RUN RUSTFLAGS="-C link-args=-rdynamic" cargo install --force cargo-stylus

# Install `wasm-opt`
RUN cargo install wasm-opt --locked

# Clone the contracts repo
# We ADD the version file first to cache the git clone appropriately
ADD https://api.github.com/repos/renegade-fi/renegade-contracts/git/refs/heads/main /renegade-contracts-version.json
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
RUN RUSTFLAGS="-C opt-level=3" \
    cargo \
    +nightly \
    build \
    -r \
    -p contracts-stylus \
    --features darkpool \
    --target wasm32-unknown-unknown \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort

# Copy over the contract deployment script
COPY ./deploy_contracts.sh /deploy_contracts.sh
RUN chmod +x /deploy_contracts.sh

# Run the contract deployment script
ARG NO_VERIFY
RUN /deploy_contracts.sh

CMD ["--node.dangerous.no-l1-listener",\
    "--node.sequencer.dangerous.no-coordinator",\
    "--node.sequencer.enable",\
    "--node.staker.enable=false",\
    "--init.dev-init",\
    "--init.empty=false",\
    "--chain.id=412346",\
    "--chain.dev-wallet.private-key=b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659",\
    "--http.addr=0.0.0.0",\
    "--http.vhosts=*",\
    "--http.corsdomain=*"]
