# Pull the compiled contract sources from the locally avialable image
# This assumes that you have already built the contract sources, which happens
# automatically when run via `cargo-integrate`
FROM renegade-contracts:latest AS sources

# We use the katana RPC node as a devnet sequencer for testing
# https://book.dojoengine.org/toolchain/katana/overview.html
FROM ubuntu AS devnet

# Install dependencies
RUN apt-get update && \
    apt-get install -y git \
    curl \
    jq \
    gcc

# Install Cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Katana directly from source
ARG DOJO_REVISION=b0d24a3
RUN git clone https://github.com/dojoengine/dojo
WORKDIR /dojo
RUN git checkout $DOJO_REVISION
RUN cargo install --path ./crates/katana --locked --force

# Install the CLI for deploying contracts
WORKDIR /
RUN git clone -b cairo2-no-poseidon-or-verifier \
    https://github.com/renegade-fi/renegade-contracts.git
WORKDIR /renegade-contracts/starknet_scripts
RUN cargo build

# Copy the compiled contract sources from the sources image
WORKDIR /
COPY --from=sources /artifacts /artifacts
COPY ./setup-sequencer.sh /setup-sequencer.sh
RUN /setup-sequencer.sh || exit -1

# Copy the deployment log to a configurable location
ARG DEPLOYMENT_CONFIG_VOLUME=/deployments
RUN mkdir $DEPLOYMENT_CONFIG_VOLUME
RUN cp /renegade-contracts/starknet_scripts/deployments.json $DEPLOYMENT_CONFIG_VOLUME

ENTRYPOINT RUST_LOG=info katana \
    --seed 0 \
    --load-state /katana-state.out \
    --disable-fee \
    --chain-id KATANA