# This Dockerfile compiles contract sources into .sierra and .casm artifacts so
# that they me be consumed by other Dockerfiles in the relayer for e.g. integration testing
FROM ubuntu AS sources

# Install git and curl
RUN apt-get update && \
    apt-get install -y git && \
    apt-get install -y curl

# Install Scarb
ARG SCARB_VERSION=0.6.2
ENV SHELL /bin/bash
RUN curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | /bin/sh -s -- -v $SCARB_VERSION 
ENV PATH="/root/.local/bin:${PATH}"

# Clone the contracts source and build the contracts
WORKDIR /sources
RUN git clone \
    -b cairo2-no-poseidon-or-verifier \
    https://github.com/renegade-fi/renegade-contracts.git

WORKDIR /sources/renegade-contracts
RUN scarb build

# Move the compiler artifacts to an output direction
RUN mv target/dev /artifacts