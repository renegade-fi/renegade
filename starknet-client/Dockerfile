# Build a set of sources that are used to build a dependency cache for the main
# integration tests. We effectively copy all the sources and then remove the target
# directory. This means that changes to `starknet-client` sources will invalidate the
# cache for this stage only, as the end state is the same
FROM alpine AS sources
COPY . .
RUN rm -rf starknet-client

# Rust build stage
FROM rust:1.63-slim-buster AS builder

# Install pkg-config, openssl
RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y libssl-dev 

# Build the rust toolchain before adding any dependencies; this is the slowest
# step and we would like to cache it before anything else
COPY ./rust-toolchain ./starknet-client/rust-toolchain
RUN cat starknet-client/rust-toolchain | xargs rustup toolchain install

# Create a build dir and add local dependencies
WORKDIR /build
COPY --from=sources . .

# Copy in the workspace Cargo.toml and modify the members field, this allows us to skip
# transferring all workspace members to the docker image, and instead only transfer the
# dependencies of the integration test. Every path dependency of the target crate is automatically
# added to the workspace
COPY ./Cargo.toml ./Cargo.toml
RUN sed -i '/members = \[/,/\]/c\members = [ "starknet-client" ]' Cargo.toml

# Place a set of dummy sources in the path, build the dummy executable
# to cache built dependencies, then bulid the full executable
WORKDIR /build/starknet-client
RUN mkdir src
RUN touch src/dummy-lib.rs

RUN mkdir integration
RUN echo 'fn main() { println!("dummy main!") }' >> integration/dummy-main.rs

COPY starknet-client/Cargo.toml .

# Modify the Cargo.toml to point to our dummy sources
RUN sed -i 's/lib.rs/dummy-lib.rs/g' Cargo.toml
RUN sed -i 's/main.rs/dummy-main.rs/g' Cargo.toml

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

RUN cargo build --quiet --test integration 

# Edit the Cargo.toml back to the original, build the full executable
RUN sed -i 's/dummy-lib.rs/lib.rs/g' Cargo.toml
RUN sed -i 's/dummy-main.rs/main.rs/g' Cargo.toml

COPY starknet-client/src ./src
COPY starknet-client/integration ./integration

RUN cargo build --quiet --test integration 
