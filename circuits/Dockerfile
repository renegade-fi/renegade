# Used for running integration tests on a simulated MPC network
FROM rust:1.63-slim-buster AS builder

RUN apt-get update && \
    apt-get install -y pkg-config && \
    apt-get install -y libssl-dev  

# Create a build dir and add local dependencies
WORKDIR /build

# Build the rust toolchain before adding any dependencies; this is the slowest
# step and we would like to cache it before anything else
COPY ./rust-toolchain ./circuits/rust-toolchain
RUN cat circuits/rust-toolchain | xargs rustup toolchain install

# Copy in the workspace Cargo.toml and modify the members field, this allows us to skip
# transferring all workspace members to the docker image, and instead only transfer the
# dependencies of the integration test. Every path dependency of the target crate is automatically
# added to the workspace
COPY ./Cargo.toml ./Cargo.toml
RUN sed -i '/members = \[/,/\]/c\members = [ "circuits" ]' Cargo.toml

# Copy in dependencies from the same repo
COPY ./circuit-types ./circuit-types
COPY ./circuit-macros ./circuit-macros
COPY ./common ./common
COPY ./constants ./constants
COPY ./renegade-crypto ./renegade-crypto
COPY ./test-helpers ./test-helpers
COPY ./util ./util

# Place a set of dummy sources in the path, build the dummy executable
# to cache built dependencies, then bulid the full executable
WORKDIR /build/circuits
RUN mkdir src
RUN touch src/dummy-lib.rs

RUN mkdir integration
RUN echo 'fn main() { println!("dummy main!") }' >> integration/dummy-main.rs

COPY circuits/Cargo.toml .
COPY circuits/benches ./benches

# Modify the Cargo.toml to point to our dummy sources
RUN sed -i 's/lib.rs/dummy-lib.rs/g' Cargo.toml
RUN sed -i 's/main.rs/dummy-main.rs/g' Cargo.toml

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

RUN cargo build --quiet --test integration --all-features

# Edit the Cargo.toml back to the original, build the full executable
RUN sed -i 's/dummy-lib.rs/lib.rs/g' Cargo.toml
RUN sed -i 's/dummy-main.rs/main.rs/g' Cargo.toml

COPY circuits/src ./src
COPY circuits/integration ./integration

RUN cargo build --quiet --test integration --all-features

CMD [ "cargo", "test" ]
