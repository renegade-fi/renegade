# Used for running integration tests on a simulated MPC network
FROM rust:1.63-slim-buster AS builder

# Create a build dir and add local dependencies
WORKDIR /build
COPY ./rust-toolchain ./circuits/rust-toolchain
COPY ./crypto ./crypto
COPY ./integration-helpers ./integration-helpers

# Place a set of dummy sources in the path, build the dummy executable
# to cache built dependencies, then bulid the full executable
WORKDIR /build/circuits
RUN mkdir src
RUN touch src/dummy-lib.rs

RUN mkdir integration
RUN echo 'fn main() { println!("dummy main!") }' >> integration/dummy-main.rs

COPY circuits/Cargo.toml .

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

COPY circuits/src ./src
COPY circuits/integration ./integration

RUN cargo build --quiet --test integration

CMD [ "cargo", "test" ]
