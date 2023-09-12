FROM rust:bookworm AS builder

# Create a build dir and add local dependencies
WORKDIR /build

# Build the rust toolchain before adding any dependencies; this is the slowest
# step and we would like to cache it before anything else
COPY ./rust-toolchain ./rust-toolchain
RUN cat rust-toolchain | xargs rustup toolchain install

# Install protoc, openssl, and pkg-config
RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y wget && \
    apt-get install -y perl && \
    apt-get install -y gcc && \
    apt-get install -y pkg-config && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y libclang-dev && \
    apt-get install -y libssl-dev && \
    apt-get install -y libz-dev

# Install libssl3 from source
RUN wget https://www.openssl.org/source/openssl-3.0.10.tar.gz
RUN tar -xzvf openssl-*.tar.gz && rm -rf openssl-*.tar.gz
WORKDIR /build/openssl-3.0.10
RUN ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
RUN make && make install
WORKDIR /build

# Copy the entire workspace and remove all source files, except for dummy lib entrypoints
COPY . .
RUN find . -path '*/src/*' ! -name 'lib.rs' -type f -delete
RUN find . -path '*/src/*' -name 'lib.rs' -type f -exec sh -c ': > {}' \;

# Build with a dummy main entrypoint, so that we can cache external dependencies
RUN echo "fn main() {}" >> core/src/main.rs
RUN cargo build

# Copy the real sources into the build directory and rebuild without the dummy entrypoints
COPY . .

# Disable compiler warnings and enable backtraces for panic debugging
ENV RUSTFLAGS=-Awarnings
ENV RUST_BACKTRACE=1

# Build the target
RUN cargo build

# Release stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y libssl-dev && \
    apt-get install -y ca-certificates

# Copy the binaries from the build stage
COPY --from=builder /build/target/debug/renegade-relayer /bin/renegade-relayer
COPY --from=builder /usr/local/ssl /usr/local/ssl
ENV LD_LIBRARY_PATH=/usr/local/ssl/lib

ENTRYPOINT [ "/bin/renegade-relayer", "--config-file", "/config.toml" ]
