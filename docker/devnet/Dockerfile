# We modify the base image of the `starknet-devnet` to include the Sierra compiler version
# used in our contracts. The devnet compiles sources once they are declared from Sierra
# to casm, so it needs a matching version to those used to generate the sender side artifacts
FROM shardlabs/starknet-devnet AS base

# Install curl and tar
RUN apk add --no-cache curl tar

# Install the Cairo compiler version used for our contracts
ARG CAIRO_COMPILER_VERSION=2.0.1
WORKDIR /
RUN curl -L -o /cairo-build.tar.gz https://github.com/starkware-libs/cairo/releases/download/v${CAIRO_COMPILER_VERSION}/release-x86_64-unknown-linux-musl.tar.gz

RUN tar -xzf /cairo-build.tar.gz
RUN rm /cairo-build.tar.gz

# Modify the entrypoint to run with our custom flags
ENTRYPOINT starknet-devnet \
    --sierra-compiler-path /cairo/bin/starknet-sierra-compile \
    --compiler-args "--add-pythonic-hints --allowed-libfuncs-list-name all" \
    --fork-network alpha-goerli \
    --fork-retries 3 \
    --timeout 1000 \
    --host 0.0.0.0 \
    --port 5050 \
    --seed 0 \
    --lite-mode \
    --verbose