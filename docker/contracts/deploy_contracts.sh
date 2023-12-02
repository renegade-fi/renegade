#!/bin/bash

# Exit on error
set -e

# Check if enough arguments are passed
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <signal_file_path>"
    exit 1
fi

# The first argument is the path to the signal file
SIGNAL_FILE="$1"

# Returns either "--no-verify" or an empty string
# depending on whether the $NO_VERIFY env var is set
no_verify() {
    if [[ -n $NO_VERIFY ]]; then
        echo "--no-verify"
    fi
    # Implicitly returns an empty string if $NO_VERIFY is unset
}

# Deploy verifier contract
cargo run \
    -p scripts -- \
    -p $DEVNET_PKEY \
    -r $DEVNET_RPC_URL \
    -d $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract verifier \

# Deploy Merkle contract
cargo run \
    -p scripts -- \
    -p $DEVNET_PKEY \
    -r $DEVNET_RPC_URL \
    -d $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract merkle \

# Deploy darkpool contract, setting the "--no-verify" flag
# conditionally depending on whether the corresponding env var is set
cargo run \
    -p scripts -- \
    -p $DEVNET_PKEY \
    -r $DEVNET_RPC_URL \
    -d $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract darkpool-test-contract \
    $(no_verify)

# Deploy the proxy contract
cargo run \
    -p scripts -- \
    -p $DEVNET_PKEY \
    -r $DEVNET_RPC_URL \
    -d $DEPLOYMENTS_PATH \
    deploy-proxy \
    -o $DEVNET_ACCOUNT_ADDRESS

# If the $UPLOAD_VKEYS env var is set, upload the verification keys
if [[ -n $UPLOAD_VKEYS ]]; then
    # Upload VALID WALLET CREATE verification key
    cargo run \
        -p scripts -- \
        -p $DEVNET_PKEY \
        -r $DEVNET_RPC_URL \
        -d $DEPLOYMENTS_PATH \
        upload-vkey \
        -c valid-wallet-create

    # Upload VALID WALLET UPDATE verification key
    cargo run \
        -p scripts -- \
        -p $DEVNET_PKEY \
        -r $DEVNET_RPC_URL \
        -d $DEPLOYMENTS_PATH \
        upload-vkey \
        -c valid-wallet-update

    # Upload VALID COMMITMENTS verification key
    cargo run \
        -p scripts -- \
        -p $DEVNET_PKEY \
        -r $DEVNET_RPC_URL \
        -d $DEPLOYMENTS_PATH \
        upload-vkey \
        -c valid-commitments

    # Upload VALID REBLIND verification key
    cargo run \
        -p scripts -- \
        -p $DEVNET_PKEY \
        -r $DEVNET_RPC_URL \
        -d $DEPLOYMENTS_PATH \
        upload-vkey \
        -c valid-reblind

    # Upload VALID MATCH SETTLE verification key
    cargo run \
        -p scripts -- \
        -p $DEVNET_PKEY \
        -r $DEVNET_RPC_URL \
        -d $DEPLOYMENTS_PATH \
        upload-vkey \
        -c valid-match-settle
fi

# Write a file signaling that the contracts have been deployed
# to a shared volume
touch $SIGNAL_FILE

# Sleep after deploying contracts to prevent stack from aborting on exit
sleep infinity
