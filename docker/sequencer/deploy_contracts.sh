#!/bin/bash

DEVNET_PKEY=0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659
DEVNET_ACCOUNT_ADDRESS=0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E
DEVNET_RPC_URL=http://localhost:8547
DEPLOYMENTS_PATH=/deployments.json

# Spawn the sequencer in the background, using the same arguments expected by
# the container's entrypoint
nitro \
    --node.dangerous.no-l1-listener \
    --node.sequencer.dangerous.no-coordinator \
    --node.sequencer.enable \
    --node.staker.enable=false \
    --init.dev-init \
    --init.empty=false \
    --chain.id=412346 \
    --chain.dev-wallet.private-key=b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659 \
    --http.addr=0.0.0.0 \
    --http.vhosts=* \
    --http.corsdomain=* \
    > /dev/null 2>&1 &

# Spinwait until the devnet is ready for contracts to be deployed to it
while ! curl -sf http://localhost:8547 > /dev/null; do
    sleep 1
done

# Exit on error
set -e

# If $NO_VERIFY is set, write dummy addresses to the deployments file.
# Otherwise, deploy the verification keys.
if [[ -n $NO_VERIFY ]]; then
    # Write dummy addresses to the deployments file
    dummy_address="0x0000000000000000000000000000000000000001"
    jq -n --arg dummy_address "$dummy_address" \
    '{
        deployments: {
            verifier_contract: $dummy_address,
            vkeys_contract: $dummy_address
        }
    }' > $DEPLOYMENTS_PATH

    no_verify_flag="--no-verify"
else
    # Deploy verification keys
    # TODO: Ensure that the same SRS is used for the verification keys
    # and the integration tests
    cargo run \
        --package scripts -- \
        --priv-key $DEVNET_PKEY \
        --rpc-url $DEVNET_RPC_URL \
        --deployments-path $DEPLOYMENTS_PATH \
        deploy-stylus \
        --contract vkeys

    no_verify_flag=""
fi

# Deploy Merkle contract
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract merkle \
    $no_verify_flag

# If the $DEPLOY_DUMMY_ERC20 env var is set, deploy the dummy ERC20 contract
if [[ -n $DEPLOY_DUMMY_ERC20 ]]; then
    cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract dummy-erc20
fi

# Deploy darkpool contract, setting the "--no-verify" flag
# conditionally depending on whether the corresponding env var is set
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract darkpool-test-contract \
    $no_verify_flag

# If the $NO_VERIFY env var is unset, deploy the verifier.
# We do this after deploying the other contracts because it uses
# different compilation flags, and we want to preserve the cached
# dependencies for the other contracts.
if [[ -z $NO_VERIFY ]]; then
    # Deploy verifier contract
    cargo run \
        --package scripts -- \
        --priv-key $DEVNET_PKEY \
        --rpc-url $DEVNET_RPC_URL \
        --deployments-path $DEPLOYMENTS_PATH \
        deploy-stylus \
        --contract verifier
fi

# Deploy the proxy contract
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-proxy \
    --owner $DEVNET_ACCOUNT_ADDRESS \
    --fee 1
