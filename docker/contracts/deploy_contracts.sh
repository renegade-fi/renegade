#!/bin/bash

# Deploys the contracts to the devnet, assumed to be running with an RPC endpoint at $DEVNET_RPC_URL.

# Spinwait until the devnet is ready for contracts to be deployed to it
while true; do
    # Check that the token bridge contracts have been deployed, this is the last step of the devnet initialization.
    response=$(curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["'$INIT_CHECK_ADDRESS'", "latest"],"id":1}' $DEVNET_RPC_URL 2> /dev/null)
    result=$(echo $response | jq -r '.result')

    # If the code is not empty, break out of the spinwait
    if [ "$result" != "0x" ] && [ -n "$result" ]; then
        break
    else
        sleep 1
    fi
done

# Exit on error
set -e

# If $NO_VERIFY is set, write dummy addresses to the deployments file.
# Otherwise, deploy the verification keys.
if [[ -n $NO_VERIFY ]]; then
    # Write dummy addresses to the deployments file
    dummy_address="0x0000000000000000000000000000000000000000"
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
    --owner $DEVNET_ACCOUNT_ADDRESS

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

# Sleep forever to prevent the Docker Compose stack from aborting due to container exit
sleep infinity
