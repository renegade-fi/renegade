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
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract verifier

# Deploy Merkle contract
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract merkle

# Deploy darkpool contract, setting the "--no-verify" flag
# conditionally depending on whether the corresponding env var is set
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract darkpool-test-contract \
    $(no_verify)

# Deploy the proxy contract
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-proxy \
    --owner $DEVNET_ACCOUNT_ADDRESS \
    --test

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
