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
    --chain.id=473474 \
    --chain.info-files=/devnet_chain_info.json \
    --chain.dev-wallet.private-key=b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659 \
    --http.addr=0.0.0.0 \
    --http.vhosts=* \
    --http.corsdomain=* \
    > /dev/null 2>&1 &

# Spinwait until the devnet is ready for contracts to be deployed to it
while ! curl -sf http://localhost:8547 > /dev/null; do
    echo "Waiting for sequencer to be ready..."
    sleep 1
done

# Exit on error
set -e

# Deploy the Permit2 contract.
# This must be deployed before the ERC20s so they can approve it
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-permit2

# Deploy the dummy ERC20 contracts
# The funding amount here is 1 million of a token with 18 decimal places

erc20s=(
    "USDC" "USD Coin" 6
    "USDT" "Tether USD" 6
    "WBTC" "Wrapped BTC" 8
    "WETH" "Wrapped Ether" 18
    "ARB" "Arbitrum" 18
    "GMX" "GMX" 18
    "PENDLE" "Pendle" 18
    "LDO" "Lido DAO Token" 18
    "LINK" "ChainLink Token" 18
    "CRV" "Curve DAO Token" 18
    "UNI" "Uniswap" 18
    "ZRO" "LayerZero" 18
    "LPT" "Livepeer Token" 18
    "GRT" "Graph Token" 18
    "COMP" "Compound" 18
    "AAVE" "Aave Token" 18
    "XAI" "Xai" 18
    "RDNT" "Radiant" 18
    "ETHFI" "Ether.fi" 18
)
num_tokens=${#erc20s[@]}
num_fields=3  # Number of fields in each tuple

for ((i=0; i<num_tokens; i+=num_fields)); do
    symbol="${erc20s[i]}"
    name="${erc20s[i+1]}"
    decimals="${erc20s[i+2]}"

    cargo run \
        --package scripts -- \
        --priv-key $DEVNET_PKEY \
        --rpc-url $DEVNET_RPC_URL \
        --deployments-path $DEPLOYMENTS_PATH \
        deploy-erc20 \
        --symbol "$symbol" \
        --name "$name" \
        --decimals "$decimals" \
        --account-skeys $DEVNET_PKEY \
        --funding-amount 1000000000000000000000000
done

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
    cargo run \
        --package scripts -- \
        --priv-key $DEVNET_PKEY \
        --rpc-url $DEVNET_RPC_URL \
        --deployments-path $DEPLOYMENTS_PATH \
        deploy-stylus \
        --contract vkeys

    no_verify_flag=""
fi

# Deploy Merkle contract, setting the "--no-verify" flag
# conditionally depending on whether the corresponding env var is set
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract merkle \
    $no_verify_flag

# Deploy transfer executor contract
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract transfer-executor \
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

# Deploy the darkpool core contract, setting the "--no-verify" flag
# conditionally depending on whether the corresponding env var is set
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract darkpool-core \
    $no_verify_flag

# Deploy darkpool test contract
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-stylus \
    --contract darkpool-test-contract \
    $no_verify_flag

# Deploy the proxy contract
# Use the FP representation of 2bps for the protocol fee
cargo run \
    --package scripts -- \
    --priv-key $DEVNET_PKEY \
    --rpc-url $DEVNET_RPC_URL \
    --deployments-path $DEPLOYMENTS_PATH \
    deploy-proxy \
    --owner $DEVNET_ACCOUNT_ADDRESS \
    --fee 1844674407370955
