#!/bin/zsh

# Spins up a devnet and optionally deploys the contracts to it. Always redeploys the proxy.
# The following environment variables are expected to be set:
# - DEVNET_PATH: Path to the test-node.bash script in the nitro-testnode repo
# - DEVNET_PKEY: The private key of a prefunded devnet account
# - DEVNET_ACCOUNT_ADDRESS: The associated address of the prefunded devnet account
# - DEVNET_RPC_URL: The RPC URL of the devnet
# - INIT_CHECK_ADDRESS: The address to check for initialization.
#   Should be that of the multicall contract, which is the last contract deployed by the devnet intialization script.
# - DEPLOYMENTS_PATH: The path to the deployments file
# - CONTRACTS_PATH: The path to the contracts repo
# - DEPLOY_CONTRACTS: Whether or not to deploy the Stylus contracts (optional)
# - UPLOAD_VKEYS: Whether or not to upload the verification keys (optional)
# - NO_VERIFY: Whether or not verification should be enabled in the darkpool contract (optional)

current_dir=$PWD

# First, check if the devnet is already running.
set +e # Disable exit on error (pgrep can expectedly fail)
devnet_pid=$(pgrep -f test-node.bash)
set -e # Re-enable exit on error
if [[ -n $devnet_pid ]]; then
    IS_RUNNING=true
else
    IS_RUNNING=false
fi

# If the devnet isn't running, spin it up
if [[ $IS_RUNNING == false ]]; then
    cd $DEVNET_PATH
    ./test-node.bash &> /dev/null &
    devnet_pid=$!
fi

# Get the process group ID of the devnet
# (so that we can later gracefully shut it down)
devnet_pgid=$(ps -o pgid= $devnet_pid)

# Gracefully shut down the devnet on EXIT or SIGTERM
# (SIGINT already propagates to the devnet)
graceful_shutdown() {
    cd $current_dir
    kill -SIGINT -$devnet_pgid
    while kill -0 -$devnet_pgid 2>/dev/null; do
        sleep 1
    done
}

trap 'graceful_shutdown' EXIT SIGTERM

# Spinwait until the devnet is ready for contracts to be deployed to it
while true; do
    set +e # Disable exit on error (curl can expectedly fail)
    # Check that the token bridge contracts have been deployed, this is the last step of the devnet initialization.
    response=$(curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["'$INIT_CHECK_ADDRESS'", "latest"],"id":1}' $DEVNET_RPC_URL 2> /dev/null)
    result=$(echo $response | jq -r '.result')
    set -e # Re-enable exit on error

    # If the code is not empty, break out of the spinwait
    if [ "$result" != "0x" ] && [ -n "$result" ]; then
        break
    else
        sleep 1
    fi
done

cd $CONTRACTS_PATH
DEPLOYMENTS_PATH=$DEPLOYMENTS_DIR/$DEPLOYMENTS_FILE

# If the $DEPLOY_CONTRACTS env var is set, deploy the Stylus contracts
if [[ -n $DEPLOY_CONTRACTS ]]; then
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
fi

# Deploy the proxy contract
# (we always do this so that we can have fresh state for the test)
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

cd $current_dir
