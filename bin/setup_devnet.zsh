#!/bin/zsh

# Spins up a devnet and optionally deploys the contracts to it. Always redeploys the proxy.

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

# If the devnet isn't running, spin it up.
# Assumes this is being run from the root of the repo, and that the
# devnet submodule has been initialized
if [[ $IS_RUNNING == false ]]; then
    cd ./nitro-testnode
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

cd $current_dir
