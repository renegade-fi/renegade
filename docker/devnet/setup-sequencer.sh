#!/bin/bash

# Exit on error
set -e

cd renegade-contracts/starknet_scripts
export RUST_BACKTRACE=1

# Run a sequencer with state dump enabled
katana \
    --seed 0 \
    --dump-state /katana-state.out \
    --disable-fee \
    --chain-id KATANA &
katana_pid=$!
sleep 5

# Deploy and initialize the contracts, uses the first predeployed account and private key of the
# sequencer when run with `--seed 0`
cargo run -- \
    deploy \
    --initialize \
    --dump-deployments \
    --artifacts-path /artifacts \
    -c darkpool \
    -c usdc \
    --network localhost \
    --address 0x3ee9e18edc71a6df30ac3aca2e0b02a198fbce19b7480a63a0d71cbd76652e0 \
    --private-key 0x300001800000000300000180000000000030000000000003006001800006600

# Kill the sequencer with SIGINT to force a state dump
kill -INT $katana_pid
sleep 3