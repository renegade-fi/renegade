#!/bin/bash

cargo build

# Spawn 5-node cluster, starting w/ leader
DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer0-config.toml > peer0.log &
peer0_pid=$!

sleep 15

DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer1-config.toml > peer1.log &
peer1_pid=$!

DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer2-config.toml > peer2.log &
peer2_pid=$!

DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer3-config.toml > peer3.log &
peer3_pid=$!

DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer4-config.toml > peer4.log &
peer4_pid=$!

# Give time for the cluster to stabilize
sleep 90

# Kill 2 nodes, add 2 nodes

kill $peer3_pid
kill $peer4_pid

sleep 5

DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer5-config.toml > peer5.log &
peer5_pid=$!

DD_ENV="local" DD_SERVICE="local-cluster" nohup target/debug/renegade-relayer --config-file /Users/akirillo/code/local-relayer-configs/peer6-config.toml > peer6.log &
peer6_pid=$!

# Give time for chaos to ensue
sleep 150

# Clean up the test

kill $peer0_pid
kill $peer1_pid
kill $peer2_pid
kill $peer5_pid
kill $peer6_pid

rm -rf peer*
