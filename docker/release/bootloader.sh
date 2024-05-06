#!/bin/bash

# Expects the following environment variables to be passed to the container:
# CONFIG_BUCKET: The S3 bucket containing the cluster config
# CLUSTER_CONFIG_FILE: The name of the cluster config file
# HTTP_PORT: The port to use for HTTP traffic
# WEBSOCKET_PORT: The port to use for WebSocket traffic
# P2P_PORT: The port to use for gossip traffic


config_path="/config.toml"

# Fetch the cluster config from S3
aws s3 cp s3://$CONFIG_BUCKET/$CLUSTER_CONFIG_FILE $config_path

# Write the used ports to the config file
echo "http-port = $HTTP_PORT" >> $config_path
echo "websocket-port = $WEBSOCKET_PORT" >> $config_path
echo "p2p-port = $P2P_PORT" >> $config_path

# Run the relayer
/bin/renegade-relayer --config-file $config_path
