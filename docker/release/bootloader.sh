#!/bin/bash

# Expects the following environment variables to be passed to the container:
# CONFIG_BUCKET: The S3 bucket containing the configs
# SNAPSHOT_BUCKET: The S3 bucket to save state snapshots to
# CONFIG_FILE: The name of the config file
# HTTP_PORT: The port to use for HTTP traffic
# WEBSOCKET_PORT: The port to use for WebSocket traffic
# P2P_PORT: The port to use for gossip traffic
# PUBLIC_IP: The public IP address of the node (optional)
set -e

config_path="/config.toml"

# Fetch the config from S3
aws s3 cp s3://$CONFIG_BUCKET/$CONFIG_FILE $config_path

# Write the used ports to the config file
echo "http-port = $HTTP_PORT" >> $config_path
echo "websocket-port = $WEBSOCKET_PORT" >> $config_path
echo "p2p-port = $P2P_PORT" >> $config_path

# If the PUBLIC_IP env var is set (e.g. for bootstrap nodes), write it to the config file
if [ -n "$PUBLIC_IP" ]; then
  echo "public-ip = \"$PUBLIC_IP:$P2P_PORT\"" >> $config_path
fi

# Run the snapshot sidecar
/bin/snapshot-sidecar --config-path $config_path --bucket $SNAPSHOT_BUCKET &

# Run the relayer
/bin/renegade-relayer --config-file $config_path
