#!/bin/bash

# Exit on error
set -e

# Check that the token bridge contracts have been deployed, this is the last step of the devnet initialization
# Here, we check the multicall contract, which is expected to be deployed to address 0xDB2D15a3EB70C347E0D2C2c7861cAFb946baAb48,
# but we could check any of the token bridge contracts
response=$(curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["'$TOKEN_BRIDGE_ADDRESS'", "latest"],"id":1}' $DEVNET_RPC_URL)
result=$(echo $response | jq -r '.result')
echo $result

# If the code is not empty, exit with a success code
if [ "$result" != "0x" ] && [ -n "$result" ]; then
  exit 0
else
  exit 1
fi
