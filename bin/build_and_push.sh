#!/bin/sh
REGION=us-east-2
DEFAULT_CHAIN=arbitrum-sepolia

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --chain) CHAIN="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# If chain contains "arbitrum", define the "arbitrum" cargo feature
if [[ "$CHAIN" == *"arbitrum"* ]]; then
    CARGO_FEATURES="default,arbitrum"
elif [[ "$CHAIN" == *"base"* ]]; then
    CARGO_FEATURES="default,base"
else
    CARGO_FEATURES="default"
fi

# Use default if not provided
CHAIN=${CHAIN:-$DEFAULT_CHAIN}
ECR_URL=377928551571.dkr.ecr.us-east-2.amazonaws.com/relayer-$CHAIN

GIT_HASH=$(git rev-parse HEAD)

TAG_1=$ECR_URL\:$GIT_HASH
TAG_2=$ECR_URL\:latest

echo "Building and pushing relayer image to: $CHAIN"

docker build -t relayer:latest  -f ./docker/release/Dockerfile . --build-arg CARGO_FEATURES=$CARGO_FEATURES
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_URL

docker tag relayer:latest $TAG_1
docker tag relayer:latest $TAG_2
docker push $TAG_1
docker push $TAG_2
