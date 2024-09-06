#!/bin/sh
REGION=us-east-2
DEFAULT_ENVIRONMENT=dev

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --env) ENVIRONMENT="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Use default if not provided
ENVIRONMENT=${ENVIRONMENT:-$DEFAULT_ENVIRONMENT}
ECR_URL=377928551571.dkr.ecr.us-east-2.amazonaws.com/relayer-$ENVIRONMENT

GIT_HASH=$(git rev-parse HEAD)

TAG_1=$ECR_URL\:$GIT_HASH
TAG_2=$ECR_URL\:latest

echo "Building and pushing relayer image to: $ENVIRONMENT"

docker build -t relayer:latest  -f ./docker/release/Dockerfile .
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_URL

docker tag relayer:latest $TAG_1
docker tag relayer:latest $TAG_2
docker push $TAG_1
docker push $TAG_2
