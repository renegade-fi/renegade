#!/bin/sh
REGION=us-east-2
ENVIRONMENT=${1:-dev}
ECR_URL=377928551571.dkr.ecr.us-east-2.amazonaws.com/relayer-$ENVIRONMENT

GIT_HASH=$(git rev-parse HEAD)
docker build -t relayer:latest  -f ./docker/release/Dockerfile .
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_URL

docker tag relayer:latest $ECR_URL:$GIT_HASH
docker tag relayer:latest $ECR_URL:latest
docker push $ECR_URL:$GIT_HASH
docker push $ECR_URL:latest
