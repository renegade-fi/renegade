#!/bin/sh
REGION=us-east-2
ENVIRONMENT=${1:-dev}
ECR_URL=377928551571.dkr.ecr.us-east-2.amazonaws.com/relayer-$ENVIRONMENT

GIT_HASH=$(git rev-parse HEAD)

TAG_1=$ECR_URL\:$GIT_HASH
TAG_2=$ECR_URL\:latest

docker build -t relayer:latest  -f ./docker/release/Dockerfile .
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_URL

docker tag relayer:latest $TAG_1
docker tag relayer:latest $TAG_2
docker push $TAG_1
docker push $TAG_2
