#!/bin/sh
REGION=us-east-2
DEFAULT_ENVIRONMENT=dev

# Get the current git commit hash (long form)
DEFAULT_IMAGE_TAG=$(git rev-parse HEAD)

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --image-tag) IMAGE_TAG="$2"; shift ;;
        --env) ENVIRONMENT="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Use defaults if not provided
ENVIRONMENT=${ENVIRONMENT:-$DEFAULT_ENVIRONMENT}
IMAGE_TAG=${IMAGE_TAG:-$DEFAULT_IMAGE_TAG}

CLUSTER_NAME=$ENVIRONMENT-cluster$CLUSTER_IDX
SERVICE_NAME=$ENVIRONMENT-cluster$CLUSTER_IDX-service
TASK_FAMILY=$ENVIRONMENT-cluster0-task-def
ECR_URL=377928551571.dkr.ecr.us-east-2.amazonaws.com/relayer-$ENVIRONMENT

FULL_IMAGE_URI="$ECR_URL:$IMAGE_TAG"
echo "Using image URI: $FULL_IMAGE_URI"
echo "Deploying relayer to: $ENVIRONMENT"

# Fetch the existing definition of the task and create a new revision with the updated URI
TASK_DEFINITION=$(aws ecs describe-task-definition --task-definition $TASK_FAMILY --region $REGION --query 'taskDefinition')
NEW_TASK_DEF=$(echo $TASK_DEFINITION | \
  jq --arg IMAGE_URI "$FULL_IMAGE_URI" '.containerDefinitions[0].image = $IMAGE_URI' | \
  jq 'del(.taskDefinitionArn)' | \
  jq 'del(.revision)' | \
  jq 'del(.status)' | \
  jq 'del(.requiresAttributes)' | \
  jq 'del(.compatibilities)' | \
  jq 'del(.registeredAt)' | \
  jq 'del(.registeredBy)' | \
  jq -c)

# Register the new task definition
NEW_TASK_INFO=$(aws ecs register-task-definition --cli-input-json "$NEW_TASK_DEF" --region $REGION)
NEW_REVISION=$(echo $NEW_TASK_INFO | jq -r '.taskDefinition.revision')
echo "Created new task revision: $NEW_REVISION"

# Update the ECS cluster to the new revision
aws ecs update-service --cluster $CLUSTER_NAME --service $SERVICE_NAME --task-definition $TASK_FAMILY:$NEW_REVISION --region $REGION >/dev/null 2>&1
echo "ECS cluster updated to new revision"
