#!/bin/sh
REGION=us-east-2
ENVIRONMENT=${1:-dev}
CLUSTER_IDX=${2:-0}
CLUSTER_NAME=$ENVIRONMENT-cluster$CLUSTER_IDX
SERVICE_NAME=$ENVIRONMENT-cluster$CLUSTER_IDX-service
TASK_FAMILY=$ENVIRONMENT-cluster0-task-def
ECR_URL=377928551571.dkr.ecr.us-east-2.amazonaws.com/relayer-$ENVIRONMENT

# Fetch the latest image URI from ECR
IMAGE_URI=$(aws ecr describe-images --repository-name relayer-dev --region us-east-2 --image-ids imageTag=latest | jq -r '.imageDetails[0].imageTags[0]')
FULL_IMAGE_URI="$ECR_URL:$IMAGE_URI"
echo "Using image URI: $FULL_IMAGE_URI"

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
