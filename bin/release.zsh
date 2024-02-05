set -e

# Check if the first argument is either "staging" or "production"
if [[ $1 != "staging" && $1 != "production" ]]; then
    echo "Error: First argument must be either 'staging' or 'production'."
    exit 1
fi

# Set variables
aws_account_id="377928551571"
aws_region="ca-central-1"
ecr_repository_name="renegade-$1"
image_name="renegade-relayer"
image_tag="latest"

# Log in to Amazon ECR
aws ecr get-login-password --region $aws_region | \
    docker login \
        --username AWS \
        --password-stdin \
        $aws_account_id.dkr.ecr.$aws_region.amazonaws.com

# Build the Docker image using buildkit for better caching
export DOCKER_BUILDKIT=1
docker build \
    -t $image_name:$image_tag \
    -f ./docker/release/Dockerfile \
    .

# Tag the Docker image for ECR
docker tag $image_name:$image_tag $aws_account_id.dkr.ecr.$aws_region.amazonaws.com/$ecr_repository_name:$image_tag

# Push the Docker image to ECR
docker push $aws_account_id.dkr.ecr.$aws_region.amazonaws.com/$ecr_repository_name:$image_tag

echo "Successfully released $1 build"
