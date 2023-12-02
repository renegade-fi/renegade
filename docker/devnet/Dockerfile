# This Dockerfile pulls in the Arbitrum Nitro devnet repo,
# and runs the devnet. This is a docker-compose stack of its own
# which will run in this container, but the stack is complex enough
# to warrant this approach.
# As such, we use the official docker image as the base.
FROM docker AS devnet

# Install dependencies
RUN apk add git bash curl jq

# Clone the Nitro devnet repo
WORKDIR devnet
RUN git clone \
    -b custom-network \
    --recurse-submodules \
    https://github.com/renegade-fi/nitro-testnode.git

WORKDIR nitro-testnode

# Copy in the healthcheck & run scripts
COPY ./healthcheck.sh /healthcheck.sh
COPY ./run_with_graceful_shutdown.sh /run_with_graceful_shutdown.sh

# Run the devnet
ENTRYPOINT /run_with_graceful_shutdown.sh
