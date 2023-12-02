#!/bin/bash

# This traps SIGTERM (sent by docker-compose when aborting)
# to gracefully shuts down the devnet stack

graceful_shutdown() {
    docker-compose \
        --file ./docker-compose.yaml \
        down \
        --volumes \
        --remove-orphans
}

trap 'graceful_shutdown' SIGTERM

yes | ./test-node.bash --init &

wait $!

