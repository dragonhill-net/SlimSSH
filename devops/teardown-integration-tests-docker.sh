#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

DOCKER_CONTAINER_NAME=$("$SCRIPT_DIR/load-config-value.sh" containerName)

docker stop "$DOCKER_CONTAINER_NAME" || true
docker rm "$DOCKER_CONTAINER_NAME" || true
