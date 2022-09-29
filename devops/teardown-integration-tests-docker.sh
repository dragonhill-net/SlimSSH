#!/bin/bash

set -e

DOCKER_CONTAINER_NAME="slimssh-local-integration-test"

sudo docker stop "$DOCKER_CONTAINER_NAME" || true
sudo docker rm "$DOCKER_CONTAINER_NAME" || true
