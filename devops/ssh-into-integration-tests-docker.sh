#!/bin/bash

set -e

HOST=$(jq -e -r .host ./integration-test-settings.json)
PORT=$(jq -e .port ./integration-test-settings.json)
CLIENT_DIR=$(realpath -m .local/client)

ssh -o "UserKnownHostsFile=$CLIENT_DIR/known_hosts" -i "$CLIENT_DIR/id_ed25519" -p "$PORT" "ssh-test@$HOST"
