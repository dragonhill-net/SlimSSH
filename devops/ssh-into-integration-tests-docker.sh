#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

HOST=$("$SCRIPT_DIR/load-config-value.sh" host)
PORT=$("$SCRIPT_DIR/load-config-value.sh" port)
CLIENT_DIR=$(realpath -m .local/client)

ssh -o "UserKnownHostsFile=$CLIENT_DIR/known_hosts" -i "$CLIENT_DIR/id_ed25519" -p "$PORT" "ssh-test@$HOST"
