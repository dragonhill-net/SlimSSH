#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

DOCKER_CONTAINER_NAME=$("$SCRIPT_DIR/load-config-value.sh" containerName)
HOST=$("$SCRIPT_DIR/load-config-value.sh" host)
PORT=$("$SCRIPT_DIR/load-config-value.sh" port)
IMAGE=$("$SCRIPT_DIR/load-config-value.sh" image)

SERVER_KEY_DIR=$(realpath -m .local/server-keys)
CLIENT_DIR=$(realpath -m .local/client)

mkdir -p "$SERVER_KEY_DIR"
mkdir -p "$CLIENT_DIR"

# Create the server keys
if [ ! -f "$SERVER_KEY_DIR/ssh_host_ed25519_key" ]; then
    ssh-keygen -q -N "" -t ed25519 -f "$SERVER_KEY_DIR/ssh_host_ed25519_key"
fi
if [ ! -f "$SERVER_KEY_DIR/ssh_host_rsa_key" ]; then
    ssh-keygen -q -N "" -t rsa -b 4096 -f "$SERVER_KEY_DIR/ssh_host_rsa_key"
fi

# Create the client keys
if [ ! -f "$CLIENT_DIR/id_ed25519" ]; then
    ssh-keygen -q -N "" -t ed25519 -f "$CLIENT_DIR/id_ed25519"
fi
if [ ! -f "$CLIENT_DIR/id_rsa" ]; then
    ssh-keygen -q -N "" -t rsa -b 4096 -f "$CLIENT_DIR/id_rsa"
fi

# Create the client authorized_keys file
cat "$CLIENT_DIR/id_ed25519.pub" "$CLIENT_DIR/id_rsa.pub" > "$CLIENT_DIR/authorized_keys"
printf "\n" >> "$CLIENT_DIR/authorized_keys"

# Create the client known_hosts file
SED_REGEX_EXTRACT_KEY="s/^(ssh-[^ ]+ [^ ]+).*$/$HOST \1/g"
sed -E "$SED_REGEX_EXTRACT_KEY" "$SERVER_KEY_DIR/ssh_host_ed25519_key.pub" > "$CLIENT_DIR/known_hosts"
sed -E "$SED_REGEX_EXTRACT_KEY" "$SERVER_KEY_DIR/ssh_host_rsa_key.pub" >> "$CLIENT_DIR/known_hosts"
printf "\n" >> "$CLIENT_DIR/known_hosts"

# In case it exists recreate it
docker stop "$DOCKER_CONTAINER_NAME" 2>/dev/null || true
docker rm "$DOCKER_CONTAINER_NAME" 2>/dev/null || true

# For debug logs append: /usr/sbin/sshd -ddd -e
docker run -d -v "$SERVER_KEY_DIR:/etc/ssh/keys:ro" -v "$CLIENT_DIR/authorized_keys:/home/ssh-test/.ssh/authorized_keys:ro" -p "$HOST:$PORT:22" --name "$DOCKER_CONTAINER_NAME" "$IMAGE"
