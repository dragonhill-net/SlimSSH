#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

SETTINGS_FILE="$SCRIPT_DIR/integration-test-settings.json"
SETTINGS_OVERRIDE_FILE="$SCRIPT_DIR/integration-test-settings.local.json"

if test -f "$SETTINGS_OVERRIDE_FILE"; then
    jq -e -r -s ".[0] * .[1] | .${1}" "$SETTINGS_FILE" "$SETTINGS_OVERRIDE_FILE"
else
    jq -e -r ".${1}" "$SCRIPT_DIR/integration-test-settings.json"
fi
