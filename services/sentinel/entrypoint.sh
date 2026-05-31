#!/bin/sh
set -e

SENTINEL_HOME="${SENTINEL_HOME:-/data}"
MANIFEST="$SENTINEL_HOME/store/sentinel.json"

# Auto-initialize wallet on first run
if [ ! -f "$MANIFEST" ]; then
    echo "No wallet found — initialising sentinel identity..."

    if [ -z "$SENTINEL_PASSPHRASE" ]; then
        echo "ERROR: SENTINEL_PASSPHRASE must be set to initialize the wallet" >&2
        exit 1
    fi

    sentinelctl init \
        --service-id="${SERVICE_ID:-sentinel}" \
        --role="${SENTINEL_ROLE:-producer}" \
        --env="${SENTINEL_ENV:-dev}" \
        --output="$SENTINEL_HOME/store"

    echo "Wallet initialized successfully."
fi

# Load DID from manifest and export it so pydantic-settings picks it up
if [ -z "$SENTINEL_DID" ]; then
    SENTINEL_DID=$(python3 -c "import json; m=json.load(open('$MANIFEST')); print(m['did'])")
    export SENTINEL_DID
    echo "Loaded DID: $SENTINEL_DID"
fi

if [ -n "$ENROLLMENT_TOKEN" ]; then
    echo "ENROLLMENT_TOKEN present — onboarding will run at startup."
fi

echo "Starting Sentinel ($SENTINEL_ROLE)..."
exec python -m sentinel.main
