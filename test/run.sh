#!/usr/bin/env bash
# Runs the gateway tests against a throwaway server with no credentials, so the
# suite exercises the unconfigured path and never touches a real wallet.
#
# Passkey settings are real values: the ceremony checks are part of what is
# being tested, and only the authenticator tap itself is stood in for.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT=${PORT:-8799}
rm -rf .storage-test
mkdir -p .storage-test
LOG=.storage-test/server.log

PINESIGN_SKIP_ENV_FILE=1 \
PINESIGN_STORAGE_DIR=.storage-test \
PORT="$PORT" \
PASSKEY_RP_ID=id.test.local \
PINESIGN_PARENT=test.eth \
SIGNIN_DOMAIN=id.test.local \
RATE_AUTH_PER_MIN=1000 \
RATE_SEND_PER_MIN=1000 \
RATE_CODE_PER_MIN=1000 \
SIGNIN_ORIGINS=https://v1.id.test.local \
node gateway/server.js > "$LOG" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  curl -s "http://localhost:$PORT/api/health" > /dev/null 2>&1 && break
  perl -e 'select(undef,undef,undef,0.25)'
done

node test/webauthn.js
node test/keysplit.js

BASE="http://localhost:$PORT" SERVER_LOG="$LOG" SIGNIN_ORIGIN=https://v1.id.test.local \
PINESIGN_STORAGE_DIR=.storage-test SIGNIN_DOMAIN=id.test.local PASSKEY_RP_ID=id.test.local node test/flow.js
