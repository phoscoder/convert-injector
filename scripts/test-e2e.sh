#!/usr/bin/env bash
# Runs the whole test suite, including the end-to-end tests, against a throwaway Postgres in Docker.
#   scripts/test-e2e.sh            # Postgres 16
#   PG_VERSION=12 scripts/test-e2e.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PG_VERSION="${PG_VERSION:-16}"
NAME="secrets-inject-e2e-$$"

docker run -d --rm --name "$NAME" \
  -e POSTGRES_PASSWORD=postgres -p 127.0.0.1::5432 \
  "postgres:${PG_VERSION}-alpine" >/dev/null
trap 'docker stop "$NAME" >/dev/null 2>&1 || true' EXIT

PORT="$(docker port "$NAME" 5432/tcp | head -n1 | sed 's/.*://')"
until docker exec "$NAME" pg_isready -U postgres -q 2>/dev/null; do sleep 0.5; done
# The image restarts once during init; wait until it stays up.
sleep 2
until docker exec "$NAME" pg_isready -U postgres -q 2>/dev/null; do sleep 0.5; done

export SECRETS_TEST_ADMIN_URL="postgres://postgres:postgres@127.0.0.1:${PORT}/postgres"
cargo test "$@"
