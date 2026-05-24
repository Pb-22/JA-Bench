#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data/db /data/uploads /data/output /data/cache /data/config

if [ -f /data/config/keys.env ]; then
  set -a
  . /data/config/keys.env
  set +a
fi

if [ -n "${SHODAN_API_KEY:-}" ]; then
  if ! shodan init "$SHODAN_API_KEY" >/dev/null 2>&1; then
    echo "Warning: shodan init failed, continuing without CLI initialization" >&2
  fi
fi

python -m app.init_db

exec "$@"
