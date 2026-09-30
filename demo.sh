#!/usr/bin/env bash
# One-command demo: builds and starts chain + agent + verifier. Ctrl-C stops everything.
set -euo pipefail
cd "$(dirname "$0")"

docker info > /dev/null 2>&1 || {
  echo "Docker isn't running. Start it (e.g. 'colima start' or Docker Desktop) and retry."; exit 1; }

trap 'docker compose down --remove-orphans > /dev/null 2>&1; echo "Demo stopped."' EXIT
echo "Dashboard: http://localhost:8502   (first build takes a few minutes)"
docker compose up --build
