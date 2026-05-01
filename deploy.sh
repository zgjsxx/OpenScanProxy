#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Building frontend"
cd "$ROOT_DIR/web"
npm run build

echo ""
echo "==> Building and deploying with Docker Compose"
cd "$ROOT_DIR/docker"
docker compose up -d --build

echo ""
echo "==> Deploy complete"
echo "    Admin UI:  http://localhost:29090"
echo "    Proxy:     http://localhost:28080"
