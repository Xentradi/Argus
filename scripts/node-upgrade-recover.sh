#!/usr/bin/env bash
set -euo pipefail

echo "[argus] reinstalling dependencies for current Node runtime..."
corepack pnpm install --frozen-lockfile

echo "[argus] rebuilding native addons..."
corepack pnpm run rebuild-native

echo "[argus] reloading PM2 process..."
pm2 startOrReload ecosystem.config.js

echo "[argus] checking local health..."
curl -fsS http://127.0.0.1:3000/healthz >/dev/null

echo "[argus] done"
