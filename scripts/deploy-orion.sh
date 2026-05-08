#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo "Refusing to deploy Argus as root. Run this as xen." >&2
  exit 1
fi

current_user="$(id -un)"
if [[ "$current_user" != "xen" ]]; then
  echo "Refusing to deploy Argus as ${current_user}. Run this as xen." >&2
  exit 1
fi

repo_dir="${1:-/home/xen/apps/Argus}"

cd "$repo_dir"

if [[ ! -d .git ]]; then
  echo "Expected a git checkout at ${repo_dir}." >&2
  exit 1
fi

if [[ -n "$(git status --short)" ]]; then
  echo "Refusing to deploy from a dirty working tree." >&2
  git status --short >&2
  exit 1
fi

current_branch="$(git branch --show-current)"
if [[ "$current_branch" != "master" ]]; then
  echo "Expected the master branch, found ${current_branch:-detached}." >&2
  exit 1
fi

git pull --ff-only origin master
corepack pnpm install --frozen-lockfile
pm2 startOrReload ecosystem.config.js --update-env
health_port="$(
  node - <<'NODE'
const config = require('./ecosystem.config.js');
const port = config.apps?.[0]?.env?.PORT;
process.stdout.write(String(port || 3001));
NODE
)"

for attempt in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:${health_port}/healthz" >/dev/null; then
    echo "Health check passed on attempt ${attempt}."
    break
  fi

  if [[ "$attempt" -eq 15 ]]; then
    echo "Health check failed after 15 attempts on port ${health_port}." >&2
    exit 1
  fi

  sleep 2
done

echo "Argus deploy completed on $(hostname -s) as ${current_user}."
