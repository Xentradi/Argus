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
pm2 startOrReload ecosystem.config.js --update-env
health_port="$(
  node - <<'NODE'
const config = require('./ecosystem.config.js');
const port = config.apps?.[0]?.env?.PORT;
process.stdout.write(String(port || 3001));
NODE
)"
curl -fsS "http://127.0.0.1:${health_port}/healthz" >/dev/null

echo "Argus deploy completed on $(hostname -s) as ${current_user}."
