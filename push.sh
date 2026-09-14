#!/bin/bash
# Bumps VERSION (the "stableN" suffix), builds, and pushes to Docker Hub with the new
# version baked into service_manifest.yml -- so every push gets a distinct tag instead
# of silently overwriting the last one.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="kylemc54321/assemblyline-service-bashsim"

current="$(cat VERSION)"
prefix="${current%stable*}"
num="${current##*stable}"
next_num=$((num + 1))
next="${prefix}stable${next_num}"

echo "Bumping version: $current -> $next"

docker build --build-arg version="$next" -t "$IMAGE:$next" .
docker push "$IMAGE:$next"

echo "$next" > VERSION
echo "Pushed $IMAGE:$next -- VERSION file updated."
