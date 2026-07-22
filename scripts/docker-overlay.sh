#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="strix-sandbox"
TAG="${1:-dev}"
BASE_IMAGE="${STRIX_SANDBOX_BASE_IMAGE:-ghcr.io/usestrix/strix-sandbox:1.0.0}"

echo "Building overlay $IMAGE:$TAG from $BASE_IMAGE ..."
docker build \
  -f "$PROJECT_ROOT/containers/Dockerfile.overlay" \
  --build-arg "BASE_IMAGE=$BASE_IMAGE" \
  -t "$IMAGE:$TAG" \
  "$PROJECT_ROOT"

echo "Done: $IMAGE:$TAG"
