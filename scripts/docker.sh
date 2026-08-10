#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="strix-sandbox"
TAG="${1:-dev}"
BUILD_ARGS=()
BASE_IMAGE_OVERRIDE="${STRIX_SANDBOX_BASE_IMAGE:-}"
LOCAL_KALI_CACHE_SOURCE="kalilinux/kali-rolling:latest"
LOCAL_KALI_CACHE_TAG="strix-kali-base:latest"

append_proxy_build_arg() {
  local target="$1"
  local value="${2:-}"
  if [ -n "$value" ]; then
    BUILD_ARGS+=(--build-arg "${target}=${value}")
  fi
}

if [ -z "$BASE_IMAGE_OVERRIDE" ] && docker image inspect "$LOCAL_KALI_CACHE_SOURCE" >/dev/null 2>&1; then
  echo "Using cached local Kali base image via $LOCAL_KALI_CACHE_TAG ..."
  docker tag "$LOCAL_KALI_CACHE_SOURCE" "$LOCAL_KALI_CACHE_TAG"
  BASE_IMAGE_OVERRIDE="$LOCAL_KALI_CACHE_TAG"
fi

if [ -z "$BASE_IMAGE_OVERRIDE" ]; then
  echo "Full build will resolve docker.io/kalilinux/kali-rolling:latest first."
  echo "If your network cannot reach docker.io metadata reliably, configure Docker Desktop proxy/registry access first,"
  echo "or pull ghcr.io/usestrix/strix-sandbox:1.3.0 and run ./scripts/docker-overlay.sh ${TAG} instead."
fi

if [ -n "$BASE_IMAGE_OVERRIDE" ]; then
  BUILD_ARGS+=(--build-arg "BASE_IMAGE=${BASE_IMAGE_OVERRIDE}")
fi

if [ -n "${STRIX_KALI_APT_MIRROR:-}" ]; then
  BUILD_ARGS+=(--build-arg "KALI_APT_MIRROR=${STRIX_KALI_APT_MIRROR}")
fi

if [ -n "${STRIX_GO_PROXY:-}" ]; then
  BUILD_ARGS+=(--build-arg "GO_MODULE_PROXY=${STRIX_GO_PROXY}")
fi

if [ -n "${STRIX_GO_SUMDB:-}" ]; then
  BUILD_ARGS+=(--build-arg "GO_SUMDB=${STRIX_GO_SUMDB}")
fi

if [ -n "${STRIX_NPM_REGISTRY:-}" ]; then
  BUILD_ARGS+=(--build-arg "NPM_REGISTRY=${STRIX_NPM_REGISTRY}")
fi

if [ -n "${STRIX_PIP_INDEX_URL:-}" ]; then
  BUILD_ARGS+=(--build-arg "PIP_INDEX_URL=${STRIX_PIP_INDEX_URL}")
fi

append_proxy_build_arg "HTTP_PROXY" "${STRIX_BUILD_HTTP_PROXY:-}"
append_proxy_build_arg "http_proxy" "${STRIX_BUILD_HTTP_PROXY:-}"
append_proxy_build_arg "HTTPS_PROXY" "${STRIX_BUILD_HTTPS_PROXY:-}"
append_proxy_build_arg "https_proxy" "${STRIX_BUILD_HTTPS_PROXY:-}"
append_proxy_build_arg "ALL_PROXY" "${STRIX_BUILD_ALL_PROXY:-}"
append_proxy_build_arg "all_proxy" "${STRIX_BUILD_ALL_PROXY:-}"
append_proxy_build_arg "NO_PROXY" "${STRIX_BUILD_NO_PROXY:-}"
append_proxy_build_arg "no_proxy" "${STRIX_BUILD_NO_PROXY:-}"

echo "Building $IMAGE:$TAG ..."
docker build \
  "${BUILD_ARGS[@]}" \
  -f "$PROJECT_ROOT/containers/Dockerfile" \
  -t "$IMAGE:$TAG" \
  "$PROJECT_ROOT"

echo "Done: $IMAGE:$TAG"
