#!/usr/bin/env bash
# Build and push the DAVIX container image using podman.
#
# Usage:
#   ./build-and-push.sh [REGISTRY/]IMAGE[:TAG]
#
# Examples:
#   ./build-and-push.sh ghcr.io/ericvaandering/davix:latest
#   ./build-and-push.sh quay.io/myorg/davix:1.0
#
# If no argument is supplied the image is built but NOT pushed.

set -euo pipefail

IMAGE="${1:-davix:latest}"

echo "==> Building image: ${IMAGE}"
podman build --tag "${IMAGE}" "$(dirname "$0")"

if [[ "$#" -lt 1 ]]; then
    echo "==> No registry target supplied; skipping push."
    echo "    To push, run: $0 <REGISTRY/IMAGE:TAG>"
    exit 0
fi

echo "==> Pushing image: ${IMAGE}"
podman push "${IMAGE}"

echo "==> Done."
