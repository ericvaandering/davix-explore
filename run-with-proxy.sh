#!/usr/bin/env bash
# Run the DAVIX container, mounting the host's X.509 user proxy into it.
#
# Usage:
#   ./run-with-proxy.sh [IMAGE]
#
# The X.509 proxy is expected at the standard voms-proxy-init location:
#   /tmp/x509up_u<UID>
# and is mounted read-only inside the container at the same path so that
# davix tools can pick it up via the X509_USER_PROXY environment variable.
#
# Examples:
#   ./run-with-proxy.sh
#   ./run-with-proxy.sh ghcr.io/ericvaandering/davix:latest

set -euo pipefail

# Verify podman is available
if ! command -v podman &>/dev/null; then
    echo "ERROR: 'podman' is not installed or not in PATH." >&2
    exit 1
fi

IMAGE="${1:-davix:latest}"
PROXY_PATH="/tmp/x509up_u$(id -u)"

if [[ ! -f "${PROXY_PATH}" ]]; then
    echo "ERROR: X.509 proxy not found at ${PROXY_PATH}." >&2
    echo "       Run 'voms-proxy-init' (or 'grid-proxy-init') first." >&2
    exit 1
fi

echo "==> Using proxy: ${PROXY_PATH}"
echo "==> Starting container from image: ${IMAGE}"

podman run --rm -it \
    --volume "${PROXY_PATH}:${PROXY_PATH}:ro" \
    --env "X509_USER_PROXY=${PROXY_PATH}" \
    "${IMAGE}"
