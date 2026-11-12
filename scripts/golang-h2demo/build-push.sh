#!/bin/sh
# Build and push the multi-arch (amd64 + arm64) phpswoole/golang-h2demo image.
# Usage: sudo ./build-push.sh [--no-push]
set -e
cd "$(dirname "$0")"

IMAGE=phpswoole/golang-h2demo:latest
BUILDER=h2multi-push
PLUGIN_SRC="${BUILDX_PLUGIN:-$(eval echo ~${SUDO_USER:-$USER})/.docker/cli-plugins/docker-buildx}"

if ! docker buildx version >/dev/null 2>&1; then
    mkdir -p /usr/local/lib/docker/cli-plugins
    cp "$PLUGIN_SRC" /usr/local/lib/docker/cli-plugins/docker-buildx
    chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
fi

if [ "$1" != "--no-push" ] && ! grep -q 'index.docker.io\|"auths"' /root/.docker/config.json 2>/dev/null; then
    docker login
fi

docker buildx inspect "$BUILDER" >/dev/null 2>&1 || docker buildx create --name "$BUILDER" \
    --driver docker-container --driver-opt network=host \
    ${https_proxy:+--driver-opt env.http_proxy=$https_proxy --driver-opt env.https_proxy=$https_proxy} >/dev/null

if [ "$1" = "--no-push" ]; then
    docker buildx build --builder "$BUILDER" --platform linux/amd64,linux/arm64 -t "$IMAGE" \
        --output type=oci,dest=/tmp/h2demo.oci .
else
    docker buildx build --builder "$BUILDER" --platform linux/amd64,linux/arm64 -t "$IMAGE" --push .
    docker buildx imagetools inspect "$IMAGE" | grep -E 'Name:|Platform:'
fi
