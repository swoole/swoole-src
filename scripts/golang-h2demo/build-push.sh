#!/bin/sh
# Build and push the multi-arch (amd64 + arm64) phpswoole/golang-h2demo image.
# Usage: sudo [https_proxy=<proxy url>] ./build-push.sh [--no-push]
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

# Optional proxy; sudo drops the environment, so set it after sudo: sudo https_proxy=<proxy url> ./build-push.sh
PROXY="${https_proxy:-$HTTPS_PROXY}"
PROXY_OPTS=""
if [ -n "$PROXY" ]; then
    PROXY_OPTS="--build-arg http_proxy=$PROXY --build-arg https_proxy=$PROXY --network host --allow network.host"
fi

docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
docker buildx create --name "$BUILDER" --driver docker-container --driver-opt network=host \
    ${PROXY:+--driver-opt env.http_proxy=$PROXY --driver-opt env.https_proxy=$PROXY} \
    --buildkitd-flags '--allow-insecure-entitlement network.host' >/dev/null

if [ "$1" = "--no-push" ]; then
    docker buildx build --builder "$BUILDER" $PROXY_OPTS --platform linux/amd64,linux/arm64 -t "$IMAGE" \
        --output type=oci,dest=/tmp/h2demo.oci .
else
    docker buildx build --builder "$BUILDER" $PROXY_OPTS --platform linux/amd64,linux/arm64 -t "$IMAGE" --push .
    docker buildx imagetools inspect "$IMAGE" | grep -E 'Name:|Platform:'
fi
