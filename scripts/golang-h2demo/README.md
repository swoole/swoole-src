# golang-h2demo

Source of the `phpswoole/golang-h2demo` test image (HTTP/2 server push demo on port 4430).

Build and push a multi-arch image:

    docker buildx build --platform linux/amd64,linux/arm64 -t phpswoole/golang-h2demo --push .
