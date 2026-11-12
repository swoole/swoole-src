# golang-h2demo

Source of the `phpswoole/golang-h2demo` test image (HTTP/2 server push demo on port 4430).

Build and push a multi-arch image:

    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o h2demo-amd64 .
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o h2demo-arm64 .
    docker buildx build --platform linux/amd64,linux/arm64 -t phpswoole/golang-h2demo --push .

The Dockerfile expects a `h2demo` binary for the target platform; use per-arch build contexts or `docker build` once per arch.
