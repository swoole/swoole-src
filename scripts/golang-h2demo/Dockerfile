# Build the binary first: GOOS=linux GOARCH=<arch> CGO_ENABLED=0 go build -o h2demo .
FROM ubuntu:24.04
LABEL maintainer="rango@swoole.com"

RUN mkdir /go
COPY h2demo /go/h2demo
COPY server.crt server.key /
CMD ["/go/h2demo", "-https_addr", "0.0.0.0:4430"]
