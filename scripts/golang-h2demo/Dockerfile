FROM --platform=$BUILDPLATFORM golang:1.22 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /h2demo .

FROM ubuntu:24.04
LABEL maintainer="rango@swoole.com"
COPY --from=build /h2demo /go/h2demo
COPY server.crt server.key /
CMD ["/go/h2demo", "-https_addr", "0.0.0.0:4430"]
